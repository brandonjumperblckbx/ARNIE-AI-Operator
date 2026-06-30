"""
ARNIE AI Backend - Main FastAPI Application
Ansible Remediation & Navigation Intelligence Engine
Natural language → Ansible playbook generation with human-in-the-loop approval

Built on the RMCP Engine by BLCKBX
"""

from fastapi import FastAPI, HTTPException, Depends, status, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import json
import logging
import uuid
import os
import threading
from datetime import datetime, timezone
from pathlib import Path

from model_router import ModelRouter, OllamaModel, build_model_catalog, resolve_ollama_model
from model_providers import get_model_provider
from agent_runtime import AgentPipeline, AgentMemoryStore
from claude_service import ClaudeService
from playbook_generator import PlaybookGenerator
from approval_engine import ApprovalEngine, ApprovalRequest, ApprovalDecision
from github_integration import GitHubPusher
from aap_integration import AAPClient
from inventory_resolver import InventoryResolver
from playbook_validator import PlaybookValidator
from operator_knowledge import is_operator_request
from operator_setup import OperatorSetupBuilder
from cluster_vision import ClusterVision, ClusterVisionError
from operator_autoground import OperatorAutoGrounder
from chart_vetting import ChartVetting
from helm_setup import HelmInstallBuilder
# RMCP native C++ core — policy decisions + live cluster watch. Optional: if the
# shared library isn't built, the binding falls back to a conservative Python verdict.
try:
    from rmcp_native.rmcp_native import get_engine as _get_rmcp_engine
except Exception:  # pragma: no cover - keep backend resilient if native dir is absent
    try:
        from rmcp_native import get_engine as _get_rmcp_engine
    except Exception:
        _get_rmcp_engine = None
from db import (
    get_pool, close_pool, verify_jwt, authenticate, create_account,
    get_account, update_account, get_audit_log
)

log = logging.getLogger("arnie")

# ── State directories ──
STATE_DIR = os.environ.get("ARNIE_STATE_DIR", str(Path(__file__).resolve().parent / "state"))
Path(STATE_DIR).mkdir(parents=True, exist_ok=True)

# ── FastAPI app ──
app = FastAPI(
    title="ARNIE AI",
    version="1.0.0",
    description="Ansible Remediation & Navigation Intelligence Engine — "
                "AI-powered playbook generation with human-in-the-loop approval"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

security = HTTPBearer(auto_error=False)

# ── RMCP Engine initialization ──
model_provider = get_model_provider()
model_router = ModelRouter()
agent_memory = AgentMemoryStore(STATE_DIR)
agent_pipeline = AgentPipeline(model_provider, agent_memory)

# ── ARNIE-specific components ──
playbook_generator = PlaybookGenerator(model_provider)
approval_engine = ApprovalEngine(STATE_DIR)
github_pusher = GitHubPusher()
aap_client = AAPClient()
inventory_resolver = InventoryResolver()
playbook_validator = PlaybookValidator()
cluster_vision = ClusterVision()  # read-only "eyes" into the cluster
operator_builder = OperatorSetupBuilder(
    auto_grounder=OperatorAutoGrounder(cluster_vision)
)
# Helm fallback path: used when OpenShift's OperatorHub has no operator for the request.
chart_vetting = ChartVetting()
helm_builder = HelmInstallBuilder()
# RMCP native core (C++): policy verdicts + live cluster watch model.
rmcp_engine = _get_rmcp_engine() if _get_rmcp_engine else None

# Conversation-scoped store for operator setups awaiting the user's answers.
# Maps conversation_id -> {"intent": str, "questions": [...]}.
_pending_operator_setups: Dict[str, Dict[str, Any]] = {}
# Conversation-scoped store for Helm chart installs awaiting the user's answers.
# Maps conversation_id -> {"vetting": {...}}.
_pending_helm_setups: Dict[str, Dict[str, Any]] = {}


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _active_provider() -> str:
    return getattr(model_provider, "provider_name", "ollama")


def _active_model() -> Optional[str]:
    if hasattr(model_provider, "model"):
        m = getattr(model_provider, "model")
        if isinstance(m, str):
            return m
    return model_router.config.ollama_model.value


def _rebuild_provider():
    """Rebuild the active model provider and rewire it into the pipeline and
    generator so a provider/model change takes effect on the running app."""
    global model_provider, agent_pipeline, model_router
    model_provider = get_model_provider()
    model_router = ModelRouter()
    agent_pipeline = AgentPipeline(model_provider, agent_memory)
    playbook_generator.model_provider = model_provider
    log.info("Active provider rebuilt: %s", _active_provider())


# ════════════════════════════════════════════════════════════════════
# Request / Response Models
# ════════════════════════════════════════════════════════════════════

class ChatRequest(BaseModel):
    message: str = Field(..., description="Natural language infrastructure request")
    conversation_id: Optional[str] = None
    context: Optional[Dict[str, Any]] = None

class ChatResponse(BaseModel):
    response: str
    conversation_id: str
    playbook: Optional[Dict[str, Any]] = None
    approval_id: Optional[str] = None
    actions_taken: List[str] = []
    trace_id: Optional[str] = None
    response_type: Optional[str] = None
    operator_setup: Optional[Dict[str, Any]] = None

class PlaybookRequest(BaseModel):
    intent: str = Field(..., description="What the playbook should do")
    target_namespace: Optional[str] = None
    target_inventory: Optional[str] = None
    dry_run: bool = True
    context: Optional[Dict[str, Any]] = None

class PlaybookResponse(BaseModel):
    playbook_id: str
    intent: str
    yaml_content: str
    validation: Dict[str, Any]
    approval_id: str
    blast_radius: Dict[str, Any]
    risk_level: str
    status: str

class ApprovalActionRequest(BaseModel):
    actor: str = Field("operator")
    reason: str = Field("")

class GitPushResponse(BaseModel):
    commit_sha: str
    repo: str
    branch: str
    file_path: str
    playbook_id: str
    timestamp: str

class AAPJobResponse(BaseModel):
    job_id: str
    job_url: str
    status: str
    playbook: str
    timestamp: str

class HealthResponse(BaseModel):
    status: str
    service: str
    engine: str
    model_provider: str
    selected_model: Optional[str]
    github_configured: bool
    aap_configured: bool
    timestamp: str


# ════════════════════════════════════════════════════════════════════
# Chat Endpoint — The main interface
# ════════════════════════════════════════════════════════════════════

def _operator_is_resolvable(intent: str) -> bool:
    """True if this install request can be served by an operator — either a curated
    catalog entry, or (when cluster vision is connected) an operator available in the
    cluster's OperatorHub/marketplace that ARNIE can auto-ground. Routes operator-first,
    with the Helm/GitHub path as the fallback when no operator exists."""
    from operator_knowledge import resolve_operator
    try:
        from operator_knowledge import extract_package_name
    except Exception:
        extract_package_name = lambda x: x
    if resolve_operator(intent):
        return True  # curated operator
    if cluster_vision.is_configured():
        try:
            pkg = extract_package_name(intent) or intent
            if cluster_vision.find_package_manifest(pkg):
                return True  # operator exists in the marketplace → auto-groundable
        except Exception:
            pass
    return False


def _extract_install_target(message: str) -> str:
    """Pull the thing-to-install out of a message like 'install open-webui' → 'open-webui'."""
    m = message.strip()
    for verb in ("install ", "deploy ", "set up ", "setup ", "add "):
        idx = m.lower().find(verb)
        if idx != -1:
            target = m[idx + len(verb):].strip()
            # Trim trailing words like "on openshift", "for me", "please".
            for tail in (" on openshift", " on the cluster", " for me", " please", " operator"):
                if target.lower().endswith(tail):
                    target = target[: -len(tail)].strip()
            return target or message
    return message


def _looks_like_install_request_for_helm(message: str) -> bool:
    """Loose detector for 'install/deploy X' requests, so ARNIE can offer the Helm
    fallback for software that has no operator."""
    m = message.lower()
    return any(w in m for w in ("install ", "deploy ", "set up ", "setup "))


@app.post("/ai/chat", response_model=ChatResponse)
async def chat(request: ChatRequest):
    """
    Natural language chat interface for ARNIE.

    Accepts plain English infrastructure requests, generates Ansible playbooks,
    stages them for approval, and manages the full lifecycle through to execution.
    """
    context = dict(request.context or {})
    actions_taken: List[str] = []
    playbook_data: Optional[Dict[str, Any]] = None
    approval_id: Optional[str] = None

    # ── Step 1: Run through RMCP agent pipeline for intent analysis ──
    agent_result = await agent_pipeline.run_chat(
        request.message,
        conversation_id=request.conversation_id,
        context={
            **context,
            "mode": "arnie",
            "product": "ARNIE AI",
            "capabilities": [
                "playbook_generation",
                "infrastructure_automation",
                "kubernetes_operations",
                "openshift_management",
                "rbac_configuration",
                "network_policy",
                "storage_provisioning",
                "operator_deployment",
                "namespace_management",
                "secret_management",
            ],
        },
    )
    actions_taken.extend(agent_result.actions_taken)

    # ── Operator setup branch ──
    # If this is an operator install/configure request that ARNIE can serve via an
    # operator (curated catalog, or available in the cluster's marketplace), route it to
    # the operator builder. If it's an install request but NO operator exists for it,
    # we fall through to the Helm/GitHub fallback branch below.
    conv_id = request.conversation_id or agent_result.conversation_id
    if (is_operator_request(request.message)
            and _operator_is_resolvable(request.message)
            and not context.get("skip_operator")):
        # If ARNIE can see the cluster, check whether this operator is already
        # installed — so it can tell the user instead of generating a duplicate.
        cluster_note = ""
        if cluster_vision.is_configured():
            try:
                from operator_knowledge import resolve_operator
                key = resolve_operator(request.message)
                frag = key or ""
                if frag and cluster_vision.is_operator_installed(frag):
                    cluster_note = (
                        f"\n\n_Heads up: it looks like a '{frag}' operator is already "
                        f"installed on your cluster. I can still build the setup (it's "
                        f"idempotent), or you can skip the install._"
                    )
            except ClusterVisionError:
                pass  # cluster read failed; proceed without the note (read-only, non-fatal)

        # If the operator needs config answers we don't have yet, ask the user.
        if operator_builder.needs_questions(request.message, answers=None):
            q = operator_builder.get_questions(request.message)
            _pending_operator_setups[conv_id] = {
                "intent": request.message,
                "questions": q["questions"],
            }
            actions_taken.append("operator_questions_asked")
            # Render the questions as a chat message the UI can show.
            lines = [q["intro"] + cluster_note, ""]
            for i, question in enumerate(q["questions"], 1):
                default = question.get("default")
                hint = ""
                if default == "__generate__":
                    hint = " (I can generate a secure one)"
                elif isinstance(default, bool):
                    hint = f" (default: {'yes' if default else 'no'})"
                elif default not in (None, ""):
                    hint = f" (default: {default})"
                lines.append(f"{i}. {question['question']}{hint}")
            lines.append("")
            lines.append("Reply with your choices and I'll build the complete setup playbook.")
            return ChatResponse(
                response="\n".join(lines),
                conversation_id=conv_id,
                playbook=None,
                approval_id=None,
                actions_taken=actions_taken,
                trace_id=agent_result.trace_id,
                response_type="operator_questions",
                operator_setup={
                    "operator": q["operator"],
                    "grounded": q["grounded"],
                    "intro": q["intro"],
                    "questions": q["questions"],
                },
            )

        # No questions needed → assemble the complete setup playbook now.
        op_result = operator_builder.build(request.message, answers=None)
        playbook_data, approval_id, op_actions = _stage_operator_playbook(
            op_result, request.message, conv_id
        )
        actions_taken.extend(op_actions)
        response_text = _operator_response_text(op_result, agent_result.response)
        return ChatResponse(
            response=response_text,
            conversation_id=conv_id,
            playbook=playbook_data,
            approval_id=approval_id,
            actions_taken=actions_taken,
            trace_id=agent_result.trace_id,
        )

    # ── Helm / GitHub fallback branch ──
    # An install request for which NO operator exists (not curated, not in the cluster's
    # marketplace). ARNIE falls back to finding a Helm chart on GitHub, vetting it
    # (trust-first), and — on the user's answers — assembling a governed Helm install.
    if (_looks_like_install_request_for_helm(request.message)
            and not _operator_is_resolvable(request.message)
            and not context.get("skip_helm")):
        target = _extract_install_target(request.message)
        # Use ARNIE's saved GitHub token to raise the rate limit, then vet.
        _settings = _load_settings()
        chart_vetting.set_token(_settings.get("github", {}).get("token", ""))
        vetting = chart_vetting.vet(target)

        if not vetting.get("ok"):
            # Couldn't find an operator OR a chart — be honest about it.
            return ChatResponse(
                response=(
                    f"I couldn't find an operator in your cluster's marketplace for "
                    f"'{target}', and I couldn't locate a Helm chart or install manifest "
                    f"for it on GitHub either. {vetting.get('summary','')}\n\n"
                    f"If you know the chart's repo or Helm URL, tell me and I'll work from that."
                ),
                conversation_id=conv_id,
                actions_taken=actions_taken + ["helm_resolve_failed"],
                trace_id=agent_result.trace_id,
            )

        # Found + vetted a chart → ask the Helm questions (grounded in its values.yaml),
        # and surface the security report up front (trust-first).
        q = helm_builder.get_questions(vetting)
        _pending_helm_setups[conv_id] = {"vetting": vetting}
        actions_taken.append("helm_chart_vetted")
        actions_taken.append("helm_questions_asked")

        sec = vetting.get("security") or {}
        risk = sec.get("risk_level", "info")
        finding_lines = "\n".join(
            f"  • [{f['severity']}] {f['message']}" for f in sec.get("findings", [])[:6]
        ) or "  • No notable concerns found."
        lines = [
            q["intro"], "",
            f"**Security scan — risk: {risk}**",
            finding_lines, "",
            "**A few choices:**",
        ]
        for i, question in enumerate(q["questions"], 1):
            default = question.get("default")
            hint = f" (default: {default})" if default not in (None, "") else ""
            lines.append(f"{i}. {question['question']}{hint}")
        lines.append("")
        lines.append("Reply with your choices and I'll build the install — you'll approve it before anything runs.")

        return ChatResponse(
            response="\n".join(lines),
            conversation_id=conv_id,
            actions_taken=actions_taken,
            trace_id=agent_result.trace_id,
            response_type="helm_questions",
            operator_setup={
                "chart": q["chart"],
                "repo": q["repo"],
                "risk_level": risk,
                "intro": q["intro"],
                "questions": q["questions"],
                "security": sec,
            },
        )

    # ── Step 2: Detect if a playbook should be generated ──
    intent_analysis = await playbook_generator.analyze_intent(request.message, context)

    if intent_analysis.get("should_generate_playbook"):
        # Resolve target inventory first so detected resource types feed generation.
        inventory = inventory_resolver.resolve(
            intent=request.message,
            context=context,
        )
        # Pass detected resource types into generation context for grounding.
        gen_context = dict(context)
        gen_context["resource_types"] = (
            intent_analysis.get("resources")
            or intent_analysis.get("target_resources")
            or inventory.get("resource_types")
            or []
        )

        # Generate the playbook
        generated = await playbook_generator.generate(
            intent=request.message,
            target_namespace=context.get("namespace") or inventory.get("namespace"),
            context=gen_context,
        )
        actions_taken.append("playbook_generated")

        # Validate it (generator already validates, but re-validate for the response)
        validation = generated.get("validation") or playbook_validator.validate(generated["yaml_content"])
        actions_taken.append("playbook_validated")

        # Estimate blast radius
        blast_radius = playbook_generator.estimate_blast_radius(
            generated["yaml_content"],
            context,
        )

        # Stage for approval
        approval = approval_engine.stage(ApprovalRequest(
            playbook_id=generated["playbook_id"],
            intent=request.message,
            yaml_content=generated["yaml_content"],
            validation=validation,
            blast_radius=blast_radius,
            risk_level=generated.get("risk_level", "medium"),
            requested_by=context.get("requested_by", "operator"),
            conversation_id=request.conversation_id or agent_result.conversation_id,
        ))
        approval_id = approval["id"]
        actions_taken.append(f"staged:{approval_id}")

        playbook_data = {
            "playbook_id": generated["playbook_id"],
            "yaml_content": generated["yaml_content"],
            "file_name": generated["file_name"],
            "validation": validation,
            "blast_radius": blast_radius,
            "risk_level": generated.get("risk_level", "medium"),
            "inventory": inventory,
            "approval_id": approval_id,
            "generation_source": generated.get("generation_source", "model"),
            "status": "pending_approval",
        }

        # Build a response that includes the playbook preview
        response_text = (
            f"{agent_result.response}\n\n"
            f"📋 **Generated Playbook:** `{generated['file_name']}`\n\n"
            f"```yaml\n{generated['yaml_content']}\n```\n\n"
            f"**Risk Level:** {generated.get('risk_level', 'medium')}\n"
            f"**Blast Radius:** {blast_radius.get('summary', 'N/A')}\n"
            f"**Validation:** {'✅ Passed' if validation.get('valid') else '❌ Issues found'}\n\n"
            f"Approve this playbook to push to GitHub and trigger AAP execution."
        )
    else:
        response_text = agent_result.response

    return ChatResponse(
        response=response_text,
        conversation_id=agent_result.conversation_id,
        playbook=playbook_data,
        approval_id=approval_id,
        actions_taken=actions_taken,
        trace_id=agent_result.trace_id,
    )


# ════════════════════════════════════════════════════════════════════
# Operator Setup — helpers + answers endpoint
# ════════════════════════════════════════════════════════════════════

def _stage_operator_playbook(op_result: Dict[str, Any], intent: str, conv_id: str):
    """Validate, blast-radius, and stage an operator setup playbook for approval.
    Returns (playbook_data, approval_id, actions)."""
    actions = ["operator_playbook_generated"]
    yaml_content = op_result["yaml_content"]

    validation = playbook_validator.validate(yaml_content)
    actions.append("playbook_validated")
    blast_radius = playbook_generator.estimate_blast_radius(yaml_content, {})

    approval = approval_engine.stage(ApprovalRequest(
        playbook_id=op_result["playbook_id"],
        intent=intent,
        yaml_content=yaml_content,
        validation=validation,
        blast_radius=blast_radius,
        risk_level=op_result.get("risk_level", "medium"),
        requested_by="operator",
        conversation_id=conv_id,
    ))
    actions.append(f"staged:{approval['id']}")

    playbook_data = {
        "playbook_id": op_result["playbook_id"],
        "yaml_content": yaml_content,
        "file_name": op_result["file_name"],
        "validation": validation,
        "blast_radius": blast_radius,
        "risk_level": op_result.get("risk_level", "medium"),
        "approval_id": approval["id"],
        "generation_source": op_result.get("generation_source", "operator"),
        "setup_summary": op_result.get("setup_summary", []),
        "rmcp_verdict": _rmcp_policy_check(
            "create", "Operator", op_result.get("target_namespace", ""),
            name=op_result.get("playbook_id", ""),
        ),
        "status": "pending_approval",
    }
    return playbook_data, approval["id"], actions


def _operator_response_text(op_result: Dict[str, Any], preamble: str) -> str:
    """Build the chat response describing the complete operator setup."""
    steps = op_result.get("setup_summary", [])
    step_lines = "\n".join(f"  {i}. {s}" for i, s in enumerate(steps, 1))
    return (
        f"{preamble}\n\n"
        f"📦 **Complete setup playbook:** `{op_result['file_name']}`\n\n"
        f"This takes you all the way to a running, configured operator:\n"
        f"{step_lines}\n\n"
        f"```yaml\n{op_result['yaml_content']}\n```\n\n"
        f"Approve it and I'll push to GitHub and run it through AAP onto the cluster."
    )


class OperatorAnswersRequest(BaseModel):
    conversation_id: str
    answers: Dict[str, Any] = {}
    install_namespace: Optional[str] = None


@app.post("/ai/operator/answers")
async def operator_answers(request: OperatorAnswersRequest):
    """Receive the user's answers to operator config questions and assemble the
    complete setup playbook."""
    pending = _pending_operator_setups.get(request.conversation_id)
    if not pending:
        raise HTTPException(404, "No operator setup awaiting answers for this conversation.")

    op_result = operator_builder.build(
        pending["intent"],
        answers=request.answers,
        install_namespace=request.install_namespace,
    )
    playbook_data, approval_id, actions = _stage_operator_playbook(
        op_result, pending["intent"], request.conversation_id
    )
    # Clear the pending state now that it's assembled.
    _pending_operator_setups.pop(request.conversation_id, None)

    return {
        "response": _operator_response_text(op_result, "Got it — here's your complete setup."),
        "conversation_id": request.conversation_id,
        "playbook": playbook_data,
        "approval_id": approval_id,
        "actions_taken": actions,
        "timestamp": _utc_now(),
    }


def _rmcp_policy_check(action: str, kind: str, ns: str, *, name: str = "",
                       api_version: str = "", attrs: Optional[Dict[str, Any]] = None,
                       requested_by: str = "operator") -> Optional[Dict[str, Any]]:
    """Run a proposed change through the RMCP native policy core (C++). Returns the
    verdict dict, or None if the engine isn't available. Advisory: the verdict is
    surfaced alongside the approval; the human still decides."""
    if not rmcp_engine:
        return None
    try:
        return rmcp_engine.evaluate({
            "action": action, "kind": kind, "api_version": api_version,
            "name": name, "ns": ns, "requested_by": requested_by,
            "attrs": attrs or {},
        })
    except Exception as e:
        log.warning("RMCP policy evaluation failed: %s", e)
        return None


@app.get("/rmcp/status")
async def rmcp_status():
    """Status of the RMCP native C++ core (policy engine + cluster watch)."""
    if not rmcp_engine:
        return {"native_available": False, "detail": "RMCP native core not loaded."}
    return {
        "native_available": rmcp_engine.available,
        "policy_rules": rmcp_engine.rule_count(),
        "watch": rmcp_engine.snapshot(),
    }


@app.post("/rmcp/evaluate")
async def rmcp_evaluate(change: dict):
    """Evaluate a proposed change against RMCP policy (C++ core). Useful for testing
    and for surfacing a verdict in the UI before staging."""
    verdict = _rmcp_policy_check(
        action=change.get("action", ""),
        kind=change.get("kind", ""),
        ns=change.get("ns", ""),
        name=change.get("name", ""),
        api_version=change.get("api_version", ""),
        attrs=change.get("attrs", {}),
        requested_by=change.get("requested_by", "operator"),
    )
    if verdict is None:
        raise HTTPException(503, "RMCP native core not available.")
    return verdict


def _stage_helm_playbook(helm_result: Dict[str, Any], intent: str, conv_id: str):
    """Validate, blast-radius, and stage a Helm install playbook for approval.
    Returns (playbook_data, approval_id, actions)."""
    actions = ["helm_playbook_generated"]
    yaml_content = helm_result["yaml_content"]

    validation = playbook_validator.validate(yaml_content)
    actions.append("playbook_validated")
    blast_radius = playbook_generator.estimate_blast_radius(yaml_content, {})

    approval = approval_engine.stage(ApprovalRequest(
        playbook_id=helm_result["playbook_id"],
        intent=intent,
        yaml_content=yaml_content,
        validation=validation,
        blast_radius=blast_radius,
        risk_level=helm_result.get("risk_level", "medium"),
        requested_by="operator",
        conversation_id=conv_id,
    ))
    actions.append(f"staged:{approval['id']}")

    playbook_data = {
        "playbook_id": helm_result["playbook_id"],
        "yaml_content": yaml_content,
        "file_name": helm_result["file_name"],
        "validation": validation,
        "blast_radius": blast_radius,
        "risk_level": helm_result.get("risk_level", "medium"),
        "approval_id": approval["id"],
        "generation_source": helm_result.get("generation_source", "helm"),
        "setup_summary": helm_result.get("setup_summary", []),
        "security_report": helm_result.get("security_report"),
        "status": "pending_approval",
    }
    return playbook_data, approval["id"], actions


class HelmAnswersRequest(BaseModel):
    conversation_id: str
    answers: Dict[str, Any] = {}


@app.post("/ai/helm/answers")
async def helm_answers(request: HelmAnswersRequest):
    """Receive the user's answers to Helm chart config questions and assemble the
    complete, vetted install playbook."""
    pending = _pending_helm_setups.get(request.conversation_id)
    if not pending:
        raise HTTPException(404, "No Helm install awaiting answers for this conversation.")

    vetting = pending["vetting"]
    helm_result = helm_builder.build(vetting, answers=request.answers)
    intent = f"install {vetting.get('project')}"
    playbook_data, approval_id, actions = _stage_helm_playbook(
        helm_result, intent, request.conversation_id
    )
    _pending_helm_setups.pop(request.conversation_id, None)

    steps = helm_result.get("setup_summary", [])
    step_lines = "\n".join(f"  {i}. {s}" for i, s in enumerate(steps, 1))
    response = (
        f"Here's the complete Helm install for **{vetting.get('project')}** "
        f"(chart from {vetting.get('repo')}):\n\n"
        f"{step_lines}\n\n"
        f"```yaml\n{helm_result['yaml_content']}\n```\n\n"
        f"Approve it and I'll push to GitHub and run it through AAP onto the cluster."
    )

    return {
        "response": response,
        "conversation_id": request.conversation_id,
        "playbook": playbook_data,
        "approval_id": approval_id,
        "actions_taken": actions,
        "timestamp": _utc_now(),
    }


# ════════════════════════════════════════════════════════════════════
# Playbook Generation
# ════════════════════════════════════════════════════════════════════

@app.post("/ai/playbook/generate", response_model=PlaybookResponse)
async def generate_playbook(request: PlaybookRequest):
    """Generate an Ansible playbook from natural language without chat context."""
    generated = await playbook_generator.generate(
        intent=request.intent,
        target_namespace=request.target_namespace,
        context=request.context or {},
    )

    validation = generated.get("validation") or playbook_validator.validate(generated["yaml_content"])
    blast_radius = playbook_generator.estimate_blast_radius(
        generated["yaml_content"],
        request.context or {},
    )

    approval = approval_engine.stage(ApprovalRequest(
        playbook_id=generated["playbook_id"],
        intent=request.intent,
        yaml_content=generated["yaml_content"],
        validation=validation,
        blast_radius=blast_radius,
        risk_level=generated.get("risk_level", "medium"),
        requested_by="operator",
    ))

    return PlaybookResponse(
        playbook_id=generated["playbook_id"],
        intent=request.intent,
        yaml_content=generated["yaml_content"],
        validation=validation,
        approval_id=approval["id"],
        blast_radius=blast_radius,
        risk_level=generated.get("risk_level", "medium"),
        status="pending_approval",
    )


# ════════════════════════════════════════════════════════════════════
# Approval Workflow
# ════════════════════════════════════════════════════════════════════

@app.get("/ai/approvals")
async def list_approvals():
    """List all staged playbook approvals."""
    approvals = approval_engine.list_approvals()
    return {
        "approvals": approvals,
        "summary": {
            "total": len(approvals),
            "pending": len([a for a in approvals if a["status"] == "pending_approval"]),
            "approved": len([a for a in approvals if a["status"] == "approved"]),
            "executed": len([a for a in approvals if a["status"] == "executed"]),
        },
        "timestamp": _utc_now(),
    }


@app.get("/ai/approvals/{approval_id}")
async def get_approval(approval_id: str):
    """Get details of a specific approval."""
    return approval_engine.get(approval_id)


@app.post("/ai/approvals/{approval_id}/approve")
async def approve_playbook(approval_id: str, request: ApprovalActionRequest):
    """Approve a staged playbook — triggers GitHub push and AAP execution."""
    approval = approval_engine.approve(
        approval_id,
        ApprovalDecision(actor=request.actor, reason=request.reason),
    )

    actions_taken = [f"approved:{approval_id}"]

    # ── Push to GitHub ──
    push_result = None
    try:
        push_result = await github_pusher.push_playbook(
            file_name=approval["file_name"],
            content=approval["yaml_content"],
            commit_message=f"ARNIE: {approval['intent']}\n\nApproved by {request.actor}\nApproval ID: {approval_id}",
        )
        approval_engine.record_push(approval_id, push_result)
        actions_taken.append(f"pushed:{push_result.get('commit_sha', 'unknown')}")
    except Exception as e:
        log.error("GitHub push failed: %s", e)
        actions_taken.append(f"push_failed:{e}")

    # ── Trigger AAP ──
    aap_result = None
    if push_result:
        try:
            aap_result = await aap_client.sync_and_launch(
                playbook=approval["file_name"],
            )
            approval_engine.record_execution(approval_id, aap_result)
            actions_taken.append(f"aap_launched:{aap_result.get('job_id', 'unknown')}")
        except Exception as e:
            log.error("AAP launch failed: %s", e)
            actions_taken.append(f"aap_failed:{e}")

    return {
        "approval": approval,
        "github": push_result,
        "aap": aap_result,
        "actions_taken": actions_taken,
        "timestamp": _utc_now(),
    }


@app.post("/ai/approvals/{approval_id}/reject")
async def reject_playbook(approval_id: str, request: ApprovalActionRequest):
    """Reject a staged playbook."""
    return approval_engine.reject(
        approval_id,
        ApprovalDecision(actor=request.actor, reason=request.reason),
    )


@app.post("/ai/approvals/{approval_id}/edit")
async def edit_playbook(approval_id: str, request: dict):
    """Edit a staged playbook's YAML before approval."""
    new_yaml = request.get("yaml_content", "")
    if not new_yaml.strip():
        raise HTTPException(400, "yaml_content is required")

    validation = playbook_validator.validate(new_yaml)
    return approval_engine.edit(approval_id, new_yaml, validation)


# ════════════════════════════════════════════════════════════════════
# GitHub Integration
# ════════════════════════════════════════════════════════════════════

@app.get("/git/status")
async def git_status():
    """Check GitHub connection and repo status."""
    return await github_pusher.get_status()


@app.get("/git/history")
async def git_history(limit: int = 20):
    """List recent ARNIE commits to the playbook repo."""
    return await github_pusher.get_history(limit)


# ════════════════════════════════════════════════════════════════════
# AAP Integration
# ════════════════════════════════════════════════════════════════════

@app.get("/aap/status")
async def aap_status():
    """Check AAP connection status."""
    return await aap_client.get_status()


@app.get("/aap/jobs")
async def aap_jobs(limit: int = 20):
    """List recent AAP job runs triggered by ARNIE."""
    return await aap_client.list_jobs(limit)


@app.get("/aap/jobs/{job_id}")
async def aap_job_detail(job_id: str):
    """Get detailed AAP job output."""
    return await aap_client.get_job(job_id)


# ════════════════════════════════════════════════════════════════════
# Model Management (RMCP Engine)
# ════════════════════════════════════════════════════════════════════

@app.get("/ai/models")
async def list_models():
    """List available AI models."""
    catalog = build_model_catalog()
    local_models = []
    if hasattr(model_provider, "list_local_models"):
        try:
            local_models = await model_provider.list_local_models()
        except Exception:
            pass
    return {
        "provider": _active_provider(),
        "selected_model": _active_model(),
        "supported_models": catalog.get("supported_models", []),
        "local_models": local_models,
        "timestamp": _utc_now(),
    }


@app.post("/ai/models/provider")
async def switch_provider(request: dict):
    """Switch AI model provider at runtime — the dropdown is authoritative."""
    provider = (request.get("provider") or "").strip().lower()
    model = request.get("model")

    if provider not in ("ollama", "claude", "codex"):
        raise HTTPException(400, "provider must be 'ollama', 'claude', or 'codex'")

    # Ensure the chosen provider's saved credential is in the environment, so the
    # provider class can authenticate. Keys come from Settings → AI Engine.
    s = _load_settings()
    ai = s.get("ai", {})
    if provider == "claude" and ai.get("claude_key"):
        os.environ["ANTHROPIC_API_KEY"] = ai["claude_key"]
    if provider == "codex" and ai.get("openai_key"):
        os.environ["OPENAI_API_KEY"] = ai["openai_key"]

    os.environ["RMCP_PROVIDER"] = provider
    os.environ["MODEL_PROVIDER"] = provider
    if model:
        resolved = resolve_ollama_model(model)
        if resolved:
            os.environ["RMCP_MODEL"] = resolved.value
            os.environ["OLLAMA_MODEL"] = resolved.value

    # Persist the choice so it survives restarts and stays in sync with settings.
    merged_ai = dict(ai)
    merged_ai["provider"] = provider
    if model:
        merged_ai["model"] = model
    _save_settings({"ai": merged_ai})

    _rebuild_provider()

    # Warn (don't fail) if the selected cloud provider has no key configured.
    warning = None
    if provider == "claude" and not os.environ.get("ANTHROPIC_API_KEY"):
        warning = "Claude selected but no Anthropic API key saved (Settings → AI Engine)."
    if provider == "codex" and not os.environ.get("OPENAI_API_KEY"):
        warning = "Codex selected but no OpenAI API key saved (Settings → AI Engine)."

    return {
        "status": "ok",
        "provider": _active_provider(),
        "selected_model": _active_model(),
        "warning": warning,
        "timestamp": _utc_now(),
    }


# ════════════════════════════════════════════════════════════════════
# Conversation History
# ════════════════════════════════════════════════════════════════════

@app.get("/ai/conversations/{conversation_id}")
async def get_conversation(conversation_id: str):
    """Get conversation state and history."""
    snapshot = agent_memory.snapshot(conversation_id)
    return {
        "conversation_id": snapshot["conversation_id"],
        "summary": snapshot["summary"],
        "recent_turns": snapshot["recent_turns"],
        "trace_count": snapshot["trace_count"],
        "updated_at": snapshot["updated_at"],
    }


@app.get("/ai/traces/{conversation_id}")
async def get_traces(conversation_id: str):
    """Get execution traces for a conversation."""
    return {
        "conversation_id": conversation_id,
        "traces": agent_memory.list_traces(conversation_id),
    }


# ════════════════════════════════════════════════════════════════════
# Audit Trail
# ════════════════════════════════════════════════════════════════════

@app.get("/ai/audit")
async def get_audit(limit: int = 50):
    """Full audit trail — playbook generation, approvals, pushes, executions."""
    return {
        "audit": approval_engine.get_audit(limit),
        "timestamp": _utc_now(),
    }


# ════════════════════════════════════════════════════════════════════
# Health
# ════════════════════════════════════════════════════════════════════

@app.get("/health", response_model=HealthResponse)
async def health():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        service="arnie-ai",
        engine="rmcp",
        model_provider=_active_provider(),
        selected_model=_active_model(),
        github_configured=github_pusher.is_configured(),
        aap_configured=aap_client.is_configured(),
        timestamp=_utc_now(),
    )


@app.get("/")
async def root():
    return {
        "service": "ARNIE AI",
        "tagline": "Ansible Remediation & Navigation Intelligence Engine",
        "version": "1.0.0",
        "engine": "RMCP by BLCKBX",
        "docs": "/docs",
    }


# ── DB lifecycle ──

@app.on_event("startup")
async def startup():
    try:
        pool = await get_pool()
        log.info("Database connected: %d connections", pool.get_size())
    except Exception as e:
        log.warning("Database unavailable: %s", e)


@app.on_event("shutdown")
async def shutdown():
    await close_pool()

# ════════════════════════════════════════════════════════════════════
# Settings Endpoints
# ════════════════════════════════════════════════════════════════════

import json as _json
from pathlib import Path as _Path

SETTINGS_PATH = _Path(STATE_DIR) / "settings.json"

def _load_settings() -> Dict[str, Any]:
    if SETTINGS_PATH.exists():
        try:
            with SETTINGS_PATH.open("r") as f:
                return _json.load(f)
        except Exception:
            pass
    return {}

def _save_settings(data: Dict[str, Any]) -> None:
    current = _load_settings()
    current.update(data)
    tmp = SETTINGS_PATH.with_suffix(".tmp")
    with tmp.open("w") as f:
        _json.dump(current, f, indent=2, default=str)
    tmp.replace(SETTINGS_PATH)

def _apply_settings():
    """Apply saved settings to integration clients and the AI engine."""
    s = _load_settings()

    # GitHub
    gh = s.get("github", {})
    if gh.get("repo"):
        github_pusher.token = gh.get("token", "")
        github_pusher.repo = gh.get("repo", "")
        github_pusher.branch = gh.get("branch", "main")
        github_pusher.playbook_dir = gh.get("playbook_dir", "")

    # AAP
    aap = s.get("aap", {})
    if aap.get("url"):
        aap_client.base_url = aap.get("url", "").rstrip("/")
        aap_client.token = aap.get("token", "")
        aap_client.project_id = aap.get("project_id", "")
        aap_client.job_template_id = aap.get("job_template_id", "")
        aap_client.verify_ssl = aap.get("verify_ssl", False)

    # AI Engine — load saved keys into the environment so the provider classes
    # (ClaudeService / CodexService / ModelRouter) pick them up, then rebuild
    # the active provider so the running pipeline uses it immediately.
    ai = s.get("ai", {})
    if ai:
        if ai.get("claude_key"):
            os.environ["ANTHROPIC_API_KEY"] = ai["claude_key"]
        if ai.get("openai_key"):
            os.environ["OPENAI_API_KEY"] = ai["openai_key"]
        if ai.get("ollama_url"):
            os.environ["OLLAMA_BASE_URL"] = ai["ollama_url"]
        provider = (ai.get("provider") or "").strip().lower()
        if provider:
            os.environ["RMCP_PROVIDER"] = provider
            os.environ["MODEL_PROVIDER"] = provider
        if ai.get("model"):
            os.environ["RMCP_MODEL"] = ai["model"]
            os.environ["OLLAMA_MODEL"] = ai["model"]
        _rebuild_provider()


    # Cluster Vision — read-only connection to OpenShift. ARNIE's "eyes."
    # This SA token should be bound to the read-only 'view' ClusterRole; ARNIE
    # never writes through this connection (writes go through AAP + approval).
    cluster = s.get("cluster", {})
    if cluster.get("url"):
        cluster_vision.configure(
            api_url=cluster.get("url", ""),
            token=cluster.get("token", ""),
            verify_ssl=cluster.get("verify_ssl", False),
        )


@app.post("/settings/github")
async def save_github_settings(request: dict):
    """Save GitHub integration settings and test the connection."""
    _save_settings({"github": {
        "repo": request.get("repo", ""),
        "token": request.get("token", ""),
        "branch": request.get("branch", "main"),
        "playbook_dir": request.get("playbook_dir", ""),
    }})
    _apply_settings()

    # Test connection
    status = await github_pusher.get_status()
    return {
        "saved": True,
        "connected": status.get("connected", False),
        "detail": status,
        "timestamp": _utc_now(),
    }


@app.post("/settings/aap")
async def save_aap_settings(request: dict):
    """Save AAP integration settings and test the connection."""
    _save_settings({"aap": {
        "url": request.get("url", ""),
        "token": request.get("token", ""),
        "project_id": request.get("project_id", ""),
        "job_template_id": request.get("job_template_id", ""),
        "verify_ssl": request.get("verify_ssl", False),
    }})
    _apply_settings()

    # Test connection
    status = await aap_client.get_status()
    return {
        "saved": True,
        "connected": status.get("connected", False),
        "detail": status,
        "timestamp": _utc_now(),
    }


@app.post("/settings/cluster")
async def save_cluster_settings(request: dict):
    """Save the read-only OpenShift connection (ARNIE's cluster vision) and test it."""
    _save_settings({"cluster": {
        "url": request.get("url", ""),
        "token": request.get("token", ""),
        "verify_ssl": request.get("verify_ssl", False),
    }})
    _apply_settings()
    status = cluster_vision.check_connection()
    return {
        "saved": True,
        "connected": status.get("connected", False),
        "detail": status,
        "read_only": True,
        "timestamp": _utc_now(),
    }


# ════════════════════════════════════════════════════════════════════
# Cluster Vision — READ-ONLY cluster awareness endpoints
# Every endpoint here only observes. No mutation path exists.
# ════════════════════════════════════════════════════════════════════

@app.get("/cluster/status")
async def cluster_status():
    """Connection status for ARNIE's read-only cluster vision."""
    if not cluster_vision.is_configured():
        return {"configured": False, "connected": False, "read_only": True}
    status = cluster_vision.check_connection()
    return {"configured": True, "read_only": True, **status}


@app.get("/cluster/operators")
async def cluster_operators():
    """List operators installed on the cluster (read-only)."""
    try:
        return {"operators": cluster_vision.list_operators(), "read_only": True}
    except ClusterVisionError as e:
        raise HTTPException(502, str(e))


@app.get("/cluster/namespaces")
async def cluster_namespaces():
    """List namespaces (read-only)."""
    try:
        return {"namespaces": cluster_vision.list_namespaces(), "read_only": True}
    except ClusterVisionError as e:
        raise HTTPException(502, str(e))


@app.get("/cluster/storage-classes")
async def cluster_storage_classes():
    """List storage classes (read-only)."""
    try:
        return {
            "storage_classes": cluster_vision.list_storage_classes(),
            "default": cluster_vision.default_storage_class(),
            "read_only": True,
        }
    except ClusterVisionError as e:
        raise HTTPException(502, str(e))


@app.get("/cluster/pods/{namespace}")
async def cluster_pods(namespace: str):
    """List pods in a namespace (read-only)."""
    try:
        return {"namespace": namespace, "pods": cluster_vision.list_pods(namespace), "read_only": True}
    except ClusterVisionError as e:
        raise HTTPException(502, str(e))


@app.get("/cluster/operator-context/{name_fragment}")
async def cluster_operator_context(name_fragment: str):
    """Cluster facts relevant to installing/configuring an operator (read-only):
    already-installed?, related CRDs, default storage class, namespaces."""
    if not cluster_vision.is_configured():
        return {"connected": False, "read_only": True}
    return {**cluster_vision.operator_context(name_fragment), "read_only": True}


@app.post("/settings/ai")
async def save_ai_settings(request: dict):
    """Save AI engine settings and apply them to the running engine immediately."""
    _save_settings({"ai": {
        "provider": request.get("provider", "ollama"),
        "ollama_url": request.get("ollama_url", "http://localhost:11434"),
        "model": request.get("model", "llama3.1:8b"),
        "claude_key": request.get("claude_key", ""),
        "openai_key": request.get("openai_key", ""),
        "fallback": request.get("fallback", True),
    }})
    _apply_settings()
    return {
        "saved": True,
        "active_provider": _active_provider(),
        "selected_model": _active_model(),
        "timestamp": _utc_now(),
    }


@app.get("/settings")
async def get_settings():
    """Get current settings (tokens masked)."""
    s = _load_settings()
    # Mask sensitive fields
    if s.get("github", {}).get("token"):
        t = s["github"]["token"]
        s["github"]["token"] = t[:4] + "•" * (len(t) - 8) + t[-4:] if len(t) > 8 else "••••"
    if s.get("aap", {}).get("token"):
        t = s["aap"]["token"]
        s["aap"]["token"] = t[:4] + "•" * (len(t) - 8) + t[-4:] if len(t) > 8 else "••••"
    if s.get("cluster", {}).get("token"):
        t = s["cluster"]["token"]
        s["cluster"]["token"] = t[:4] + "•" * (len(t) - 8) + t[-4:] if len(t) > 8 else "••••"
    if s.get("ai", {}).get("claude_key"):
        t = s["ai"]["claude_key"]
        s["ai"]["claude_key"] = t[:7] + "•" * (len(t) - 11) + t[-4:] if len(t) > 11 else "••••"
    if s.get("ai", {}).get("openai_key"):
        t = s["ai"]["openai_key"]
        s["ai"]["openai_key"] = t[:7] + "•" * (len(t) - 11) + t[-4:] if len(t) > 11 else "••••"
    return {"settings": s, "timestamp": _utc_now()}


# ── Load saved settings on startup ──
@app.on_event("startup")
async def load_saved_settings():
    try:
        _apply_settings()
        log.info("Saved settings applied")
    except Exception as e:
        log.warning("Could not load saved settings: %s", e)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8085)

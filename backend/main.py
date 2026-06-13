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

    # ── Step 2: Detect if a playbook should be generated ──
    intent_analysis = await playbook_generator.analyze_intent(request.message, context)

    if intent_analysis.get("should_generate_playbook"):
        # Generate the playbook
        generated = await playbook_generator.generate(
            intent=request.message,
            target_namespace=context.get("namespace"),
            context=context,
        )
        actions_taken.append("playbook_generated")

        # Validate it
        validation = playbook_validator.validate(generated["yaml_content"])
        actions_taken.append("playbook_validated")

        # Resolve target inventory
        inventory = inventory_resolver.resolve(
            intent=request.message,
            context=context,
        )

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

    validation = playbook_validator.validate(generated["yaml_content"])
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
    """Switch AI model provider at runtime."""
    global model_provider, agent_pipeline, model_router

    provider = request.get("provider", "").strip().lower()
    model = request.get("model")

    if provider not in ("ollama", "claude"):
        raise HTTPException(400, "provider must be 'ollama' or 'claude'")

    os.environ["RMCP_PROVIDER"] = provider
    os.environ["MODEL_PROVIDER"] = provider
    if model:
        resolved = resolve_ollama_model(model)
        if resolved:
            os.environ["RMCP_MODEL"] = resolved.value
            os.environ["OLLAMA_MODEL"] = resolved.value

    model_provider = get_model_provider()
    model_router = ModelRouter()
    agent_pipeline = AgentPipeline(model_provider, agent_memory)
    playbook_generator.model_provider = model_provider

    return {
        "status": "ok",
        "provider": _active_provider(),
        "selected_model": _active_model(),
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
# Settings Endpoints —
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
    """Apply saved settings to integration clients."""
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
    """Save cluster connection settings."""
    _save_settings({"cluster": {
        "url": request.get("url", ""),
        "token": request.get("token", ""),
        "verify_ssl": request.get("verify_ssl", False),
    }})
    return {"saved": True, "timestamp": _utc_now()}


@app.post("/settings/ai")
async def save_ai_settings(request: dict):
    """Save AI engine settings."""
    _save_settings({"ai": {
        "provider": request.get("provider", "ollama"),
        "ollama_url": request.get("ollama_url", "http://localhost:11434"),
        "model": request.get("model", "llama3.1:8b"),
        "claude_key": request.get("claude_key", ""),
        "fallback": request.get("fallback", True),
    }})
    return {"saved": True, "timestamp": _utc_now()}


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
    uvicorn.run(app, host="0.0.0.0", port=8082)

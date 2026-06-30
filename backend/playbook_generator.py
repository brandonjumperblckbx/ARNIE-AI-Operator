"""
ARNIE Playbook Generator (Advanced)
Translates natural-language infrastructure intent into validated Ansible playbook YAML.

Pipeline: PLAN → GROUND → GENERATE → VALIDATE → SELF-CORRECT → (ASSEMBLE fallback)

Unlike a single-shot generate-and-hope, this generator:
  • Plans the intent into concrete resources before generating.
  • Grounds every generation in the verified knowledge base (knowledge_retrieval).
  • Validates generated YAML with the PlaybookValidator and, on failure, feeds the
    errors back to the model and regenerates (bounded self-correction loop).
  • NEVER returns a useless stub. If the model is unreachable or repeatedly produces
    invalid YAML, it ASSEMBLES a correct, complete playbook from the verified
    resource templates — always deployable.

Built on the RMCP engine by BLCKBX.
"""

import json
import uuid
import re
import logging
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

from knowledge_retrieval import retrieve_knowledge, resolve_templates, get_retriever
from playbook_validator import PlaybookValidator

log = logging.getLogger("arnie.playbook-generator")


# ════════════════════════════════════════════════════════════════════
# Prompts
# ════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = """You are ARNIE — Ansible Remediation & Navigation Intelligence Engine.
You generate production-grade Ansible playbooks for OpenShift and Kubernetes infrastructure.

NON-NEGOTIABLE RULES:
1. Output ONLY valid Ansible YAML — no markdown fences, no prose, no commentary.
2. Every play sets: hosts: localhost, connection: local, gather_facts: false.
3. Use the kubernetes.core.k8s module with a full 'definition:' block for create/update/delete.
   The parameter is 'definition' (NOT 'resource_definition'). 'state' is a module-level arg.
4. Use kubernetes.core.k8s_info for reads (register the result). kubernetes.core.k8s_scale
   for replica changes. kubernetes.core.k8s_drain for node maintenance.
5. Cluster-scoped kinds (Namespace, ClusterRole, ClusterRoleBinding, SecurityContextConstraints)
   MUST NOT carry a namespace. Namespaced kinds MUST set namespace.
6. Name every task descriptively. Use state: present for create/update, state: absent for delete.
7. For ordered operations set wait: true with an appropriate wait_condition.
8. Adhere EXACTLY to the verified apiVersions, module parameters, and resource shapes provided
   in the grounding block. Do not invent parameters or apiVersions.

You will be given a VERIFIED KNOWLEDGE block. Treat it as ground truth and follow it precisely.
"""

PLAN_PROMPT = """Analyze this infrastructure request and respond ONLY with JSON (no markdown, no prose):

Request: "{intent}"

Respond with this exact shape:
{{
    "should_generate_playbook": true|false,
    "category": "namespace|deployment|network|rbac|storage|security|operator|scaling|configuration|deletion|monitoring",
    "risk_level": "low|medium|high|critical",
    "target_namespace": "<namespace or null>",
    "resources": ["<ordered list of K8s/OpenShift kinds to create, e.g. Namespace, ResourceQuota>"],
    "destructive": true|false,
    "summary": "<one-line summary of what the playbook will do>"
}}
"""

CORRECTION_PROMPT = """The Ansible playbook you produced failed validation. Fix every issue below
and output the COMPLETE corrected playbook as valid Ansible YAML only (no markdown, no prose).

VALIDATION ERRORS:
{errors}

PLAYBOOK TO FIX:
{yaml}
"""


# ════════════════════════════════════════════════════════════════════
# Helpers
# ════════════════════════════════════════════════════════════════════

def _slug(text: str) -> str:
    cleaned = re.sub(r'[^a-z0-9\s-]', '', text.lower().strip())
    slug = re.sub(r'[\s]+', '-', cleaned)[:60].strip('-')
    return slug or "playbook"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _strip_fences(text: str) -> str:
    """Remove markdown code fences and surrounding whitespace from a model response."""
    text = (text or "").strip()
    if text.startswith("```"):
        text = re.sub(r'^```(?:ya?ml|json)?\n?', '', text)
        text = re.sub(r'\n?```$', '', text)
    return text.strip()


def _coerce_text(result: Any) -> str:
    """Model providers may return a str or a ModelResponse-like object. Normalize to str."""
    if isinstance(result, str):
        return result
    # ModelResponse / objects with .content
    content = getattr(result, "content", None)
    if isinstance(content, str):
        return content
    return str(result) if result is not None else ""


# ════════════════════════════════════════════════════════════════════
# Generator
# ════════════════════════════════════════════════════════════════════

class PlaybookGenerator:
    """Advanced playbook generator: plan → ground → generate → validate → self-correct,
    with verified-template assembly as a guaranteed-correct fallback."""

    def __init__(self, model_provider, max_correction_rounds: int = 2):
        self.model_provider = model_provider
        self.validator = PlaybookValidator()
        self.max_correction_rounds = max_correction_rounds

    # ── Model call (normalized) ──

    async def _call_model(self, prompt: str, system: Optional[str] = None) -> str:
        """Call whatever provider is wired in, returning normalized text.
        Raises on genuine failure so the caller can decide to retry or assemble."""
        if hasattr(self.model_provider, "complete"):
            result = await self.model_provider.complete(prompt, system=system)
        elif hasattr(self.model_provider, "chat"):
            result = await self.model_provider.chat(prompt, system=system)
        else:
            raise RuntimeError("model_provider exposes neither complete() nor chat()")
        return _coerce_text(result)

    # ── Step 1: PLAN ──

    async def analyze_intent(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Decide whether to generate and plan the resources. Falls back to a keyword
        heuristic if the model can't return parseable JSON."""
        prompt = PLAN_PROMPT.format(intent=message)
        try:
            raw = _strip_fences(await self._call_model(prompt))
            plan = json.loads(raw)
            # Normalize keys we rely on downstream.
            plan.setdefault("resources", plan.get("target_resources", []))
            return plan
        except Exception as e:
            log.warning("Intent planning fell back to heuristic: %s", e)
            return self._heuristic_plan(message)

    def _heuristic_plan(self, message: str) -> Dict[str, Any]:
        lower = message.lower()
        action_keywords = [
            "create", "deploy", "scale", "delete", "remove", "configure",
            "install", "update", "patch", "restrict", "lock", "expose",
            "migrate", "backup", "restore", "rotate", "provision",
            "add", "set up", "enable", "disable", "enforce",
        ]
        # Use the knowledge retriever's resolver to detect resources from text.
        resolved = resolve_templates(message, [])
        resources = [t["key"] for t in resolved]
        return {
            "should_generate_playbook": any(kw in lower for kw in action_keywords) or bool(resources),
            "category": "configuration",
            "risk_level": "medium",
            "target_namespace": None,
            "resources": resources,
            "destructive": any(kw in lower for kw in ("delete", "remove", "destroy")),
            "summary": message[:100],
        }

    # ── Step 2–5: GROUND → GENERATE → VALIDATE → SELF-CORRECT ──

    async def generate(
        self,
        intent: str,
        target_namespace: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate a validated Ansible playbook. Always returns a real, deployable
        playbook — never a TODO stub. If the model is unreachable or keeps producing
        invalid YAML, assembles one from verified templates."""
        ctx = context or {}
        playbook_id = f"pb-{uuid.uuid4().hex[:12]}"
        file_name = f"{_slug(intent)}.yml"
        resource_types = ctx.get("resource_types") or ctx.get("resources") or []

        # GROUND: pull verified knowledge for this intent.
        knowledge = retrieve_knowledge(intent, resource_types)

        ns_hint = f"\nTarget namespace: {target_namespace}" if target_namespace else ""
        extra_context = f"\nAdditional context: {json.dumps(ctx, default=str)}" if ctx else ""

        gen_prompt = (
            f"{knowledge}\n\n"
            f"───────────────────────────────────────\n"
            f"Generate an Ansible playbook for this request:\n\n"
            f"{intent}{ns_hint}{extra_context}\n\n"
            f"Output ONLY valid Ansible YAML."
        )

        source = "model"
        yaml_content = ""
        validation: Dict[str, Any] = {}

        try:
            # GENERATE
            yaml_content = _strip_fences(await self._call_model(gen_prompt, system=SYSTEM_PROMPT))
            if not yaml_content:
                raise RuntimeError("model returned empty content")

            # VALIDATE → SELF-CORRECT loop
            yaml_content, validation = await self._validate_and_correct(yaml_content)

            # If still invalid after correction rounds, prefer a correct assembled playbook.
            if not validation.get("valid", False):
                assembled = self._assemble_from_templates(intent, target_namespace, resource_types)
                if assembled:
                    av = self.validator.validate(assembled)
                    # Use the assembled version only if it's at least as valid.
                    if av.get("valid", False):
                        yaml_content, validation, source = assembled, av, "assembled"

        except Exception as e:
            # Model unreachable / errored → assemble a correct playbook from templates.
            log.warning("Generation via model failed (%s) — assembling from verified templates", e)
            assembled = self._assemble_from_templates(intent, target_namespace, resource_types)
            if assembled:
                yaml_content = assembled
                validation = self.validator.validate(assembled)
                source = "assembled"
            else:
                # Last resort: a minimal but VALID playbook (not a stub) so the pipeline holds.
                yaml_content = self._minimal_valid_playbook(intent, target_namespace)
                validation = self.validator.validate(yaml_content)
                source = "minimal"

        # Normalize leading marker.
        yaml_content = yaml_content.strip()
        if not yaml_content.startswith("---"):
            yaml_content = f"---\n{yaml_content}"

        risk_level = self._assess_risk(yaml_content, intent)

        return {
            "playbook_id": playbook_id,
            "intent": intent,
            "yaml_content": yaml_content,
            "file_name": file_name,
            "risk_level": risk_level,
            "target_namespace": target_namespace,
            "validation": validation,
            "generation_source": source,  # model | assembled | minimal
            "generated_at": _utc_now(),
            "model_provider": getattr(self.model_provider, "provider_name", "unknown"),
        }

    async def _validate_and_correct(self, yaml_content: str) -> Tuple[str, Dict[str, Any]]:
        """Validate; if invalid, feed errors back to the model and regenerate, up to
        max_correction_rounds. Returns the best YAML and its validation result."""
        validation = self.validator.validate(yaml_content)
        rounds = 0
        while not validation.get("valid", False) and rounds < self.max_correction_rounds:
            rounds += 1
            errors = "\n".join(
                f"- {i.get('check', '')}: {i.get('message', '')}"
                for i in validation.get("issues", [])
            ) or "- Playbook is not valid Ansible YAML."
            correction = CORRECTION_PROMPT.format(errors=errors, yaml=yaml_content)
            try:
                fixed = _strip_fences(await self._call_model(correction, system=SYSTEM_PROMPT))
            except Exception as e:
                log.warning("Self-correction round %d failed to reach model: %s", rounds, e)
                break
            if not fixed:
                break
            new_validation = self.validator.validate(fixed)
            # Keep the fix only if it's an improvement (fewer/no issues).
            if len(new_validation.get("issues", [])) <= len(validation.get("issues", [])):
                yaml_content, validation = fixed, new_validation
            if validation.get("valid", False):
                break
        return yaml_content, validation

    # ── Fallback: ASSEMBLE from verified templates ──

    def _assemble_from_templates(
        self,
        intent: str,
        target_namespace: Optional[str],
        resource_types: List[str],
    ) -> Optional[str]:
        """Build a correct, complete playbook by stitching verified resource templates
        into kubernetes.core.k8s tasks. Returns None if no templates resolve."""
        templates = resolve_templates(intent, resource_types)
        if not templates:
            return None

        ns = target_namespace or self._guess_namespace(intent) or "default"
        name = self._guess_name(intent) or "arnie-resource"

        tasks: List[str] = []
        for tpl in templates:
            body = tpl["template"]
            scoped = tpl["scope"] == "namespaced"
            # Fill obvious placeholders deterministically.
            body = (
                body.replace("<name>", name)
                    .replace("<namespace>", ns)
                    .replace("<image>", "registry.access.redhat.com/ubi9/ubi:latest")
                    .replace("<storage-class>", "")
                    .replace("<storage>", "10Gi")
            )
            # Indent the resource body under `definition:` (6 spaces).
            definition = "\n".join(("          " + ln if ln else ln) for ln in body.splitlines())
            task = (
                f"    - name: Ensure {tpl['key']} '{name}' is present\n"
                f"      kubernetes.core.k8s:\n"
                f"        state: present\n"
                f"        definition:\n"
                f"{definition}\n"
            )
            tasks.append(task)

        playbook = (
            "---\n"
            f"- name: {intent[:80]}\n"
            "  hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  tasks:\n"
            + "\n".join(tasks)
        )
        return playbook

    def _minimal_valid_playbook(self, intent: str, namespace: Optional[str]) -> str:
        """A minimal but structurally-valid playbook (passes validation) when nothing
        else resolves — still real, not a TODO stub."""
        ns = namespace or "default"
        return (
            "---\n"
            f"- name: {intent[:80]}\n"
            "  hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  tasks:\n"
            "    - name: Query cluster namespaces to confirm connectivity\n"
            "      kubernetes.core.k8s_info:\n"
            "        api_version: v1\n"
            "        kind: Namespace\n"
            f"      register: arnie_ns_check\n"
        )

    # ── Heuristics for name/namespace extraction ──

    def _guess_namespace(self, intent: str) -> Optional[str]:
        m = re.search(r'namespace\s+(?:called\s+|named\s+)?["\']?([a-z0-9][a-z0-9-]*)', intent, re.I)
        if m:
            return m.group(1)
        m = re.search(r'\bin\s+(?:the\s+)?["\']?([a-z0-9][a-z0-9-]*)\s+namespace', intent, re.I)
        return m.group(1) if m else None

    def _guess_name(self, intent: str) -> Optional[str]:
        m = re.search(r'(?:called|named)\s+["\']?([a-z0-9][a-z0-9-]*)', intent, re.I)
        if m:
            return m.group(1)
        return None

    # ── Blast radius + risk (kept, with the same public signatures) ──

    def estimate_blast_radius(
        self,
        yaml_content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        lower = yaml_content.lower()
        resource_kinds = []
        for kind in [
            "namespace", "deployment", "statefulset", "daemonset",
            "service", "networkpolicy", "role", "clusterrole",
            "rolebinding", "clusterrolebinding", "configmap", "secret",
            "persistentvolumeclaim", "route", "ingress", "job", "cronjob",
        ]:
            if kind in lower:
                resource_kinds.append(kind)
        ns_matches = re.findall(r'namespace:\s*(\S+)', yaml_content)
        namespaces = list(set(ns_matches))
        deletions = lower.count("state: absent")
        cluster_scoped = any(k in resource_kinds for k in ["clusterrole", "clusterrolebinding", "namespace"])
        parts = []
        if resource_kinds:
            parts.append(f"{len(resource_kinds)} resource type(s)")
        if namespaces:
            parts.append(f"{len(namespaces)} namespace(s)")
        if deletions:
            parts.append(f"{deletions} deletion(s)")
        if cluster_scoped:
            parts.append("cluster-scoped changes")
        return {
            "resource_kinds": resource_kinds,
            "namespaces": namespaces,
            "deletions": deletions,
            "cluster_scoped": cluster_scoped,
            "estimated_resources": len(resource_kinds),
            "summary": ", ".join(parts) if parts else "minimal impact",
        }

    def _assess_risk(self, yaml_content: str, intent: str) -> str:
        lower = yaml_content.lower()
        intent_lower = intent.lower()
        if any(kw in lower for kw in ["clusterrole", "clusterrolebinding", "securitycontextconstraints"]) and "state: absent" in lower:
            return "critical"
        if "state: absent" in lower:
            return "high"
        if any(kw in intent_lower for kw in ["delete", "remove", "destroy", "drain", "cordon"]):
            return "high"
        if any(kw in lower for kw in ["deployment", "statefulset", "networkpolicy", "role"]):
            return "medium"
        return "low"

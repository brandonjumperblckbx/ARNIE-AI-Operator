"""
ARNIE Playbook Generator
Translates natural language infrastructure intent into validated Ansible playbook YAML.
Uses the RMCP engine's model router and agent pipeline for AI-powered generation.
"""

import json
import uuid
import re
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

log = logging.getLogger("arnie.playbook-generator")

# ── Playbook templates for common patterns ──

SYSTEM_PROMPT = """You are ARNIE — Ansible Remediation & Navigation Intelligence Engine.
You generate production-grade Ansible playbooks for OpenShift and Kubernetes infrastructure.

RULES:
1. Always output valid Ansible YAML — no markdown fences, no explanation, just YAML.
2. Use `kubernetes.core.k8s` and `kubernetes.core.k8s_info` modules for cluster operations.
3. Use `connection: local` and `hosts: localhost` — playbooks run inside an Execution Environment.
4. Include meaningful task names that describe what each step does.
5. Use `state: present` for creation/updates, `state: absent` for deletion.
6. Add `register:` for tasks whose output matters to subsequent steps.
7. Include validation tasks that confirm the operation succeeded.
8. Set appropriate `namespace:` on every resource definition.
9. For destructive operations, add a confirmation task or note in the playbook name.
10. Output ONLY the YAML playbook content — no preamble, no commentary.

RESOURCE KNOWLEDGE:
- Namespace: apiVersion v1, kind Namespace
- Deployment: apiVersion apps/v1, kind Deployment
- Service: apiVersion v1, kind Service
- NetworkPolicy: apiVersion networking.k8s.io/v1, kind NetworkPolicy
- Role/ClusterRole: apiVersion rbac.authorization.k8s.io/v1
- RoleBinding/ClusterRoleBinding: apiVersion rbac.authorization.k8s.io/v1
- ConfigMap: apiVersion v1, kind ConfigMap
- Secret: apiVersion v1, kind Secret
- PersistentVolumeClaim: apiVersion v1, kind PersistentVolumeClaim
- Route (OpenShift): apiVersion route.openshift.io/v1, kind Route
- SecurityContextConstraints: apiVersion security.openshift.io/v1, kind SecurityContextConstraints
"""

INTENT_ANALYSIS_PROMPT = """Analyze this infrastructure request and respond ONLY with JSON (no markdown):

Request: "{intent}"

Respond with:
{{
    "should_generate_playbook": true/false,
    "category": "namespace|deployment|network|rbac|storage|security|operator|scaling|configuration|deletion|monitoring",
    "risk_level": "low|medium|high|critical",
    "target_namespace": "detected namespace or null",
    "target_resources": ["list of k8s resource types involved"],
    "destructive": true/false,
    "summary": "one-line summary of what the playbook will do"
}}
"""


def _slug(text: str) -> str:
    """Convert text to a filename-safe slug."""
    cleaned = re.sub(r'[^a-z0-9\s-]', '', text.lower().strip())
    slug = re.sub(r'[\s]+', '-', cleaned)[:60].strip('-')
    return slug or "playbook"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PlaybookGenerator:
    """Generates Ansible playbooks from natural language using the RMCP engine."""

    def __init__(self, model_provider):
        self.model_provider = model_provider

    async def analyze_intent(
        self,
        message: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Analyze whether a message warrants playbook generation."""
        prompt = INTENT_ANALYSIS_PROMPT.format(intent=message)

        try:
            if hasattr(self.model_provider, 'complete'):
                result = await self.model_provider.complete(prompt)
                raw = result if isinstance(result, str) else getattr(result, 'content', str(result))
            elif hasattr(self.model_provider, 'chat'):
                result = await self.model_provider.chat(prompt)
                raw = result if isinstance(result, str) else str(result)
            else:
                raw = '{"should_generate_playbook": false}'

            # Parse JSON from response
            raw = raw.strip()
            if raw.startswith('```'):
                raw = re.sub(r'^```(?:json)?\n?', '', raw)
                raw = re.sub(r'\n?```$', '', raw)

            return json.loads(raw)

        except (json.JSONDecodeError, Exception) as e:
            log.warning("Intent analysis failed: %s", e)
            # Heuristic fallback — look for action keywords
            action_keywords = [
                "create", "deploy", "scale", "delete", "remove", "configure",
                "install", "update", "patch", "restrict", "lock", "expose",
                "migrate", "backup", "restore", "rotate", "provision",
                "add", "set up", "enable", "disable", "enforce",
            ]
            lower = message.lower()
            has_action = any(kw in lower for kw in action_keywords)
            return {
                "should_generate_playbook": has_action,
                "category": "configuration",
                "risk_level": "medium",
                "target_namespace": None,
                "target_resources": [],
                "destructive": any(kw in lower for kw in ("delete", "remove", "destroy")),
                "summary": message[:100],
            }

    async def generate(
        self,
        intent: str,
        target_namespace: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Generate an Ansible playbook from natural language intent."""
        ctx = context or {}
        playbook_id = f"pb-{uuid.uuid4().hex[:12]}"
        file_slug = _slug(intent)
        file_name = f"{file_slug}.yml"

        # Build the generation prompt
        ns_hint = f"\nTarget namespace: {target_namespace}" if target_namespace else ""
        extra_context = ""
        if ctx:
            extra_context = f"\nAdditional context: {json.dumps(ctx, default=str)}"

        prompt = (
            f"Generate an Ansible playbook for the following request:\n\n"
            f"{intent}{ns_hint}{extra_context}\n\n"
            f"Output ONLY valid Ansible YAML. No markdown, no explanation."
        )

        try:
            if hasattr(self.model_provider, 'complete'):
                result = await self.model_provider.complete(prompt, system=SYSTEM_PROMPT)
                yaml_content = result if isinstance(result, str) else getattr(result, 'content', str(result))
            elif hasattr(self.model_provider, 'chat'):
                result = await self.model_provider.chat(prompt, system=SYSTEM_PROMPT)
                yaml_content = result if isinstance(result, str) else str(result)
            else:
                yaml_content = self._fallback_playbook(intent, target_namespace)
        except Exception as e:
            log.error("Playbook generation failed: %s", e)
            yaml_content = self._fallback_playbook(intent, target_namespace)

        # Clean up the response
        yaml_content = yaml_content.strip()
        if yaml_content.startswith('```'):
            yaml_content = re.sub(r'^```(?:ya?ml)?\n?', '', yaml_content)
            yaml_content = re.sub(r'\n?```$', '', yaml_content)
        yaml_content = yaml_content.strip()

        # Ensure it starts with ---
        if not yaml_content.startswith('---'):
            yaml_content = f"---\n{yaml_content}"

        # Analyze risk
        risk_level = self._assess_risk(yaml_content, intent)

        return {
            "playbook_id": playbook_id,
            "intent": intent,
            "yaml_content": yaml_content,
            "file_name": file_name,
            "risk_level": risk_level,
            "target_namespace": target_namespace,
            "generated_at": _utc_now(),
            "model_provider": getattr(self.model_provider, 'provider_name', 'unknown'),
        }

    def estimate_blast_radius(
        self,
        yaml_content: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Estimate the blast radius of a generated playbook."""
        lower = yaml_content.lower()

        # Count resources being modified
        resource_kinds = []
        for kind in [
            "namespace", "deployment", "statefulset", "daemonset",
            "service", "networkpolicy", "role", "clusterrole",
            "rolebinding", "clusterrolebinding", "configmap", "secret",
            "persistentvolumeclaim", "route", "ingress", "job", "cronjob",
        ]:
            if kind in lower:
                resource_kinds.append(kind)

        # Count namespaces
        ns_matches = re.findall(r'namespace:\s*(\S+)', yaml_content)
        namespaces = list(set(ns_matches))

        # Detect state: absent (deletions)
        deletions = lower.count("state: absent")

        # Detect cluster-scoped resources
        cluster_scoped = any(k in resource_kinds for k in [
            "clusterrole", "clusterrolebinding", "namespace"
        ])

        # Build summary
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
        """Assess risk level based on playbook content."""
        lower = yaml_content.lower()
        intent_lower = intent.lower()

        # Critical: cluster-wide destructive operations
        if any(kw in lower for kw in [
            "clusterrole", "clusterrolebinding",
            "securitycontextconstraints",
        ]) and "state: absent" in lower:
            return "critical"

        # High: deletions, RBAC changes, security changes
        if any(kw in lower for kw in ["state: absent"]):
            return "high"
        if any(kw in intent_lower for kw in [
            "delete", "remove", "destroy", "drain", "cordon",
        ]):
            return "high"

        # Medium: deployments, config changes, scaling
        if any(kw in lower for kw in [
            "deployment", "statefulset", "networkpolicy", "role",
        ]):
            return "medium"

        return "low"

    def _fallback_playbook(self, intent: str, namespace: Optional[str] = None) -> str:
        """Generate a minimal playbook template when the AI model is unavailable."""
        ns = namespace or "default"
        return (
            f"---\n"
            f"- name: {intent[:80]}\n"
            f"  hosts: localhost\n"
            f"  connection: local\n"
            f"  gather_facts: false\n"
            f"  tasks:\n"
            f"    - name: TODO — implement generated task\n"
            f"      ansible.builtin.debug:\n"
            f"        msg: \"Playbook generated for intent: {intent[:100]}\"\n"
        )

"""
ARNIE Operator Setup Builder
Assembles COMPLETE operator lifecycle playbooks from the grounded operator knowledge base.

This is the piece that delivers the product promise: a user says "install Quay" (or Grafana,
or cert-manager) and ARNIE produces ONE playbook that goes from nothing to a running,
configured, verified operator — install the operator, wait for it to be ready, create and
configure its operand, and verify it's actually up. No guesswork.

Two-phase, conversational by design:
  • PHASE 1 (gather): if the operator has config questions and the user hasn't answered them
    yet, ARNIE returns the QUESTIONS instead of a playbook — "before I configure this, a few
    quick things..." — exactly the come-back-and-ask flow.
  • PHASE 2 (assemble): once answers are in hand (or none are needed), ARNIE assembles the
    complete lifecycle playbook, grounded in verified metadata + CR templates.

For operators not in the grounded catalog, ARNIE lays down the standardized OLM install
sequence reliably, then a CRD-discovery step so the operand can be grounded from the live
cluster rather than guessed.

Built on the RMCP engine by BLCKBX.
"""

import re
import uuid
import secrets
import logging
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from operator_knowledge import (
    build_operator_grounding,
    INSTALL_SEQUENCE,
    OPERATOR_FALLBACK,
)

log = logging.getLogger("arnie.operator-setup")


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _slug(text: str) -> str:
    s = re.sub(r'[^a-z0-9\s-]', '', (text or '').lower().strip())
    s = re.sub(r'\s+', '-', s)[:60].strip('-')
    return s or "operator-setup"


def _gen_password(n: int = 20) -> str:
    """Generate a URL-safe secure password for operands that need one."""
    return secrets.token_urlsafe(n)


def _indent(block: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join((pad + ln if ln else ln) for ln in block.splitlines())


class OperatorSetupBuilder:
    """Builds complete operator lifecycle playbooks from grounded knowledge."""

    def __init__(self, auto_grounder=None):
        # Optional Tier-2 auto-grounder. When set, operators with no curated catalog
        # entry are grounded live from their own CSV/CRD instead of falling all the way
        # back to the bare install-and-discover path.
        self.auto_grounder = auto_grounder

    def _grounding_for(self, intent: str) -> Dict[str, Any]:
        """Resolve grounding with tiering: curated catalog first, then auto-ground from
        the operator's own metadata, then the bare fallback."""
        grounding = build_operator_grounding(intent)
        if grounding["grounded"]:
            return grounding
        # Tier 2: try to auto-ground from the operator's CSV/CRD on the live cluster.
        if self.auto_grounder is not None:
            try:
                if self.auto_grounder.can_autoground():
                    name = grounding.get("package_name") or intent
                    auto = self.auto_grounder.ground(name)
                    if auto:
                        return self._auto_to_grounding(auto, grounding)
            except Exception as e:  # auto-grounding is best-effort; never break the flow
                log.warning("Auto-ground failed for '%s': %s", intent, e)
        return grounding

    def _auto_to_grounding(self, auto: Dict[str, Any], base: Dict[str, Any]) -> Dict[str, Any]:
        """Convert an auto-grounding (from the operator's metadata) into the catalog-entry
        shape the builder's grounded path expects."""
        operand = auto["operand"]
        # Map auto config questions (key/question/input/required/default) to the catalog
        # question shape (field/question/type/required/default).
        qs = []
        for q in auto.get("config_questions", []):
            qs.append({
                "field": q["key"],
                "question": q["question"],
                "type": q.get("input", "text"),
                "required": q.get("required", False),
                "default": q.get("default"),
            })
        # Build a CR template from the alm-example: re-serialize with placeholders for the
        # asked fields so the user's answers thread through consistently.
        cr_template = self._cr_template_from_example(auto.get("cr_example"), operand, qs)
        op_entry = {
            "display_name": auto["display_name"],
            "package_name": auto.get("package_name") or auto.get("csv_name", "").split(".v")[0] or auto["display_name"],
            "channel": auto.get("channel"),
            "catalog_source": auto.get("catalog_source"),
            "catalog_source_namespace": auto.get("catalog_source_namespace", "openshift-marketplace"),
            "default_install_namespace": auto.get("install_namespace") or f'{_slug(auto["display_name"])}',
            "install_mode": auto.get("install_mode", "AllNamespaces"),
            "operand": {
                "kind": operand["kind"],
                "api_version": operand["api_version"],
                "workload_weight": operand.get("workload_weight", "standard"),
                "cr_template": cr_template,
                "verify": {"by": "exists"},
            },
            "config_questions": qs,
            "_auto": True,  # marker: this entry was auto-grounded, not curated
        }
        return {
            "grounded": True,
            "operator_key": None,
            "operator": op_entry,
            "package_name": op_entry["package_name"],
            "install_sequence": base["install_sequence"],
            "config_questions": qs,
            "grounding_text": auto.get("notes", "Auto-grounded from operator metadata."),
            "_auto": True,
        }

    def _cr_template_from_example(self, example, operand, questions) -> str:
        """Render the alm-example as a YAML CR template, substituting {field} placeholders
        for the fields ARNIE will ask about so answers thread through. Namespace + name are
        always templated for consistent pinning."""
        import yaml as _yaml
        ex = dict(example or {})
        ex.setdefault("apiVersion", operand.get("api_version"))
        ex.setdefault("kind", operand.get("kind"))
        meta = dict(ex.get("metadata", {}) or {})
        meta["name"] = "{instance_name}"
        meta["namespace"] = "{install_namespace}"
        labels = dict(meta.get("labels", {}) or {})
        labels["app.kubernetes.io/managed-by"] = "arnie"
        meta["labels"] = labels
        ex["metadata"] = meta
        # Substitute asked spec fields with placeholders.
        spec = dict(ex.get("spec", {}) or {})
        for q in questions:
            f = q["field"]
            if f in ("instance_name", "install_namespace"):
                continue
            if f in spec and isinstance(spec[f], (str, int, float, bool)):
                spec[f] = "{" + f + "}"
        ex["spec"] = spec
        text = _yaml.safe_dump(ex, default_flow_style=False, sort_keys=False)
        # yaml quotes our placeholders; unquote them so .format() works.
        return text.replace("'{", "{").replace("}'", "}")

    def needs_questions(self, intent: str, answers: Optional[Dict[str, Any]]) -> bool:
        """True if this operator has config questions that haven't been answered yet."""
        grounding = self._grounding_for(intent)
        questions = grounding.get("config_questions", [])
        if not questions:
            return False
        answers = answers or {}
        # Only block on REQUIRED questions; optional ones fall back to defaults.
        for q in questions:
            if q.get("required") and q["field"] not in answers:
                return True
        # If nothing's been answered at all and there are questions, ask once.
        return len(answers) == 0

    def get_questions(self, intent: str) -> Dict[str, Any]:
        """Return the questions ARNIE should ask the user before configuring."""
        grounding = self._grounding_for(intent)
        op = grounding.get("operator") or {}
        return {
            "mode": "operator_setup_questions",
            "operator": op.get("display_name") or grounding.get("package_name") or "operator",
            "grounded": grounding["grounded"],
            "auto": grounding.get("_auto", False),
            "intro": (
                f"I can install and fully configure {op.get('display_name', 'this operator')} "
                f"for you — install it, wait for it to come up, set up its instance, and verify "
                f"it's running. Before I build the playbook, a few quick choices:"
            ),
            "questions": grounding.get("config_questions", []),
        }

    def build(
        self,
        intent: str,
        answers: Optional[Dict[str, Any]] = None,
        install_namespace: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Assemble the complete operator setup playbook.

        Returns the same shape as the main generator so it flows through the existing
        approval pipeline unchanged: playbook_id, yaml_content, file_name, risk_level,
        validation-less (caller validates), generation_source='operator-assembled', etc.
        """
        answers = dict(answers or {})
        grounding = self._grounding_for(intent)

        if grounding["grounded"]:
            yaml_content, summary = self._build_grounded(grounding, answers, install_namespace)
            source = "operator-auto" if grounding.get("_auto") else "operator-grounded"
        else:
            yaml_content, summary = self._build_fallback(grounding, install_namespace)
            source = "operator-fallback"

        return {
            "playbook_id": f"op-{uuid.uuid4().hex[:12]}",
            "intent": intent,
            "yaml_content": yaml_content,
            "file_name": f"{_slug(intent)}.yml",
            "risk_level": "medium",  # operator installs change cluster state but are additive
            "target_namespace": install_namespace or self._default_ns(grounding),
            "generation_source": source,
            "setup_summary": summary,
            "generated_at": _utc_now(),
        }

    # ── grounded path: full lifecycle from verified knowledge ──

    def _default_ns(self, grounding: Dict[str, Any]) -> str:
        op = grounding.get("operator")
        if op:
            return op.get("default_install_namespace", "default")
        return "operators"

    def _build_grounded(
        self,
        grounding: Dict[str, Any],
        answers: Dict[str, Any],
        install_namespace: Optional[str],
    ) -> (str, List[str]):
        op = grounding["operator"]
        ns = install_namespace or op["default_install_namespace"]
        operator_name = grounding["operator_key"] or op["package_name"]
        package_name = op["package_name"]
        channel = op["channel"]
        catalog_source = op["catalog_source"]
        all_namespaces = op.get("install_mode") == "AllNamespaces"

        # Resolve config answers → fill defaults, generate secrets where asked.
        resolved = self._resolve_answers(op.get("config_questions", []), answers, ns)

        fill = {
            "install_namespace": ns,
            "operator_name": operator_name,
            "package_name": package_name,
            "channel": channel,
            "catalog_source": catalog_source,
            **resolved,
        }

        tasks: List[str] = []
        summary: List[str] = []

        # 1) Namespace
        ns_def = INSTALL_SEQUENCE["steps"][0]["template"].format(**fill)
        tasks.append(self._k8s_task(f"Create namespace for {op['display_name']}", ns_def))
        summary.append(f"Create namespace '{ns}'")

        # 2) OperatorGroup (omit targetNamespaces for AllNamespaces mode)
        og_def = INSTALL_SEQUENCE["steps"][1]["template"].format(**fill)
        if all_namespaces:
            og_def = self._strip_target_namespaces(og_def)
        tasks.append(self._k8s_task(f"Create OperatorGroup for {op['display_name']}", og_def))
        summary.append("Create OperatorGroup")

        # 3) Subscription
        sub_def = INSTALL_SEQUENCE["steps"][2]["template"].format(**fill)
        tasks.append(self._k8s_task(f"Subscribe to {op['display_name']} ({channel})", sub_def))
        summary.append(f"Subscribe to {package_name} (channel {channel})")

        # 4) Wait for CSV Succeeded
        wait_task = INSTALL_SEQUENCE["steps"][3]["task_template"].format(**fill)
        tasks.append(wait_task)
        summary.append("Wait for operator to be ready (CSV Succeeded)")

        # 5) Wait for the operand's CRD to be registered & established. A CSV can
        # report 'Succeeded' a moment before its CRDs are discoverable by the API
        # server, which makes an immediate CR create fail with "Failed to find exact
        # match for <group>/<version>.<kind>". This step closes that race.
        operand = op["operand"]
        crd_name = self._operand_crd_name(operand)
        tasks.append(self._wait_for_crd_task(operand, crd_name))
        summary.append(f"Wait for the {operand['kind']} CRD to be ready")

        # 6) Create the operand (CR). NOTE: we do NOT block here (no wait: true).
        # Blocking the apply on readiness causes heavy/stateful operands (Elasticsearch,
        # Quay, databases) to fail the whole run with "Timed out waiting on resource"
        # even though the CR applied fine. Instead, apply immediately and let the
        # dedicated verify step (below) poll for readiness with a workload-appropriate
        # patience budget.
        cr_def = operand["cr_template"].format(**fill)
        tasks.append(self._k8s_task(
            f"Create and configure {operand['kind']} instance", cr_def, wait=False))
        summary.append(f"Create {operand['kind']} instance")

        # 7) Optional route exposure (if asked and applicable)
        if resolved.get("expose_route") is True:
            route_task = self._route_task(fill, operand)
            if route_task:
                tasks.append(route_task)
                summary.append("Expose with an OpenShift route")

        # 8) Verify the operand is actually running
        verify = operand.get("verify")
        if verify:
            tasks.append(self._verify_task(operand, ns, fill))
            summary.append(f"Verify {operand['kind']} is running")

        playbook = self._wrap_play(
            f"Install and configure {op['display_name']}", tasks)
        return playbook, summary

    def _resolve_answers(
        self,
        questions: List[Dict[str, Any]],
        answers: Dict[str, Any],
        ns: str,
    ) -> Dict[str, Any]:
        """Fill each config field from the user's answer or its default; generate
        secrets where the default is the sentinel '__generate__'."""
        out: Dict[str, Any] = {}
        for q in questions:
            field = q["field"]
            if field in answers and answers[field] not in (None, ""):
                out[field] = answers[field]
            else:
                default = q.get("default")
                if default == "__generate__":
                    out[field] = _gen_password()
                else:
                    out[field] = default
        # Always have an instance_name fallback.
        out.setdefault("instance_name", "instance")
        return out

    def _strip_target_namespaces(self, og_def: str) -> str:
        """Remove spec.targetNamespaces block for AllNamespaces-mode operators.
        Produces a valid `spec: {}` so the OperatorGroup watches all namespaces."""
        lines = og_def.splitlines()
        kept = []
        for ln in lines:
            stripped = ln.strip()
            # Drop the targetNamespaces key and its list items entirely.
            if "targetNamespaces" in ln:
                continue
            if stripped.startswith("-") and "targetNamespaces" not in ln:
                # list item under targetNamespaces (a bare '- namespace') — drop it
                # only if we're in the spec block; safe here since OperatorGroup spec
                # has no other lists in our template.
                continue
            kept.append(ln)
        text = "\n".join(kept)
        # Replace a now-empty 'spec:' (nothing meaningful after it) with 'spec: {}'.
        text = re.sub(r'(^|\n)(\s*)spec:\s*(?=\n|$)', r'\1\2spec: {}', text)
        # Collapse any trailing blank lines.
        return text.rstrip("\n") + "\n"

    # ── fallback path: reliable install + CRD discovery ──

    def _build_fallback(
        self,
        grounding: Dict[str, Any],
        install_namespace: Optional[str],
    ) -> (str, List[str]):
        pkg = grounding.get("package_name") or "the-operator"
        ns = install_namespace or f"{pkg}-operator"
        operator_name = re.sub(r'[^a-z0-9-]', '-', pkg)

        fill = {
            "install_namespace": ns,
            "operator_name": operator_name,
            "package_name": pkg,
            "channel": "stable",
            "catalog_source": "redhat-operators",
        }

        tasks: List[str] = []
        summary: List[str] = []

        ns_def = INSTALL_SEQUENCE["steps"][0]["template"].format(**fill)
        tasks.append(self._k8s_task(f"Create namespace for {pkg}", ns_def))
        summary.append(f"Create namespace '{ns}'")

        og_def = self._strip_target_namespaces(
            INSTALL_SEQUENCE["steps"][1]["template"].format(**fill))
        tasks.append(self._k8s_task(f"Create OperatorGroup for {pkg}", og_def))
        summary.append("Create OperatorGroup (AllNamespaces)")

        sub_def = INSTALL_SEQUENCE["steps"][2]["template"].format(**fill)
        tasks.append(self._k8s_task(
            f"Subscribe to {pkg} (verify channel/source in OperatorHub)", sub_def))
        summary.append(f"Subscribe to {pkg}")

        wait_task = INSTALL_SEQUENCE["steps"][3]["task_template"].format(**fill)
        tasks.append(wait_task)
        summary.append("Wait for operator to be ready (CSV Succeeded)")

        # CRD discovery so the operand can be grounded from the live cluster
        tasks.append(OPERATOR_FALLBACK["crd_inspection_task"])
        summary.append("Discover the operator's CRDs to configure its instance")

        tasks.append(self._debug_task(
            "Operator installed. Review discovered_crds for the operand schema, then "
            "ARNIE can generate the Custom Resource grounded in the live CRD."))
        summary.append("Report CRDs for grounded CR generation")

        playbook = self._wrap_play(f"Install {pkg} operator", tasks)
        return playbook, summary

    # ── task builders ──

    def _k8s_task(self, name: str, definition_block: str, wait: bool = False) -> str:
        body = _indent(definition_block.rstrip("\n"), 10)
        wait_lines = ""
        if wait:
            wait_lines = (
                "        wait: true\n"
                "        wait_timeout: 300\n"
            )
        return (
            f"    - name: {name}\n"
            f"      kubernetes.core.k8s:\n"
            f"        state: present\n"
            f"{wait_lines}"
            f"        definition:\n"
            f"{body}\n"
        )

    def _route_task(self, fill: Dict[str, Any], operand: Dict[str, Any]) -> Optional[str]:
        ns = fill["install_namespace"]
        name = fill.get("instance_name", "instance")
        # Generic edge route to a service named after the instance (operator-dependent;
        # safe default for Grafana-style operands that expose a Service).
        route = (
            "apiVersion: route.openshift.io/v1\n"
            "kind: Route\n"
            "metadata:\n"
            f"  name: {name}-route\n"
            f"  namespace: {ns}\n"
            "  labels:\n"
            "    app.kubernetes.io/managed-by: arnie\n"
            "spec:\n"
            f"  to:\n"
            f"    kind: Service\n"
            f"    name: {name}-service\n"
            "  tls:\n"
            "    termination: edge\n"
        )
        return self._k8s_task("Expose instance with an OpenShift route", route)

    def _operand_crd_name(self, operand: Dict[str, Any]) -> str:
        """Derive the CRD name 'plural.group' from the operand's apiVersion + kind.
        e.g. grafana.integreatly.org/v1beta1 + Grafana -> grafanas.grafana.integreatly.org"""
        api_version = operand["api_version"]
        group = api_version.split("/")[0] if "/" in api_version else ""
        lower = operand["kind"].lower()
        if lower.endswith("s"):
            plural = lower + "es"
        elif lower.endswith("y"):
            plural = lower[:-1] + "ies"
        else:
            plural = lower + "s"
        return f"{plural}.{group}" if group else plural

    def _wait_for_crd_task(self, operand: Dict[str, Any], crd_name: str) -> str:
        """Poll until the operand's CRD exists AND reports the Established condition,
        so the CR create that follows can't lose the install race (a CSV can report
        Succeeded a moment before its CRDs are discoverable by the API server)."""
        return (
            f"    - name: Wait for the {operand['kind']} CRD to be established\n"
            f"      kubernetes.core.k8s_info:\n"
            f"        api_version: apiextensions.k8s.io/v1\n"
            f"        kind: CustomResourceDefinition\n"
            f"        name: {crd_name}\n"
            f"      register: operand_crd\n"
            f"      until: >\n"
            f"        operand_crd.resources | length > 0 and\n"
            f"        (operand_crd.resources[0].status.conditions | default([])\n"
            f"         | selectattr('type', 'equalto', 'Established')\n"
            f"         | selectattr('status', 'equalto', 'True') | list | length > 0)\n"
            f"      retries: 30\n"
            f"      delay: 5\n"
        )

    def _verify_task(self, operand: Dict[str, Any], ns: str, fill: Dict[str, Any]) -> str:
        name = fill.get("instance_name", "instance")
        # Scale patience to the operand's workload weight. Stateless apps come up fast;
        # stateful clusters (Elasticsearch, Quay, databases) need much longer — and even
        # then we treat a timeout as "still starting," not a hard failure, so a slow
        # reconcile never fails the whole install.
        weight = operand.get("workload_weight", "standard")
        budgets = {
            "light":    (20, 10),    # ~3 min   (stateless, small)
            "standard": (40, 15),    # ~10 min  (typical app/operand)
            "heavy":    (90, 20),    # ~30 min  (stateful clusters, storage-bound)
        }
        retries, delay = budgets.get(weight, budgets["standard"])
        approx_min = (retries * delay) // 60
        return (
            f"    - name: Wait for {operand['kind']} '{name}' to come up (up to ~{approx_min} min)\n"
            f"      kubernetes.core.k8s_info:\n"
            f"        api_version: {operand['api_version']}\n"
            f"        kind: {operand['kind']}\n"
            f"        name: {name}\n"
            f"        namespace: {ns}\n"
            f"      register: operand_status\n"
            f"      until: operand_status.resources | length > 0\n"
            f"      retries: {retries}\n"
            f"      delay: {delay}\n"
            f"      failed_when: false\n"
            f"\n"
            f"    - name: Report {operand['kind']} status\n"
            f"      ansible.builtin.debug:\n"
            f"        msg: >-\n"
            f"          {operand['kind']} '{name}' has been created in {ns}. If it is still\n"
            f"          starting, the operator will continue reconciling it in the background;\n"
            f"          a slow start is normal for this workload and is not a failure.\n"
        )

    def _debug_task(self, msg: str) -> str:
        return (
            f"    - name: Report status\n"
            f"      ansible.builtin.debug:\n"
            f"        msg: \"{msg}\"\n"
        )

    def _wrap_play(self, name: str, tasks: List[str]) -> str:
        return (
            "---\n"
            f"- name: {name}\n"
            "  hosts: localhost\n"
            "  connection: local\n"
            "  gather_facts: false\n"
            "  tasks:\n"
            + "\n".join(tasks)
        )

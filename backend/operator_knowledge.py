"""
ARNIE Operator Knowledge Base
Verified operator lifecycle knowledge for COMPLETE, end-to-end setup playbooks.

This is what takes ARNIE from "writes a playbook" to "writes the whole setup playbook
that goes from nothing to a running, configured, verified operator."

The accuracy problem for operators is acute: a model will hallucinate package names,
channels, and — worst of all — Custom Resource (operand) schemas, because every
operator's CR is different and the model's memory of them is stale. So ARNIE grounds
operator setup in:

  1. VERIFIED install metadata  — real package name, channel, catalogSource per operator
  2. A STANDARD install sequence — Namespace → OperatorGroup → Subscription → wait-for-CSV
     (this part is identical for almost every OLM operator, so ARNIE does it reliably
      for ANY operator, grounded or not)
  3. A CR TEMPLATE per operator  — the configured operand, grounded from the real CRD
  4. CONFIG QUESTIONS per operator — required/optional fields turned into plain-English
     questions, so ARNIE can converse a novice from confusion to a running operator
  5. A VERIFICATION step         — poll until the operand reports Ready, so "done" means
     actually running, not merely "submitted"

For operators NOT in this KB, ARNIE can still do the standard install sequence reliably,
then inspect the live CRD on the cluster to ground the CR (see OPERATOR_FALLBACK).

Built on the RMCP engine by BLCKBX.
"""

import re
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("arnie.operator-knowledge")


# ════════════════════════════════════════════════════════════════════
# STANDARD OLM INSTALL SEQUENCE
# Identical for almost every operator. This is the reliable backbone ARNIE
# can lay down for ANY operator, even ones not individually grounded below.
# Placeholders in {curly_braces} are filled by the generator from operator metadata.
# ════════════════════════════════════════════════════════════════════

INSTALL_SEQUENCE: Dict[str, Any] = {
    "description": (
        "The OLM operator install lifecycle: create the install namespace, an "
        "OperatorGroup defining the operator's watch scope, a Subscription that tells "
        "OLM which operator/channel to install, then WAIT for the ClusterServiceVersion "
        "(CSV) to reach phase 'Succeeded' before creating any Custom Resource. Creating "
        "the CR before the CSV succeeds is the #1 cause of operator setup failure."
    ),
    "steps": [
        {
            "name": "namespace",
            "purpose": "The namespace the operator is installed into.",
            "kind": "Namespace",
            "api_version": "v1",
            "scope": "cluster",
            "template": (
                "apiVersion: v1\n"
                "kind: Namespace\n"
                "metadata:\n"
                "  name: {install_namespace}\n"
                "  labels:\n"
                "    app.kubernetes.io/managed-by: arnie\n"
            ),
        },
        {
            "name": "operatorgroup",
            "purpose": (
                "Defines which namespaces the operator watches. For an "
                "AllNamespaces-mode operator, spec.targetNamespaces is omitted/empty. "
                "For OwnNamespace/SingleNamespace, it lists the target namespace."
            ),
            "kind": "OperatorGroup",
            "api_version": "operators.coreos.com/v1",
            "scope": "namespaced",
            "template": (
                "apiVersion: operators.coreos.com/v1\n"
                "kind: OperatorGroup\n"
                "metadata:\n"
                "  name: {operator_name}-og\n"
                "  namespace: {install_namespace}\n"
                "spec:\n"
                "  targetNamespaces:\n"
                "    - {install_namespace}\n"
            ),
            "notes": (
                "OMIT the entire spec.targetNamespaces block for AllNamespaces-mode "
                "operators (most cluster-wide operators). Include it only for "
                "namespace-scoped install modes."
            ),
        },
        {
            "name": "subscription",
            "purpose": "Tells OLM which operator package + channel to install and from which catalog.",
            "kind": "Subscription",
            "api_version": "operators.coreos.com/v1alpha1",
            "scope": "namespaced",
            "template": (
                "apiVersion: operators.coreos.com/v1alpha1\n"
                "kind: Subscription\n"
                "metadata:\n"
                "  name: {package_name}\n"
                "  namespace: {install_namespace}\n"
                "spec:\n"
                "  channel: {channel}\n"
                "  name: {package_name}\n"
                "  source: {catalog_source}\n"
                "  sourceNamespace: openshift-marketplace\n"
                "  installPlanApproval: Automatic\n"
            ),
        },
        {
            "name": "wait_for_csv",
            "purpose": (
                "Poll the ClusterServiceVersion until phase == 'Succeeded'. The operator "
                "is NOT usable until this passes. Only after this should the CR be created."
            ),
            "kind": "ClusterServiceVersion",
            "api_version": "operators.coreos.com/v1alpha1",
            "task_template": (
                "    - name: Wait for {operator_name} operator CSV to succeed\n"
                "      kubernetes.core.k8s_info:\n"
                "        api_version: operators.coreos.com/v1alpha1\n"
                "        kind: ClusterServiceVersion\n"
                "        namespace: {install_namespace}\n"
                "      register: {operator_name}_csv\n"
                "      until: >\n"
                "        {operator_name}_csv.resources | selectattr('status.phase', 'defined')\n"
                "        | selectattr('status.phase', 'equalto', 'Succeeded') | list | length > 0\n"
                "      retries: 30\n"
                "      delay: 10\n"
            ),
        },
    ],
}


# ════════════════════════════════════════════════════════════════════
# GROUNDED OPERATOR CATALOG
# Verified metadata + CR template + config questions for the common operators.
# Each entry is enough for ARNIE to build a COMPLETE setup playbook.
# ════════════════════════════════════════════════════════════════════

OPERATOR_CATALOG: Dict[str, Dict[str, Any]] = {

    "grafana": {
        "display_name": "Grafana Operator",
        "package_name": "grafana-operator",
        "channel": "v5",
        "catalog_source": "community-operators",
        "default_install_namespace": "grafana-operator",
        "install_mode": "AllNamespaces",
        "operand": {
            "kind": "Grafana",
            "api_version": "grafana.integreatly.org/v1beta1",
            "workload_weight": "standard",
            "purpose": "A running Grafana instance managed by the operator.",
            "cr_template": (
                "apiVersion: grafana.integreatly.org/v1beta1\n"
                "kind: Grafana\n"
                "metadata:\n"
                "  name: {instance_name}\n"
                "  namespace: {install_namespace}\n"
                "  labels:\n"
                "    dashboards: grafana\n"
                "    app.kubernetes.io/managed-by: arnie\n"
                "spec:\n"
                "  config:\n"
                "    security:\n"
                "      admin_user: {admin_user}\n"
                "      admin_password: {admin_password}\n"
                "    auth:\n"
                "      disable_login_form: \"false\"\n"
            ),
            "verify": {
                "kind": "Grafana",
                "ready_jsonpath": "status.stage",
                "ready_value": "complete",
            },
        },
        "config_questions": [
            {"field": "instance_name", "question": "What should the Grafana instance be named?",
             "default": "grafana", "required": False},
            {"field": "admin_user", "question": "Grafana admin username?",
             "default": "admin", "required": False},
            {"field": "admin_password", "question": "Admin password — set one, or shall I generate a secure one?",
             "default": "__generate__", "required": False, "secret": True},
            {"field": "expose_route", "question": "Expose Grafana with an OpenShift route so you can reach the UI?",
             "default": True, "required": False, "type": "bool"},
        ],
        "common_mistakes": [
            "v5 of the operator uses api group grafana.integreatly.org/v1beta1 — v4 used integreatly.org/v1alpha1. Do not mix them.",
            "The 'dashboards: grafana' label on the Grafana CR is how GrafanaDashboard CRs find this instance.",
        ],
    },

    "cert-manager": {
        "display_name": "cert-manager Operator",
        "package_name": "openshift-cert-manager-operator",
        "channel": "stable-v1",
        "catalog_source": "redhat-operators",
        "default_install_namespace": "cert-manager-operator",
        "install_mode": "AllNamespaces",
        "operand": {
            "kind": "CertManager",
            "api_version": "operator.openshift.io/v1alpha1",
            "purpose": "The cert-manager controller deployment, configured cluster-wide.",
            "cr_template": (
                "apiVersion: operator.openshift.io/v1alpha1\n"
                "kind: CertManager\n"
                "metadata:\n"
                "  name: cluster\n"
                "  labels:\n"
                "    app.kubernetes.io/managed-by: arnie\n"
                "spec:\n"
                "  managementState: Managed\n"
            ),
            "verify": {
                "kind": "CertManager",
                "ready_jsonpath": "status.conditions",
                "ready_value": "Available",
            },
        },
        "config_questions": [
            {"field": "create_issuer", "question": "Want me to also create a ClusterIssuer (e.g. Let's Encrypt) after install?",
             "default": False, "required": False, "type": "bool"},
        ],
        "common_mistakes": [
            "The Red Hat cert-manager operator's CR is named 'cluster' and is cluster-scoped (no namespace).",
            "Do not confuse the Red Hat 'openshift-cert-manager-operator' with the upstream 'cert-manager' community package — different channels and CRs.",
        ],
    },

    "prometheus": {
        "display_name": "Prometheus Operator",
        "package_name": "prometheus",
        "channel": "beta",
        "catalog_source": "community-operators",
        "default_install_namespace": "prometheus-operator",
        "install_mode": "AllNamespaces",
        "operand": {
            "kind": "Prometheus",
            "api_version": "monitoring.coreos.com/v1",
            "purpose": "A running Prometheus server instance.",
            "cr_template": (
                "apiVersion: monitoring.coreos.com/v1\n"
                "kind: Prometheus\n"
                "metadata:\n"
                "  name: {instance_name}\n"
                "  namespace: {install_namespace}\n"
                "  labels:\n"
                "    app.kubernetes.io/managed-by: arnie\n"
                "spec:\n"
                "  replicas: {replicas}\n"
                "  serviceAccountName: prometheus\n"
                "  serviceMonitorSelector: {{}}\n"
                "  resources:\n"
                "    requests:\n"
                "      memory: 400Mi\n"
            ),
            "verify": {
                "kind": "Prometheus",
                "ready_jsonpath": "status.availableReplicas",
                "ready_value": "1",
            },
        },
        "config_questions": [
            {"field": "instance_name", "question": "Name for the Prometheus instance?",
             "default": "prometheus", "required": False},
            {"field": "replicas", "question": "How many Prometheus replicas?",
             "default": 1, "required": False, "type": "int"},
        ],
        "common_mistakes": [
            "spec.serviceMonitorSelector: {} (empty) means 'select ALL ServiceMonitors'. Omitting it selects none.",
            "A Prometheus instance needs a ServiceAccount named 'prometheus' with appropriate RBAC to scrape — create it alongside.",
        ],
    },
}


# Alias map so user phrasing resolves to a catalog key.
OPERATOR_ALIASES: Dict[str, str] = {
    "grafana": "grafana",
    "grafana operator": "grafana",
    "cert manager": "cert-manager",
    "cert-manager": "cert-manager",
    "certmanager": "cert-manager",
    "certificates": "cert-manager",
    "prometheus": "prometheus",
    "prometheus operator": "prometheus",
    "monitoring": "prometheus",
}


# ════════════════════════════════════════════════════════════════════
# FALLBACK for operators NOT in the catalog
# ARNIE can still do the standard install reliably, then inspect the live CRD.
# ════════════════════════════════════════════════════════════════════

OPERATOR_FALLBACK: Dict[str, Any] = {
    "description": (
        "For an operator not in ARNIE's grounded catalog: lay down the standard OLM "
        "install sequence (Namespace → OperatorGroup → Subscription → wait-for-CSV) "
        "using the package name the user gave. The install part is standardized and "
        "reliable. For the CR (the configured operand), ARNIE does NOT guess the schema "
        "— instead it queries the cluster for the operator's CRD after install and uses "
        "the real schema to ground the CR, or asks the user what to configure."
    ),
    "crd_inspection_task": (
        "    - name: Discover CRDs owned by the installed operator\n"
        "      kubernetes.core.k8s_info:\n"
        "        api_version: apiextensions.k8s.io/v1\n"
        "        kind: CustomResourceDefinition\n"
        "      register: discovered_crds\n"
    ),
    "guidance": (
        "After install, read discovered_crds for the operator's owned kinds and their "
        "openAPIV3Schema. Required fields (schema.required) become the config questions "
        "ARNIE asks the user; optional fields get sensible defaults. This lets ARNIE "
        "configure operators it has never seen, grounded in the live CRD rather than memory."
    ),
}


# ════════════════════════════════════════════════════════════════════
# Retrieval API — mirrors knowledge_retrieval's shape
# ════════════════════════════════════════════════════════════════════

def resolve_operator(intent: str) -> Optional[str]:
    """Map free-text intent to a catalog key, or None if not grounded."""
    lower = intent.lower()
    # Longest alias first so 'grafana operator' wins over 'grafana'.
    for alias in sorted(OPERATOR_ALIASES, key=len, reverse=True):
        if alias in lower:
            return OPERATOR_ALIASES[alias]
    return None


def get_operator(key: str) -> Optional[Dict[str, Any]]:
    """Return the full grounded operator entry by catalog key."""
    return OPERATOR_CATALOG.get(key)


def extract_package_name(intent: str) -> Optional[str]:
    """Best-effort pull of an operator package name from free text for the fallback path.
    e.g. 'install the foo-bar operator' -> 'foo-bar'."""
    m = re.search(r'(?:install|deploy|add)\s+(?:the\s+)?([a-z0-9][a-z0-9-]+?)\s+operator', intent, re.I)
    if m:
        return m.group(1).lower()
    return None


def is_operator_request(intent: str) -> bool:
    """Heuristic: does this intent ask to install/configure an operator?"""
    lower = intent.lower()
    if "operator" in lower:
        return True
    return resolve_operator(intent) is not None


def build_operator_grounding(intent: str) -> Dict[str, Any]:
    """Return everything the generator needs to build a complete operator setup playbook.

    Shape:
      {
        grounded: bool,
        operator_key: str | None,
        operator: <catalog entry> | None,
        package_name: str | None,        # for fallback path
        install_sequence: INSTALL_SEQUENCE,
        config_questions: [...],         # questions to ask the user, if any
        grounding_text: str,             # human/model-readable grounding block
      }
    """
    key = resolve_operator(intent)
    if key:
        op = OPERATOR_CATALOG[key]
        return {
            "grounded": True,
            "operator_key": key,
            "operator": op,
            "package_name": op["package_name"],
            "install_sequence": INSTALL_SEQUENCE,
            "config_questions": op.get("config_questions", []),
            "grounding_text": _render_grounding(op),
        }
    # Not grounded — fallback path.
    pkg = extract_package_name(intent)
    return {
        "grounded": False,
        "operator_key": None,
        "operator": None,
        "package_name": pkg,
        "install_sequence": INSTALL_SEQUENCE,
        "config_questions": [],
        "grounding_text": (
            "VERIFIED OPERATOR INSTALL SEQUENCE (standard OLM):\n"
            f"{INSTALL_SEQUENCE['description']}\n\n"
            "This operator is not in ARNIE's grounded catalog. Lay down the standard "
            "install sequence with the user's package name, wait for the CSV to succeed, "
            "then inspect the live CRD to ground the Custom Resource.\n"
            f"{OPERATOR_FALLBACK['guidance']}"
        ),
    }


def _render_grounding(op: Dict[str, Any]) -> str:
    """Build the grounding text block injected into generation for a grounded operator."""
    lines: List[str] = []
    lines.append(f"VERIFIED OPERATOR: {op['display_name']}")
    lines.append(f"  package_name:  {op['package_name']}")
    lines.append(f"  channel:       {op['channel']}")
    lines.append(f"  catalogSource: {op['catalog_source']}")
    lines.append(f"  install mode:  {op['install_mode']}")
    lines.append(f"  install namespace (default): {op['default_install_namespace']}")
    lines.append("")
    lines.append("INSTALL SEQUENCE (in order): Namespace -> OperatorGroup -> Subscription -> wait for CSV Succeeded.")
    lines.append("")
    operand = op["operand"]
    lines.append(f"OPERAND (create only AFTER CSV succeeds): {operand['kind']} ({operand['api_version']})")
    lines.append(f"  purpose: {operand['purpose']}")
    lines.append("  verified CR template:")
    for ln in operand["cr_template"].splitlines():
        lines.append("    " + ln)
    if op.get("common_mistakes"):
        lines.append("")
        lines.append("COMMON MISTAKES TO AVOID:")
        for m in op["common_mistakes"]:
            lines.append(f"  - {m}")
    return "\n".join(lines)


# Convenience for the generator's question-asking flow.
def get_config_questions(intent: str) -> List[Dict[str, Any]]:
    """Return the plain-English config questions ARNIE should ask for this operator."""
    key = resolve_operator(intent)
    if key:
        return OPERATOR_CATALOG[key].get("config_questions", [])
    return []

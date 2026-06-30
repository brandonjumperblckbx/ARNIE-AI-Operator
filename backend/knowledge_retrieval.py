"""
ARNIE Knowledge Retrieval
Verified Ansible Automation Platform module knowledge base for grounded playbook generation.

This module solves the core accuracy problem: local models hallucinate Ansible module
syntax (wrong parameter names, wrong apiVersions, invalid module options). By injecting
VERIFIED module specifications and correct resource templates into the generation prompt,
ARNIE writes playbooks from ground truth instead of from the model's (often stale) memory.

Knowledge is sourced from the real kubernetes.core and redhat.openshift collection
DOCUMENTATION specs and Red Hat AAP best practices. Retrieval is resource-type-keyed
(deterministic, no embedding infra) which fits ARNIE's finite, known resource domain
and CPU-only inference profile.

Built on RMCP by BLCKBX.
"""

import re
import logging
from typing import Any, Dict, List, Optional, Set

log = logging.getLogger("arnie.knowledge")


# ════════════════════════════════════════════════════════════════════
# MODULE KNOWLEDGE BASE
# Verified parameter specs for the Ansible modules ARNIE generates with.
# Sourced from kubernetes.core and redhat.openshift collection docs.
# ════════════════════════════════════════════════════════════════════

MODULE_SPECS: Dict[str, Dict[str, Any]] = {
    "kubernetes.core.k8s": {
        "purpose": "Create, update, or delete Kubernetes/OpenShift objects from inline definitions or files.",
        "key_parameters": {
            "state": "present | absent | patched. 'present' creates/updates, 'absent' deletes. Default: present.",
            "definition": "Inline resource definition (a dict / YAML map). Preferred for ARNIE-generated resources.",
            "src": "Path to a file containing the resource definition. Mutually exclusive with 'definition'.",
            "namespace": "Target namespace. Required for namespaced resources, omit for cluster-scoped.",
            "api_version": "Only when using name/kind shorthand instead of definition. Usually set inside definition.",
            "kind": "Only when using name/kind shorthand. Usually set inside definition.",
            "name": "Resource name when using shorthand instead of full definition.",
            "merge_type": "List: ['strategic-merge', 'merge', 'json']. Controls patch strategy. Use for updates.",
            "wait": "Boolean. Wait for the resource to reach expected state. Default: false. Set true for ordered ops.",
            "wait_condition": "Dict with type/status/reason. e.g. {type: Available, status: 'True'} for Deployments.",
            "wait_timeout": "Seconds to wait when wait=true. Default: 120.",
            "apply": "Boolean. Use server-side apply (kubectl apply semantics). Good for idempotency.",
            "force": "Boolean. Replace the object (delete + recreate) rather than patch.",
            "validate_certs": "Boolean. Verify cluster TLS. Often false for self-signed clusters.",
        },
        "common_mistakes": [
            "Do NOT use 'resource_definition' — the correct parameter is 'definition'.",
            "Do NOT put 'state: present' inside the definition — it goes at the module task level.",
            "Do NOT use 'apiVersion'/'kind' as top-level module args when a full 'definition' is provided.",
            "Cluster-scoped resources (Namespace, ClusterRole) must NOT have a 'namespace' at module level.",
        ],
        "correct_example": (
            "    - name: Create namespace\n"
            "      kubernetes.core.k8s:\n"
            "        state: present\n"
            "        definition:\n"
            "          apiVersion: v1\n"
            "          kind: Namespace\n"
            "          metadata:\n"
            "            name: example\n"
            "            labels:\n"
            "              app.kubernetes.io/managed-by: arnie\n"
        ),
    },
    "kubernetes.core.k8s_info": {
        "purpose": "Read/query existing Kubernetes/OpenShift objects (does not modify state).",
        "key_parameters": {
            "kind": "Required. Resource kind to query, e.g. 'Pod', 'Deployment'.",
            "api_version": "API version of the resource. Default: v1.",
            "namespace": "Namespace to search. Omit for cluster-scoped or all-namespace queries.",
            "name": "Specific resource name. Omit to list all of that kind.",
            "label_selectors": "List of label selector strings, e.g. ['app=nginx'].",
            "field_selectors": "List of field selector strings, e.g. ['status.phase=Running'].",
            "wait": "Boolean. Wait for the resource to exist / match wait_condition.",
        },
        "common_mistakes": [
            "k8s_info is READ-ONLY — never give it 'state' or 'definition'.",
            "Use 'register' to capture results, then reference via the registered variable.",
        ],
        "correct_example": (
            "    - name: Check if namespace exists\n"
            "      kubernetes.core.k8s_info:\n"
            "        api_version: v1\n"
            "        kind: Namespace\n"
            "        name: example\n"
            "      register: ns_check\n"
        ),
    },
    "kubernetes.core.k8s_scale": {
        "purpose": "Scale a Deployment, StatefulSet, ReplicaSet, or ReplicationController.",
        "key_parameters": {
            "api_version": "e.g. apps/v1.",
            "kind": "Deployment | StatefulSet | ReplicaSet.",
            "name": "Name of the workload to scale.",
            "namespace": "Namespace of the workload.",
            "replicas": "Target replica count (integer).",
            "wait": "Boolean. Wait for the scale operation to complete.",
            "wait_timeout": "Seconds to wait. Default: 20.",
        },
        "common_mistakes": [
            "Use k8s_scale for replica changes, not a full k8s definition patch — it's purpose-built and idempotent.",
        ],
        "correct_example": (
            "    - name: Scale deployment\n"
            "      kubernetes.core.k8s_scale:\n"
            "        api_version: apps/v1\n"
            "        kind: Deployment\n"
            "        name: web\n"
            "        namespace: app\n"
            "        replicas: 3\n"
            "        wait: true\n"
        ),
    },
    "kubernetes.core.k8s_drain": {
        "purpose": "Cordon, drain, or uncordon a node for maintenance.",
        "key_parameters": {
            "name": "Node name.",
            "state": "drain | cordon | uncordon.",
            "delete_options": "Dict: terminate_grace_period, force, ignore_daemonsets, delete_emptydir_data.",
        },
        "common_mistakes": [
            "Set 'ignore_daemonsets: true' under delete_options or drain fails on DaemonSet-managed pods.",
        ],
        "correct_example": (
            "    - name: Drain node for maintenance\n"
            "      kubernetes.core.k8s_drain:\n"
            "        name: worker-1\n"
            "        state: drain\n"
            "        delete_options:\n"
            "          ignore_daemonsets: true\n"
            "          delete_emptydir_data: true\n"
            "          terminate_grace_period: 300\n"
        ),
    },
    "redhat.openshift.openshift_route": {
        "purpose": "Manage OpenShift Routes (the OpenShift-native way to expose Services).",
        "key_parameters": {
            "state": "present | absent.",
            "name": "Route name.",
            "namespace": "Route namespace.",
            "service": "Target Service name.",
            "port": "Target port (name or number).",
            "tls": "Dict: termination (edge|passthrough|reencrypt), insecureEdgeTerminationPolicy.",
        },
        "common_mistakes": [
            "A plain kubernetes.core.k8s with a Route definition also works and is more portable — prefer it unless openshift_route is required.",
        ],
        "correct_example": (
            "    - name: Create edge-terminated route\n"
            "      kubernetes.core.k8s:\n"
            "        state: present\n"
            "        definition:\n"
            "          apiVersion: route.openshift.io/v1\n"
            "          kind: Route\n"
            "          metadata:\n"
            "            name: web\n"
            "            namespace: app\n"
            "          spec:\n"
            "            to:\n"
            "              kind: Service\n"
            "              name: web\n"
            "            port:\n"
            "              targetPort: 8080\n"
            "            tls:\n"
            "              termination: edge\n"
        ),
    },
}


# ════════════════════════════════════════════════════════════════════
# RESOURCE TEMPLATES
# Verified, correct apiVersion + kind + minimal valid spec per resource type.
# These are the ground-truth shapes models most often get wrong.
# ════════════════════════════════════════════════════════════════════

RESOURCE_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "Namespace": {
        "api_version": "v1",
        "scope": "cluster",
        "notes": "Cluster-scoped — never set a namespace. Add labels for ARNIE management tracking.",
        "template": (
            "apiVersion: v1\n"
            "kind: Namespace\n"
            "metadata:\n"
            "  name: <name>\n"
            "  labels:\n"
            "    app.kubernetes.io/managed-by: arnie\n"
        ),
    },
    "ResourceQuota": {
        "api_version": "v1",
        "scope": "namespaced",
        "notes": "Quota keys use 'requests.cpu', 'requests.memory', 'limits.cpu', 'limits.memory', 'pods'.",
        "template": (
            "apiVersion: v1\n"
            "kind: ResourceQuota\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  hard:\n"
            "    requests.cpu: '4'\n"
            "    requests.memory: 8Gi\n"
            "    limits.cpu: '8'\n"
            "    limits.memory: 16Gi\n"
            "    pods: '20'\n"
        ),
    },
    "LimitRange": {
        "api_version": "v1",
        "scope": "namespaced",
        "notes": "type must be 'Container'. Use default (limits) and defaultRequest.",
        "template": (
            "apiVersion: v1\n"
            "kind: LimitRange\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  limits:\n"
            "    - type: Container\n"
            "      default:\n"
            "        cpu: 500m\n"
            "        memory: 512Mi\n"
            "      defaultRequest:\n"
            "        cpu: 250m\n"
            "        memory: 256Mi\n"
        ),
    },
    "Deployment": {
        "api_version": "apps/v1",
        "scope": "namespaced",
        "notes": "selector.matchLabels MUST match template.metadata.labels exactly or the API rejects it.",
        "template": (
            "apiVersion: apps/v1\n"
            "kind: Deployment\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  replicas: 3\n"
            "  selector:\n"
            "    matchLabels:\n"
            "      app: <name>\n"
            "  template:\n"
            "    metadata:\n"
            "      labels:\n"
            "        app: <name>\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: <name>\n"
            "          image: <image>\n"
            "          ports:\n"
            "            - containerPort: 8080\n"
        ),
    },
    "Service": {
        "api_version": "v1",
        "scope": "namespaced",
        "notes": "selector must match the target pods' labels. type defaults to ClusterIP.",
        "template": (
            "apiVersion: v1\n"
            "kind: Service\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  selector:\n"
            "    app: <name>\n"
            "  ports:\n"
            "    - port: 8080\n"
            "      targetPort: 8080\n"
            "  type: ClusterIP\n"
        ),
    },
    "Route": {
        "api_version": "route.openshift.io/v1",
        "scope": "namespaced",
        "notes": "OpenShift-only. tls.termination is edge|passthrough|reencrypt.",
        "template": (
            "apiVersion: route.openshift.io/v1\n"
            "kind: Route\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  to:\n"
            "    kind: Service\n"
            "    name: <name>\n"
            "  port:\n"
            "    targetPort: 8080\n"
            "  tls:\n"
            "    termination: edge\n"
        ),
    },
    "NetworkPolicy": {
        "api_version": "networking.k8s.io/v1",
        "scope": "namespaced",
        "notes": "policyTypes lists Ingress/Egress. Empty ingress/egress = deny-all for that direction.",
        "template": (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  podSelector: {}\n"
            "  policyTypes:\n"
            "    - Ingress\n"
            "  ingress:\n"
            "    - from:\n"
            "        - namespaceSelector:\n"
            "            matchLabels:\n"
            "              kubernetes.io/metadata.name: <source-namespace>\n"
        ),
    },
    "Role": {
        "api_version": "rbac.authorization.k8s.io/v1",
        "scope": "namespaced",
        "notes": "rules require apiGroups (use '' for core), resources, verbs.",
        "template": (
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: Role\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "rules:\n"
            "  - apiGroups: ['']\n"
            "    resources: ['pods', 'services']\n"
            "    verbs: ['get', 'list', 'watch']\n"
        ),
    },
    "ClusterRole": {
        "api_version": "rbac.authorization.k8s.io/v1",
        "scope": "cluster",
        "notes": "Cluster-scoped — no namespace. Avoid wildcard verbs/resources (least privilege).",
        "template": (
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: ClusterRole\n"
            "metadata:\n"
            "  name: <name>\n"
            "rules:\n"
            "  - apiGroups: ['']\n"
            "    resources: ['pods', 'services', 'configmaps']\n"
            "    verbs: ['get', 'list', 'watch']\n"
        ),
    },
    "RoleBinding": {
        "api_version": "rbac.authorization.k8s.io/v1",
        "scope": "namespaced",
        "notes": "roleRef.apiGroup is 'rbac.authorization.k8s.io'. subjects need kind/name/(namespace for SA).",
        "template": (
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: RoleBinding\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "roleRef:\n"
            "  apiGroup: rbac.authorization.k8s.io\n"
            "  kind: Role\n"
            "  name: <role-name>\n"
            "subjects:\n"
            "  - kind: ServiceAccount\n"
            "    name: <sa-name>\n"
            "    namespace: <namespace>\n"
        ),
    },
    "ClusterRoleBinding": {
        "api_version": "rbac.authorization.k8s.io/v1",
        "scope": "cluster",
        "notes": "Cluster-scoped. roleRef.kind is ClusterRole. Subjects can be users, groups, or SAs.",
        "template": (
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: ClusterRoleBinding\n"
            "metadata:\n"
            "  name: <name>\n"
            "roleRef:\n"
            "  apiGroup: rbac.authorization.k8s.io\n"
            "  kind: ClusterRole\n"
            "  name: <clusterrole-name>\n"
            "subjects:\n"
            "  - kind: Group\n"
            "    name: <group>\n"
            "    apiGroup: rbac.authorization.k8s.io\n"
        ),
    },
    "ServiceAccount": {
        "api_version": "v1",
        "scope": "namespaced",
        "notes": "Minimal object; permissions come from Role/ClusterRole bindings.",
        "template": (
            "apiVersion: v1\n"
            "kind: ServiceAccount\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
        ),
    },
    "ConfigMap": {
        "api_version": "v1",
        "scope": "namespaced",
        "notes": "data values must be strings. Use stringData semantics only for Secrets.",
        "template": (
            "apiVersion: v1\n"
            "kind: ConfigMap\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "data:\n"
            "  key: value\n"
        ),
    },
    "Secret": {
        "api_version": "v1",
        "scope": "namespaced",
        "notes": "Use 'stringData' for plaintext (auto-encoded). 'data' requires base64. type defaults to Opaque.",
        "template": (
            "apiVersion: v1\n"
            "kind: Secret\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "type: Opaque\n"
            "stringData:\n"
            "  username: <value>\n"
            "  password: <value>\n"
        ),
    },
    "PersistentVolumeClaim": {
        "api_version": "v1",
        "scope": "namespaced",
        "notes": "accessModes is a list. storageClassName optional (uses default if omitted).",
        "template": (
            "apiVersion: v1\n"
            "kind: PersistentVolumeClaim\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  accessModes:\n"
            "    - ReadWriteOnce\n"
            "  resources:\n"
            "    requests:\n"
            "      storage: 10Gi\n"
            "  storageClassName: <storage-class>\n"
        ),
    },
    "StatefulSet": {
        "api_version": "apps/v1",
        "scope": "namespaced",
        "notes": "Requires serviceName (headless Service). volumeClaimTemplates for per-pod storage.",
        "template": (
            "apiVersion: apps/v1\n"
            "kind: StatefulSet\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  serviceName: <name>\n"
            "  replicas: 3\n"
            "  selector:\n"
            "    matchLabels:\n"
            "      app: <name>\n"
            "  template:\n"
            "    metadata:\n"
            "      labels:\n"
            "        app: <name>\n"
            "    spec:\n"
            "      containers:\n"
            "        - name: <name>\n"
            "          image: <image>\n"
            "  volumeClaimTemplates:\n"
            "    - metadata:\n"
            "        name: data\n"
            "      spec:\n"
            "        accessModes: ['ReadWriteOnce']\n"
            "        resources:\n"
            "          requests:\n"
            "            storage: 10Gi\n"
        ),
    },
    "CronJob": {
        "api_version": "batch/v1",
        "scope": "namespaced",
        "notes": "schedule is cron syntax. jobTemplate.spec.template.spec.restartPolicy must be OnFailure or Never.",
        "template": (
            "apiVersion: batch/v1\n"
            "kind: CronJob\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  schedule: '0 2 * * *'\n"
            "  jobTemplate:\n"
            "    spec:\n"
            "      template:\n"
            "        spec:\n"
            "          restartPolicy: OnFailure\n"
            "          containers:\n"
            "            - name: <name>\n"
            "              image: <image>\n"
        ),
    },
    "HorizontalPodAutoscaler": {
        "api_version": "autoscaling/v2",
        "scope": "namespaced",
        "notes": "Use autoscaling/v2 (not v1). metrics is a list; scaleTargetRef points at the workload.",
        "template": (
            "apiVersion: autoscaling/v2\n"
            "kind: HorizontalPodAutoscaler\n"
            "metadata:\n"
            "  name: <name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  scaleTargetRef:\n"
            "    apiVersion: apps/v1\n"
            "    kind: Deployment\n"
            "    name: <target>\n"
            "  minReplicas: 2\n"
            "  maxReplicas: 10\n"
            "  metrics:\n"
            "    - type: Resource\n"
            "      resource:\n"
            "        name: cpu\n"
            "        target:\n"
            "          type: Utilization\n"
            "          averageUtilization: 70\n"
        ),
    },
    "SecurityContextConstraints": {
        "api_version": "security.openshift.io/v1",
        "scope": "cluster",
        "notes": "OpenShift-only, cluster-scoped. Prefer binding existing SCCs (anyuid, restricted) over new ones.",
        "template": (
            "apiVersion: security.openshift.io/v1\n"
            "kind: SecurityContextConstraints\n"
            "metadata:\n"
            "  name: <name>\n"
            "allowPrivilegedContainer: false\n"
            "runAsUser:\n"
            "  type: MustRunAsRange\n"
            "users:\n"
            "  - system:serviceaccount:<namespace>:<sa-name>\n"
        ),
    },
    "Subscription": {
        "api_version": "operators.coreos.com/v1alpha1",
        "scope": "namespaced",
        "notes": "OLM operator install. Needs channel, name (package), source, sourceNamespace (openshift-marketplace).",
        "template": (
            "apiVersion: operators.coreos.com/v1alpha1\n"
            "kind: Subscription\n"
            "metadata:\n"
            "  name: <operator-name>\n"
            "  namespace: <namespace>\n"
            "spec:\n"
            "  channel: stable\n"
            "  name: <operator-package-name>\n"
            "  source: redhat-operators\n"
            "  sourceNamespace: openshift-marketplace\n"
            "  installPlanApproval: Automatic\n"
        ),
    },
}


# ════════════════════════════════════════════════════════════════════
# GLOBAL BEST-PRACTICE GROUNDING
# Always-injected rules that apply to every ARNIE-generated playbook.
# ════════════════════════════════════════════════════════════════════

PLAYBOOK_GROUNDING = """VERIFIED ANSIBLE PLAYBOOK STRUCTURE (follow exactly):
- Every play: hosts: localhost, connection: local, gather_facts: false.
- Use the kubernetes.core.k8s module with a full 'definition:' block for create/update/delete.
- The parameter is 'definition' (NOT 'resource_definition'). 'state' goes at module level (present/absent).
- For reads use kubernetes.core.k8s_info (read-only, register the result).
- For replica changes use kubernetes.core.k8s_scale (purpose-built, idempotent).
- Cluster-scoped kinds (Namespace, ClusterRole, ClusterRoleBinding, SCC) must NOT carry a namespace.
- For ordered operations set wait: true with an appropriate wait_condition.
- Name every task descriptively. Use state: present for create/update, state: absent for delete.
- Output ONLY valid Ansible YAML — no markdown fences, no commentary.
"""

# Map detected resource-type strings (from inventory_resolver) → template keys.
# inventory_resolver returns canonical K8s kinds; we also catch lowercase intent words.
_KIND_ALIASES: Dict[str, str] = {
    "namespace": "Namespace",
    "resourcequota": "ResourceQuota",
    "quota": "ResourceQuota",
    "limitrange": "LimitRange",
    "deployment": "Deployment",
    "service": "Service",
    "route": "Route",
    "networkpolicy": "NetworkPolicy",
    "network policy": "NetworkPolicy",
    "role": "Role",
    "clusterrole": "ClusterRole",
    "rolebinding": "RoleBinding",
    "clusterrolebinding": "ClusterRoleBinding",
    "serviceaccount": "ServiceAccount",
    "service account": "ServiceAccount",
    "configmap": "ConfigMap",
    "config map": "ConfigMap",
    "secret": "Secret",
    "persistentvolumeclaim": "PersistentVolumeClaim",
    "pvc": "PersistentVolumeClaim",
    "persistent volume": "PersistentVolumeClaim",
    "statefulset": "StatefulSet",
    "cronjob": "CronJob",
    "hpa": "HorizontalPodAutoscaler",
    "horizontalpodautoscaler": "HorizontalPodAutoscaler",
    "autoscaler": "HorizontalPodAutoscaler",
    "scc": "SecurityContextConstraints",
    "securitycontextconstraints": "SecurityContextConstraints",
    "operator": "Subscription",
    "subscription": "Subscription",
}

# Which modules to surface for which resource templates.
_TEMPLATE_MODULES: Dict[str, List[str]] = {
    "_default": ["kubernetes.core.k8s"],
    "Deployment": ["kubernetes.core.k8s", "kubernetes.core.k8s_scale"],
    "StatefulSet": ["kubernetes.core.k8s", "kubernetes.core.k8s_scale"],
    "Route": ["kubernetes.core.k8s"],
}

# Intent verbs → extra module surfacing (drain, scale, query).
_INTENT_MODULE_HINTS: List[tuple] = [
    (("drain", "cordon", "uncordon", "maintenance"), "kubernetes.core.k8s_drain"),
    (("scale", "replicas", "scale up", "scale down"), "kubernetes.core.k8s_scale"),
    (("check", "verify", "list", "get", "query", "health"), "kubernetes.core.k8s_info"),
]


class KnowledgeRetriever:
    """Retrieves verified module specs and resource templates relevant to an intent,
    formatted as grounding text to prepend to the generation prompt."""

    def __init__(self, max_templates: int = 4, max_modules: int = 3):
        self.max_templates = max_templates
        self.max_modules = max_modules

    def retrieve(
        self,
        intent: str,
        resource_types: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Return relevant knowledge for a generation request.

        Args:
            intent: the natural-language request.
            resource_types: canonical kinds detected by inventory_resolver (optional —
                            we also scan the intent text directly as a fallback).
        Returns a dict with 'grounding' (the prompt-ready text) and the raw matches.
        """
        lower = intent.lower()

        # 1. Resolve which resource templates are relevant.
        template_keys = self._resolve_templates(lower, resource_types)

        # 2. Resolve which modules to surface.
        module_keys = self._resolve_modules(lower, template_keys)

        # 3. Build grounding text.
        grounding = self._build_grounding(template_keys, module_keys)

        return {
            "grounding": grounding,
            "templates": template_keys,
            "modules": module_keys,
            "matched": bool(template_keys or module_keys),
        }

    def _resolve_templates(self, lower: str, resource_types: Optional[List[str]]) -> List[str]:
        keys: List[str] = []
        seen: Set[str] = set()

        # From inventory_resolver's detected kinds (already canonical).
        for rt in (resource_types or []):
            canon = _KIND_ALIASES.get(rt.lower(), rt if rt in RESOURCE_TEMPLATES else None)
            if canon and canon in RESOURCE_TEMPLATES and canon not in seen:
                seen.add(canon)
                keys.append(canon)

        # Fallback / supplement: scan intent text for alias keywords.
        # Longer aliases first so "network policy" wins over "policy".
        for alias in sorted(_KIND_ALIASES.keys(), key=len, reverse=True):
            if alias in lower:
                canon = _KIND_ALIASES[alias]
                if canon in RESOURCE_TEMPLATES and canon not in seen:
                    seen.add(canon)
                    keys.append(canon)
            if len(keys) >= self.max_templates:
                break

        return keys[: self.max_templates]

    def _resolve_modules(self, lower: str, template_keys: List[str]) -> List[str]:
        keys: List[str] = []
        seen: Set[str] = set()

        # Modules implied by the resource templates.
        for tk in template_keys:
            for mod in _TEMPLATE_MODULES.get(tk, _TEMPLATE_MODULES["_default"]):
                if mod not in seen:
                    seen.add(mod)
                    keys.append(mod)

        # Modules implied by intent verbs.
        for verbs, mod in _INTENT_MODULE_HINTS:
            if any(v in lower for v in verbs) and mod not in seen:
                seen.add(mod)
                keys.append(mod)

        # Always ensure the core module is present.
        if "kubernetes.core.k8s" not in seen:
            keys.insert(0, "kubernetes.core.k8s")
            seen.add("kubernetes.core.k8s")

        return keys[: self.max_modules]

    def _build_grounding(self, template_keys: List[str], module_keys: List[str]) -> str:
        parts: List[str] = [PLAYBOOK_GROUNDING]

        if module_keys:
            parts.append("\nVERIFIED MODULE REFERENCE:")
            for mk in module_keys:
                spec = MODULE_SPECS.get(mk)
                if not spec:
                    continue
                parts.append(f"\n• {mk} — {spec['purpose']}")
                params = spec.get("key_parameters", {})
                if params:
                    param_lines = "; ".join(f"{k}: {v.split('.')[0]}" for k, v in list(params.items())[:6])
                    parts.append(f"  Key params: {param_lines}")
                for mistake in spec.get("common_mistakes", [])[:3]:
                    parts.append(f"  ⚠ {mistake}")
                if spec.get("correct_example"):
                    parts.append("  Correct usage:\n" + spec["correct_example"])

        if template_keys:
            parts.append("\nVERIFIED RESOURCE TEMPLATES (use these exact apiVersion/kind/shapes):")
            for tk in template_keys:
                tpl = RESOURCE_TEMPLATES.get(tk)
                if not tpl:
                    continue
                parts.append(f"\n• {tk} (apiVersion: {tpl['api_version']}, scope: {tpl['scope']})")
                parts.append(f"  Note: {tpl['notes']}")
                parts.append("  Shape:\n" + _indent(tpl["template"], 4))

        return "\n".join(parts)


def _indent(text: str, spaces: int) -> str:
    pad = " " * spaces
    return "\n".join(pad + line if line else line for line in text.splitlines())


# Module-level singleton for easy import.
_retriever: Optional[KnowledgeRetriever] = None


def get_retriever() -> KnowledgeRetriever:
    global _retriever
    if _retriever is None:
        _retriever = KnowledgeRetriever()
    return _retriever


def retrieve_knowledge(intent: str, resource_types: Optional[List[str]] = None) -> str:
    """Convenience function — returns just the grounding text for prompt injection."""
    return get_retriever().retrieve(intent, resource_types)["grounding"]


def resolve_templates(intent: str, resource_types: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Return the resolved RESOURCE_TEMPLATES entries (with their canonical key) for an intent.

    Used by the playbook assembler fallback to build a correct playbook from verified
    templates when the model is unreachable. Each item: {key, api_version, scope, notes, template}.
    """
    result = get_retriever().retrieve(intent, resource_types)
    out: List[Dict[str, Any]] = []
    for key in result["templates"]:
        tpl = RESOURCE_TEMPLATES.get(key)
        if tpl:
            out.append({"key": key, **tpl})
    return out


def get_template(kind: str) -> Optional[Dict[str, Any]]:
    """Return a single resource template by canonical kind, or None."""
    tpl = RESOURCE_TEMPLATES.get(kind)
    if tpl:
        return {"key": kind, **tpl}
    return None

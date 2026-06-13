"""
ARNIE Inventory Resolver
Detects the target inventory and execution context from natural language intent.
Maps infrastructure requests to AAP inventories, namespaces, and host groups.
"""

import re
import logging
from typing import Any, Dict, Optional

log = logging.getLogger("arnie.inventory-resolver")

# ── Known inventory patterns ──
NAMESPACE_PATTERNS = [
    r'\b(?:in|on|for|to)\s+(?:the\s+)?(?:namespace\s+)?["\']?(\w[\w-]*)["\']?\s+namespace\b',
    r'\bnamespace\s+["\']?(\w[\w-]*)["\']?\b',
    r'\b(?:in|on)\s+(?:the\s+)?(\w[\w-]*)\s+(?:environment|env|cluster)\b',
    r'\b-n\s+(\w[\w-]*)\b',
]

ENVIRONMENT_MAP = {
    "prod": "production",
    "production": "production",
    "staging": "staging",
    "stage": "staging",
    "dev": "development",
    "development": "development",
    "test": "testing",
    "testing": "testing",
    "qa": "qa",
    "uat": "uat",
    "infra": "infrastructure",
    "monitoring": "monitoring",
    "logging": "logging",
}


class InventoryResolver:
    """Resolves target inventory and execution context from intent."""

    def resolve(
        self,
        intent: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Resolve the target inventory for a playbook."""
        ctx = context or {}
        lower = intent.lower()

        # Extract namespace
        namespace = ctx.get("namespace") or ctx.get("target_namespace")
        if not namespace:
            namespace = self._extract_namespace(intent)

        # Detect environment
        environment = self._detect_environment(lower)

        # Detect if cluster-scoped
        cluster_scoped = self._is_cluster_scoped(lower)

        # Detect target resource types
        resource_types = self._detect_resource_types(lower)

        # Determine inventory type
        inventory_type = "localhost"  # k8s module runs locally
        if any(kw in lower for kw in ("ssh", "ansible.builtin.shell", "remote host")):
            inventory_type = "host_group"

        return {
            "inventory": inventory_type,
            "namespace": namespace or "default",
            "environment": environment,
            "cluster_scoped": cluster_scoped,
            "resource_types": resource_types,
            "connection": "local" if inventory_type == "localhost" else "ssh",
        }

    def _extract_namespace(self, intent: str) -> Optional[str]:
        for pattern in NAMESPACE_PATTERNS:
            match = re.search(pattern, intent, re.IGNORECASE)
            if match:
                ns = match.group(1).strip()
                if ns.lower() not in ("the", "a", "an", "this", "that", "my"):
                    return ns
        return None

    def _detect_environment(self, lower: str) -> Optional[str]:
        for key, env in ENVIRONMENT_MAP.items():
            if re.search(rf'\b{key}\b', lower):
                return env
        return None

    def _is_cluster_scoped(self, lower: str) -> bool:
        cluster_keywords = [
            "clusterrole", "clusterrolebinding", "namespace", "node",
            "persistentvolume", "storageclass", "cluster-wide",
            "all namespaces", "cluster scoped",
        ]
        return any(kw in lower for kw in cluster_keywords)

    def _detect_resource_types(self, lower: str) -> list:
        resource_map = {
            "deployment": "Deployment",
            "statefulset": "StatefulSet",
            "daemonset": "DaemonSet",
            "service": "Service",
            "ingress": "Ingress",
            "route": "Route",
            "networkpolicy": "NetworkPolicy",
            "network policy": "NetworkPolicy",
            "configmap": "ConfigMap",
            "config map": "ConfigMap",
            "secret": "Secret",
            "namespace": "Namespace",
            "role": "Role",
            "rolebinding": "RoleBinding",
            "clusterrole": "ClusterRole",
            "serviceaccount": "ServiceAccount",
            "service account": "ServiceAccount",
            "pvc": "PersistentVolumeClaim",
            "persistent volume": "PersistentVolumeClaim",
            "cronjob": "CronJob",
            "job": "Job",
            "pod": "Pod",
            "hpa": "HorizontalPodAutoscaler",
        }
        found = []
        for keyword, resource_type in resource_map.items():
            if keyword in lower and resource_type not in found:
                found.append(resource_type)
        return found

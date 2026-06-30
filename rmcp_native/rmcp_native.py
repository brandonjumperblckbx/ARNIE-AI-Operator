"""
RMCP Native — Python binding.

Loads the compiled C++ core (librmcp_native.so) and exposes the policy engine and
cluster watch engine to ARNIE's FastAPI backend with a clean Python interface.

Python orchestrates; the C++ core decides (policy) and observes (watch). This module
is the bridge: it marshals Python dicts to/from the C ABI as JSON, holds the engine
handles, and frees native strings correctly.

If the shared library isn't present (e.g. it hasn't been built on this host), import
still succeeds but `NATIVE_AVAILABLE` is False and a pure-Python fallback verdict is
returned, so the backend degrades gracefully rather than crashing.

Build the library first:
    cd rmcp_native && ./build_so.sh      # produces librmcp_native.so

Built on the RMCP engine by BLCKBX.
"""

import os
import json
import ctypes
import logging
from typing import Any, Dict, List, Optional

log = logging.getLogger("arnie.rmcp-native")

_LIB_NAME = "librmcp_native.so"
# Look next to this file first, then a couple of sensible fallbacks.
_SEARCH = [
    os.path.join(os.path.dirname(os.path.abspath(__file__)), _LIB_NAME),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "rmcp_native", _LIB_NAME),
    os.path.join(os.getcwd(), "rmcp_native", _LIB_NAME),
]

_lib = None
for _path in _SEARCH:
    if os.path.exists(_path):
        try:
            _lib = ctypes.CDLL(_path)
            break
        except OSError as e:
            log.warning("Found %s but failed to load: %s", _path, e)

NATIVE_AVAILABLE = _lib is not None

if NATIVE_AVAILABLE:
    # ── declare signatures ──
    _lib.rmcp_policy_create.restype = ctypes.c_void_p
    _lib.rmcp_policy_destroy.argtypes = [ctypes.c_void_p]
    _lib.rmcp_watch_create.restype = ctypes.c_void_p
    _lib.rmcp_watch_destroy.argtypes = [ctypes.c_void_p]
    _lib.rmcp_free_string.argtypes = [ctypes.c_void_p]

    _lib.rmcp_watch_apply.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _lib.rmcp_watch_snapshot.argtypes = [ctypes.c_void_p]
    _lib.rmcp_watch_snapshot.restype = ctypes.c_void_p
    _lib.rmcp_watch_namespace_exists.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _lib.rmcp_watch_namespace_exists.restype = ctypes.c_int
    _lib.rmcp_watch_operator_installed.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    _lib.rmcp_watch_operator_installed.restype = ctypes.c_int
    _lib.rmcp_watch_size.argtypes = [ctypes.c_void_p]
    _lib.rmcp_watch_size.restype = ctypes.c_int

    _lib.rmcp_policy_evaluate.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                          ctypes.c_char_p, ctypes.c_char_p]
    _lib.rmcp_policy_evaluate.restype = ctypes.c_void_p
    _lib.rmcp_policy_rule_count.argtypes = [ctypes.c_void_p]
    _lib.rmcp_policy_rule_count.restype = ctypes.c_int


def _take_string(ptr) -> str:
    """Copy a char* returned by the library into a Python str, then free it."""
    if not ptr:
        return ""
    s = ctypes.cast(ptr, ctypes.c_char_p).value
    out = s.decode("utf-8") if s else ""
    _lib.rmcp_free_string(ptr)
    return out


class RMCPNative:
    """Pythonic wrapper over the native policy + watch engines.

    Holds both engine handles for the life of the process. Thread-safety of the
    watch engine is handled in C++; this wrapper is a thin marshaller.
    """

    def __init__(self, protected_namespaces: Optional[List[str]] = None):
        self.protected_namespaces = protected_namespaces or [
            "default", "kube-system", "openshift-operators",
            "openshift-marketplace", "openshift-monitoring",
        ]
        self._policy = None
        self._watch = None
        if NATIVE_AVAILABLE:
            self._policy = _lib.rmcp_policy_create()
            self._watch = _lib.rmcp_watch_create()
            log.info("RMCP native core loaded (%d baseline rules).", self.rule_count())
        else:
            log.warning("RMCP native core not available; using Python fallback.")

    @property
    def available(self) -> bool:
        return NATIVE_AVAILABLE and self._policy is not None

    def rule_count(self) -> int:
        if not self.available:
            return 0
        return _lib.rmcp_policy_rule_count(self._policy)

    # ── watch engine ──

    def apply_event(self, event: Dict[str, Any]) -> None:
        """Feed one observed cluster event into the live model."""
        if not self.available:
            return
        _lib.rmcp_watch_apply(self._watch, json.dumps(event).encode("utf-8"))

    def prime(self, events: List[Dict[str, Any]]) -> None:
        for e in events:
            e = dict(e)
            e["type"] = "added"
            self.apply_event(e)

    def snapshot(self) -> Dict[str, Any]:
        if not self.available:
            return {"total_resources": 0, "namespaces": [], "operators": [],
                    "pods_running": 0, "pods_not_running": 0, "native": False}
        out = json.loads(_take_string(_lib.rmcp_watch_snapshot(self._watch)) or "{}")
        out["native"] = True
        return out

    def namespace_exists(self, ns: str) -> bool:
        if not self.available:
            return False
        return bool(_lib.rmcp_watch_namespace_exists(self._watch, ns.encode("utf-8")))

    def operator_installed(self, fragment: str) -> bool:
        if not self.available:
            return False
        return bool(_lib.rmcp_watch_operator_installed(self._watch, fragment.encode("utf-8")))

    def watch_size(self) -> int:
        if not self.available:
            return 0
        return _lib.rmcp_watch_size(self._watch)

    # ── policy core ──

    def evaluate(self, change: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate a proposed change against the live cluster facts.

        change: {action, kind, api_version, name, ns, requested_by, attrs:{...}}
        Returns: {decision: 'allow'|'require_approval'|'deny', summary, findings:[...]}
        """
        if not self.available:
            return self._fallback_verdict(change)
        # Ensure attrs is a flat string map.
        c = dict(change)
        attrs = c.get("attrs", {}) or {}
        c["attrs"] = {str(k): str(v) for k, v in attrs.items()}
        result = _take_string(_lib.rmcp_policy_evaluate(
            self._policy, self._watch,
            json.dumps(c).encode("utf-8"),
            json.dumps(self.protected_namespaces).encode("utf-8"),
        ))
        return json.loads(result or "{}")

    def _fallback_verdict(self, change: Dict[str, Any]) -> Dict[str, Any]:
        """Conservative pure-Python verdict if the native lib isn't built: deny the
        known-dangerous cases, require approval for everything else mutating."""
        action = change.get("action", "")
        kind = (change.get("kind") or "").lower()
        ns = change.get("ns", "")
        if action == "delete" and kind == "persistentvolumeclaim":
            return {"decision": "deny", "summary": "deny: PVC deletion (data-loss risk).",
                    "findings": [], "native": False}
        if action == "delete" and ns in self.protected_namespaces:
            return {"decision": "deny", "summary": f"deny: protected namespace '{ns}'.",
                    "findings": [], "native": False}
        if action in ("create", "update", "delete"):
            return {"decision": "require_approval",
                    "summary": "require_approval: cluster-mutating action.",
                    "findings": [], "native": False}
        return {"decision": "allow", "summary": "allow", "findings": [], "native": False}

    def __del__(self):
        try:
            if self.available:
                _lib.rmcp_policy_destroy(self._policy)
                _lib.rmcp_watch_destroy(self._watch)
        except Exception:
            pass


# A process-wide singleton the backend can import and share.
_engine: Optional[RMCPNative] = None


def get_engine() -> RMCPNative:
    global _engine
    if _engine is None:
        _engine = RMCPNative()
    return _engine

//! RMCP Policy FFI — Rust binding to the native C++ policy core.
//!
//! The reconciliation engine detects drift and proposes corrections. Before any
//! correction is applied, it must pass through the RMCP policy core for a verdict
//! (allow / require_approval / deny) — the same governed decision the rest of ARNIE
//! uses. This module is the bridge: it links against librmcp_native.so (the C ABI we
//! built for the Python binding) and exposes a safe Rust interface.
//!
//! Decide-then-reconcile: the Rust engine never auto-applies a correction the C++
//! policy core would forbid. A `Deny` blocks the correction; `RequireApproval` routes
//! it to the human gate; only `Allow` proceeds automatically.
//!
//! Built on the RMCP engine by BLCKBX.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

// ── extern declarations matching rmcp_capi.cpp ──
extern "C" {
    fn rmcp_policy_create() -> *mut c_void;
    fn rmcp_policy_destroy(h: *mut c_void);
    fn rmcp_watch_create() -> *mut c_void;
    fn rmcp_watch_destroy(h: *mut c_void);
    fn rmcp_free_string(s: *mut c_char);
    fn rmcp_policy_evaluate(
        policy_h: *mut c_void,
        watch_h: *mut c_void,
        change_json: *const c_char,
        protected_json: *const c_char,
    ) -> *mut c_char;
    fn rmcp_policy_rule_count(h: *mut c_void) -> i32;
}

/// The policy decision returned by the native core.
#[derive(Debug, Clone, PartialEq)]
pub enum Decision {
    Allow,
    RequireApproval,
    Deny,
    Unknown,
}

impl Decision {
    fn from_str(s: &str) -> Self {
        match s {
            "allow" => Decision::Allow,
            "require_approval" => Decision::RequireApproval,
            "deny" => Decision::Deny,
            _ => Decision::Unknown,
        }
    }
}

/// A verdict from the policy core.
#[derive(Debug, Clone)]
pub struct Verdict {
    pub decision: Decision,
    pub summary: String,
    pub raw_json: String,
}

/// A proposed change to evaluate (a drift correction, typically).
#[derive(Debug, Clone, Default)]
pub struct Change {
    pub action: String,       // "create" | "update" | "delete"
    pub kind: String,
    pub api_version: String,
    pub name: String,
    pub ns: String,
    pub requested_by: String,
}

impl Change {
    fn to_json(&self) -> String {
        // Minimal hand-built JSON (no serde dependency needed here).
        format!(
            "{{\"action\":\"{}\",\"kind\":\"{}\",\"api_version\":\"{}\",\"name\":\"{}\",\"ns\":\"{}\",\"requested_by\":\"{}\",\"attrs\":{{}}}}",
            esc(&self.action), esc(&self.kind), esc(&self.api_version),
            esc(&self.name), esc(&self.ns), esc(&self.requested_by)
        )
    }
}

fn esc(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Safe RAII wrapper over the native policy + watch handles.
pub struct PolicyCore {
    policy: *mut c_void,
    watch: *mut c_void,
    protected_namespaces: Vec<String>,
}

impl PolicyCore {
    /// Create a policy core with the baseline rule set. Returns None if the native
    /// library failed to provide a handle.
    pub fn new(protected_namespaces: Vec<String>) -> Option<Self> {
        let policy = unsafe { rmcp_policy_create() };
        let watch = unsafe { rmcp_watch_create() };
        if policy.is_null() || watch.is_null() {
            return None;
        }
        Some(Self { policy, watch, protected_namespaces })
    }

    pub fn rule_count(&self) -> i32 {
        unsafe { rmcp_policy_rule_count(self.policy) }
    }

    /// Evaluate a proposed change. Deterministic; safe to call from the reconciliation
    /// loop before applying a correction.
    pub fn evaluate(&self, change: &Change) -> Verdict {
        let change_json = CString::new(change.to_json()).unwrap();
        let prot = format!(
            "[{}]",
            self.protected_namespaces
                .iter()
                .map(|n| format!("\"{}\"", esc(n)))
                .collect::<Vec<_>>()
                .join(",")
        );
        let prot_json = CString::new(prot).unwrap();

        let raw = unsafe {
            rmcp_policy_evaluate(
                self.policy,
                self.watch,
                change_json.as_ptr(),
                prot_json.as_ptr(),
            )
        };
        if raw.is_null() {
            return Verdict {
                decision: Decision::Unknown,
                summary: "native evaluation returned null".into(),
                raw_json: String::new(),
            };
        }
        let json = unsafe { CStr::from_ptr(raw) }.to_string_lossy().into_owned();
        unsafe { rmcp_free_string(raw) };

        // Extract the decision + summary without a full JSON parser.
        let decision = extract_field(&json, "decision")
            .map(|d| Decision::from_str(&d))
            .unwrap_or(Decision::Unknown);
        let summary = extract_field(&json, "summary").unwrap_or_default();
        Verdict { decision, summary, raw_json: json }
    }
}

impl Drop for PolicyCore {
    fn drop(&mut self) {
        unsafe {
            rmcp_policy_destroy(self.policy);
            rmcp_watch_destroy(self.watch);
        }
    }
}

// Tiny field extractor for {"key":"value"} — enough for decision/summary.
fn extract_field(json: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    let start = json.find(&pat)? + pat.len();
    let rest = &json[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pvc_delete_is_denied() {
        // Requires librmcp_native.so on the linker path.
        if let Some(core) = PolicyCore::new(vec!["default".into(), "kube-system".into()]) {
            let c = Change {
                action: "delete".into(),
                kind: "PersistentVolumeClaim".into(),
                ns: "elastic-system".into(),
                ..Default::default()
            };
            let v = core.evaluate(&c);
            assert_eq!(v.decision, Decision::Deny);
        }
    }
}

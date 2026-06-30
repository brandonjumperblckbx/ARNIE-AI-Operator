// ============================================================================
//  RMCP Policy Core — implementation.
//  Built on the RMCP engine by BLCKBX.
// ============================================================================
#include "rmcp_policy_core.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

namespace rmcp {

const char* to_string(Decision d) {
    switch (d) {
        case Decision::Allow:           return "allow";
        case Decision::RequireApproval: return "require_approval";
        case Decision::Deny:            return "deny";
    }
    return "unknown";
}

// ── small helpers ──
static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

const std::string& Change::attr(const std::string& key, const std::string& dflt) const {
    auto it = attrs.find(key);
    return it == attrs.end() ? dflt : it->second;
}

bool Change::has_attr(const std::string& key) const {
    return attrs.find(key) != attrs.end();
}

bool ClusterFacts::namespace_exists(const std::string& ns) const {
    auto it = namespaces.find(ns);
    return it != namespaces.end() && it->second;
}

bool ClusterFacts::is_protected(const std::string& ns) const {
    return std::any_of(protected_namespaces.begin(), protected_namespaces.end(),
                       [&](const std::string& p) { return p == ns; });
}

bool ClusterFacts::operator_installed(const std::string& frag) const {
    std::string f = lower(frag);
    return std::any_of(installed_operators.begin(), installed_operators.end(),
                       [&](const std::string& op) { return lower(op).find(f) != std::string::npos; });
}

// ── Verdict summary ──
std::string Verdict::summary() const {
    // Surface the strongest finding (highest severity among the governing decision).
    const Finding* strongest = nullptr;
    for (const auto& f : findings) {
        if (f.decision == decision) {
            if (!strongest || f.severity > strongest->severity) strongest = &f;
        }
    }
    std::ostringstream os;
    os << to_string(decision);
    if (strongest) os << ": " << strongest->message;
    return os.str();
}

// ── Engine ──
PolicyEngine::PolicyEngine() {}

void PolicyEngine::add_rule(Rule rule) {
    rules_.push_back(std::move(rule));
}

Verdict PolicyEngine::evaluate(const Change& change, const ClusterFacts& facts) const {
    Verdict v;
    bool any_deny = false;
    bool any_escalate = false;

    for (const auto& rule : rules_) {
        RuleResult r = rule.fn(change, facts);
        if (!r.applies) continue;
        v.findings.push_back(r.finding);
        if (r.finding.decision == Decision::Deny) any_deny = true;
        else if (r.finding.decision == Decision::RequireApproval) any_escalate = true;
    }

    // Deny-overrides: deny beats escalate beats allow. The safe default for security.
    if (any_deny)            v.decision = Decision::Deny;
    else if (any_escalate)   v.decision = Decision::RequireApproval;
    else                     v.decision = Decision::Allow;

    return v;
}

// ── Baseline RMCP rule set ──
// These encode the hard guardrails ARNIE must always enforce. Each is a pure
// predicate over (Change, ClusterFacts).
void PolicyEngine::load_baseline_rules() {

    // R1: Never destructively act on a protected namespace.
    add_rule(Rule{
        "RMCP-001-protected-namespace",
        "Deny destructive actions against protected namespaces.",
        [](const Change& c, const ClusterFacts& f) -> RuleResult {
            if (c.action == "delete" && f.is_protected(c.ns)) {
                return {true, Finding{"RMCP-001-protected-namespace", Decision::Deny,
                    "Refusing to delete resources in protected namespace '" + c.ns + "'.", 4}};
            }
            return {false, {}};
        }
    });

    // R2: Deleting a PersistentVolumeClaim is destructive to data — deny outright.
    // (ARNIE has a hard rule: never delete PVCs.)
    add_rule(Rule{
        "RMCP-002-no-pvc-delete",
        "Deny deletion of PersistentVolumeClaims (data-loss risk).",
        [](const Change& c, const ClusterFacts&) -> RuleResult {
            if (c.action == "delete" && lower(c.kind) == "persistentvolumeclaim") {
                return {true, Finding{"RMCP-002-no-pvc-delete", Decision::Deny,
                    "Refusing to delete a PersistentVolumeClaim — data loss risk.", 4}};
            }
            return {false, {}};
        }
    });

    // R3: Privileged / host-level resources require human approval (escalate).
    add_rule(Rule{
        "RMCP-003-privileged-escalation",
        "Escalate changes that request privileged or host-level access.",
        [](const Change& c, const ClusterFacts&) -> RuleResult {
            bool priv = c.attr("privileged", "") == "true"
                     || c.attr("hostNetwork", "") == "true"
                     || c.attr("hostPID", "") == "true"
                     || c.has_attr("hostPath");
            if (priv) {
                return {true, Finding{"RMCP-003-privileged-escalation", Decision::RequireApproval,
                    "Change requests privileged/host-level access; human approval required.", 3}};
            }
            return {false, {}};
        }
    });

    // R4: Cluster-admin RBAC grants require approval.
    add_rule(Rule{
        "RMCP-004-cluster-admin-rbac",
        "Escalate changes that bind cluster-admin.",
        [](const Change& c, const ClusterFacts&) -> RuleResult {
            if (lower(c.attr("roleRef", "")).find("cluster-admin") != std::string::npos) {
                return {true, Finding{"RMCP-004-cluster-admin-rbac", Decision::RequireApproval,
                    "Change binds cluster-admin; human approval required.", 3}};
            }
            return {false, {}};
        }
    });

    // R5: Creating into a non-existent namespace is fine ONLY if the change also
    // creates it; otherwise escalate (likely a mistake / drift).
    add_rule(Rule{
        "RMCP-005-namespace-exists",
        "Escalate creates targeting a namespace that doesn't exist and isn't being created.",
        [](const Change& c, const ClusterFacts& f) -> RuleResult {
            if (c.action == "create" && !c.ns.empty()
                && lower(c.kind) != "namespace"
                && !f.namespace_exists(c.ns)) {
                return {true, Finding{"RMCP-005-namespace-exists", Decision::RequireApproval,
                    "Target namespace '" + c.ns + "' does not exist; confirm it will be created first.", 2}};
            }
            return {false, {}};
        }
    });

    // R6: All operator/CR installs are state-changing but additive — they always
    // require approval (never silently allowed). This is the governance backbone.
    add_rule(Rule{
        "RMCP-006-mutation-requires-approval",
        "Any create/update/delete requires human approval by default (governed action).",
        [](const Change& c, const ClusterFacts&) -> RuleResult {
            if (c.action == "create" || c.action == "update" || c.action == "delete") {
                return {true, Finding{"RMCP-006-mutation-requires-approval", Decision::RequireApproval,
                    "Cluster-mutating action requires human approval.", 1}};
            }
            return {false, {}};
        }
    });
}

}  // namespace rmcp

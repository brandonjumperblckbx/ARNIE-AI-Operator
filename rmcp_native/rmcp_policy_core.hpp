// ============================================================================
//  RMCP Policy Core — the decision engine at the heart of ARNIE.
//
//  Recursive Model Control Protocol (RMCP) policy evaluation, in C++ for speed
//  and determinism. The Python layer orchestrates; THIS evaluates. Given a
//  proposed change (a resource ARNIE wants to apply) and the live cluster state,
//  the policy core decides — fast, deterministically — whether the change is
//  allowed, denied, or requires elevated approval, and why.
//
//  Why C++: policy evaluation is on the critical path of every governed action.
//  It must be fast (thousands of rules in microseconds), deterministic (the same
//  inputs always yield the same verdict — essential for an audit trail), and
//  memory-safe in the sense of no surprises. C++ gives tight, predictable control.
//
//  Design: rules are pure predicates over a (Change, ClusterState) pair. The
//  engine evaluates all applicable rules and combines their verdicts using a
//  deny-overrides strategy (the safe default for security): if any rule denies,
//  the change is denied; escalations require approval; otherwise allowed.
//
//  Built on the RMCP engine by BLCKBX.
// ============================================================================
#ifndef RMCP_POLICY_CORE_HPP
#define RMCP_POLICY_CORE_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>

namespace rmcp {

// ── Verdict: the outcome of evaluating a change against policy ──
enum class Decision {
    Allow,        // no policy objects; safe to proceed
    RequireApproval,  // permitted, but a human must approve (the governance gate)
    Deny          // a policy forbids this; must not proceed
};

const char* to_string(Decision d);

// A single rule's finding, carried into the audit trail.
struct Finding {
    std::string rule_id;
    Decision decision;
    std::string message;   // human-readable reason (for the audit log + UI)
    int severity;          // 0=info .. 4=critical
};

// The aggregate result of a full policy evaluation.
struct Verdict {
    Decision decision = Decision::Allow;
    std::vector<Finding> findings;     // every rule that had something to say
    // Convenience: the strongest reason, for a one-line summary.
    std::string summary() const;
};

// ── A proposed change ARNIE wants to apply ──
// Kept deliberately simple/flat: the Python layer flattens a k8s resource into
// these fields before handing it across. Arbitrary attributes live in `attrs`.
struct Change {
    std::string action;        // "create" | "update" | "delete"
    std::string kind;          // e.g. "NetworkPolicy", "Grafana", "Namespace"
    std::string api_version;   // e.g. "v1", "grafana.integreatly.org/v1beta1"
    std::string name;
    std::string ns;            // namespace ("" for cluster-scoped)
    std::string requested_by;  // actor identity
    std::unordered_map<std::string, std::string> attrs;  // flattened spec fields

    // Helper: read an attr with a default.
    const std::string& attr(const std::string& key, const std::string& dflt) const;
    bool has_attr(const std::string& key) const;
};

// ── A snapshot of relevant cluster state (fed by the watch engine) ──
// The policy core does not query the cluster itself; it is handed the state it
// needs. This keeps it pure and deterministic (and trivially testable).
struct ClusterFacts {
    // namespace -> does it exist
    std::unordered_map<std::string, bool> namespaces;
    // set of installed operator CSV names (lowercased)
    std::vector<std::string> installed_operators;
    // protected namespaces that changes must never touch destructively
    std::vector<std::string> protected_namespaces;
    // existing resource identities ("kind/ns/name") for idempotency checks
    std::vector<std::string> existing_resources;

    bool namespace_exists(const std::string& ns) const;
    bool is_protected(const std::string& ns) const;
    bool operator_installed(const std::string& name_fragment) const;
};

// A rule: a pure predicate. Returns a Finding if it has an opinion, or nullopt-ish
// via the `applies` flag. We use a small struct return to stay allocation-light.
struct RuleResult {
    bool applies = false;
    Finding finding;
};

using RuleFn = std::function<RuleResult(const Change&, const ClusterFacts&)>;

struct Rule {
    std::string id;
    std::string description;
    RuleFn fn;
};

// ── The engine ──
class PolicyEngine {
public:
    PolicyEngine();

    // Register a rule. Rules are evaluated in registration order, but the final
    // decision uses deny-overrides regardless of order.
    void add_rule(Rule rule);

    // Load the built-in RMCP baseline rule set (protected namespaces, destructive
    // delete guarding, privileged-resource escalation, etc).
    void load_baseline_rules();

    // Evaluate a change against the facts. Deterministic: same inputs → same verdict.
    Verdict evaluate(const Change& change, const ClusterFacts& facts) const;

    size_t rule_count() const { return rules_.size(); }

private:
    std::vector<Rule> rules_;
};

}  // namespace rmcp

#endif  // RMCP_POLICY_CORE_HPP

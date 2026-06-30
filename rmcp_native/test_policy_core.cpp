// Test harness for the RMCP policy core.
#include "rmcp_policy_core.hpp"
#include <iostream>
#include <cassert>

using namespace rmcp;

static void show(const std::string& label, const Verdict& v) {
    std::cout << "  " << label << " -> " << to_string(v.decision) << "\n";
    for (const auto& f : v.findings) {
        std::cout << "      [" << to_string(f.decision) << "] " << f.rule_id
                  << ": " << f.message << "\n";
    }
}

int main() {
    PolicyEngine engine;
    engine.load_baseline_rules();
    std::cout << "RMCP policy core loaded with " << engine.rule_count() << " baseline rules.\n\n";

    ClusterFacts facts;
    facts.namespaces["grafana-operator"] = true;
    facts.protected_namespaces = {"default", "kube-system", "openshift-operators"};
    facts.installed_operators = {"grafana-operator.v5.24.0"};

    // Test 1: a normal operator CR create in an existing namespace -> require approval (governed)
    {
        Change c;
        c.action = "create"; c.kind = "Grafana";
        c.api_version = "grafana.integreatly.org/v1beta1";
        c.name = "grafana"; c.ns = "grafana-operator"; c.requested_by = "brandon";
        show("create Grafana (normal)", engine.evaluate(c, facts));
        assert(engine.evaluate(c, facts).decision == Decision::RequireApproval);
    }

    // Test 2: deleting a PVC -> DENY (hard rule)
    {
        Change c;
        c.action = "delete"; c.kind = "PersistentVolumeClaim";
        c.name = "data-es-0"; c.ns = "elastic-system";
        show("delete a PVC", engine.evaluate(c, facts));
        assert(engine.evaluate(c, facts).decision == Decision::Deny);
    }

    // Test 3: deleting something in a protected namespace -> DENY
    {
        Change c;
        c.action = "delete"; c.kind = "ConfigMap"; c.name = "cfg"; c.ns = "kube-system";
        show("delete in protected ns", engine.evaluate(c, facts));
        assert(engine.evaluate(c, facts).decision == Decision::Deny);
    }

    // Test 4: a privileged container -> require approval (escalate)
    {
        Change c;
        c.action = "create"; c.kind = "Pod"; c.name = "p"; c.ns = "grafana-operator";
        c.attrs["privileged"] = "true";
        show("create privileged Pod", engine.evaluate(c, facts));
        assert(engine.evaluate(c, facts).decision == Decision::RequireApproval);
    }

    // Test 5: create into a non-existent namespace (not creating it) -> escalate
    {
        Change c;
        c.action = "create"; c.kind = "Service"; c.name = "svc"; c.ns = "does-not-exist";
        show("create into missing ns", engine.evaluate(c, facts));
        auto v = engine.evaluate(c, facts);
        assert(v.decision == Decision::RequireApproval);
    }

    // Test 6: determinism — same inputs, same verdict, repeated
    {
        Change c; c.action = "create"; c.kind = "Grafana"; c.ns = "grafana-operator";
        auto a = engine.evaluate(c, facts);
        auto b = engine.evaluate(c, facts);
        assert(a.decision == b.decision && a.findings.size() == b.findings.size());
        std::cout << "  determinism check -> OK (identical verdicts)\n";
    }

    std::cout << "\nAll policy core tests passed.\n";
    return 0;
}

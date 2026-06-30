// Integration test: watch engine (live state) feeds the policy core (decisions).
#include "rmcp_cluster_watch.hpp"
#include "rmcp_policy_core.hpp"
#include <iostream>
#include <cassert>

using namespace rmcp;

int main() {
    ClusterWatch watch;

    // Prime with an initial "list": namespaces, an operator, some pods.
    watch.prime({
        {EventType::Added, "Namespace", "v1", "", "grafana-operator", "", 1},
        {EventType::Added, "Namespace", "v1", "", "default", "", 1},
        {EventType::Added, "ClusterServiceVersion", "operators.coreos.com/v1alpha1",
            "grafana-operator", "grafana-operator.v5.24.0", "Succeeded", 2},
        {EventType::Added, "Pod", "v1", "grafana-operator", "grafana-deployment-1", "Running", 3},
        {EventType::Added, "Pod", "v1", "grafana-operator", "grafana-operator-ctrl", "Running", 3},
    });

    std::cout << "Watch engine primed. Live model size: " << watch.size() << "\n";
    auto snap = watch.snapshot();
    std::cout << "  namespaces: " << snap.namespaces.size()
              << " | operators: " << snap.operators.size()
              << " | pods running: " << snap.pods_running << "\n\n";

    assert(watch.namespace_exists("grafana-operator"));
    assert(watch.operator_installed("grafana"));
    assert(!watch.operator_installed("elasticsearch"));

    // A live event arrives: a new Elasticsearch operator gets installed.
    std::cout << "Event: ECK operator installed...\n";
    watch.apply_event({EventType::Added, "ClusterServiceVersion",
        "operators.coreos.com/v1alpha1", "elastic-system",
        "elasticsearch-eck-operator-certified.v3.4.1", "Succeeded", 10});
    assert(watch.operator_installed("elasticsearch"));
    std::cout << "  watch now sees elasticsearch operator: yes\n\n";

    // Now evaluate a change against the LIVE state via the policy core.
    PolicyEngine engine;
    engine.load_baseline_rules();

    ClusterFacts facts = watch.to_facts({"default", "kube-system"});

    // Change 1: create a Grafana CR in the existing grafana-operator ns.
    Change c1;
    c1.action = "create"; c1.kind = "Grafana";
    c1.api_version = "grafana.integreatly.org/v1beta1";
    c1.name = "grafana"; c1.ns = "grafana-operator";
    auto v1 = engine.evaluate(c1, facts);
    std::cout << "Decision (create Grafana in existing ns): " << to_string(v1.decision)
              << "  [" << v1.summary() << "]\n";
    assert(v1.decision == Decision::RequireApproval);  // governed, ns exists

    // Change 2: create a Service into a namespace the live model does NOT have.
    Change c2;
    c2.action = "create"; c2.kind = "Service"; c2.name = "svc"; c2.ns = "ghost-ns";
    auto v2 = engine.evaluate(c2, facts);
    std::cout << "Decision (create into missing ns): " << to_string(v2.decision)
              << "  [" << v2.summary() << "]\n";
    // Both R005 (missing ns) and R006 (mutation) escalate -> require approval.
    assert(v2.decision == Decision::RequireApproval);

    // Change 3: delete in a protected namespace -> deny, against live facts.
    Change c3;
    c3.action = "delete"; c3.kind = "ConfigMap"; c3.name = "x"; c3.ns = "default";
    auto v3 = engine.evaluate(c3, facts);
    std::cout << "Decision (delete in protected ns): " << to_string(v3.decision)
              << "  [" << v3.summary() << "]\n";
    assert(v3.decision == Decision::Deny);

    std::cout << "\nIntegration OK: watch engine state drives policy decisions.\n";
    return 0;
}

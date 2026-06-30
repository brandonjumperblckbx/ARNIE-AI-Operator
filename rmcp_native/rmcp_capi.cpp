// ============================================================================
//  RMCP Native — C ABI binding.
//
//  Exposes the C++ policy core + cluster watch engine to Python (via ctypes) over
//  a flat, stable C interface. Python passes JSON strings in, gets JSON strings
//  back; all C++ types stay on this side of the boundary. Opaque handles keep
//  engine instances alive across calls.
//
//  This keeps the engines pure C++ (fast, testable, reusable by the future native
//  agent) while making them callable from the FastAPI backend with no heavy
//  binding framework — just compile to a .so and ctypes.CDLL it.
//
//  Built on the RMCP engine by BLCKBX.
// ============================================================================
#include "rmcp_policy_core.hpp"
#include "rmcp_cluster_watch.hpp"

#include <string>
#include <cstring>
#include <cstdlib>

// Minimal embedded JSON (we only need to parse flat objects + emit small results;
// avoiding an external dependency keeps the build a single g++ command).
#include "mini_json.hpp"

using namespace rmcp;

extern "C" {

// ── lifecycle ──

// Create a policy engine with the baseline rule set loaded. Returns an opaque handle.
void* rmcp_policy_create() {
    auto* eng = new PolicyEngine();
    eng->load_baseline_rules();
    return static_cast<void*>(eng);
}

void rmcp_policy_destroy(void* h) {
    delete static_cast<PolicyEngine*>(h);
}

void* rmcp_watch_create() {
    return static_cast<void*>(new ClusterWatch());
}

void rmcp_watch_destroy(void* h) {
    delete static_cast<ClusterWatch*>(h);
}

// Free a string returned by this library.
void rmcp_free_string(char* s) {
    std::free(s);
}

// ── helpers ──

static char* dup_cstr(const std::string& s) {
    char* out = static_cast<char*>(std::malloc(s.size() + 1));
    std::memcpy(out, s.c_str(), s.size() + 1);
    return out;
}

// ── watch engine ──

// Feed one event. JSON: {"type":"added|modified|deleted","kind","api_version",
//                        "ns","name","phase","resource_version"}
void rmcp_watch_apply(void* h, const char* json) {
    auto* w = static_cast<ClusterWatch*>(h);
    minijson::Object o = minijson::parse_object(json ? json : "{}");
    ResourceEvent ev;
    std::string t = o.get("type", "added");
    ev.type = (t == "deleted") ? EventType::Deleted
            : (t == "modified") ? EventType::Modified
            : EventType::Added;
    ev.kind = o.get("kind", "");
    ev.api_version = o.get("api_version", "");
    ev.ns = o.get("ns", "");
    ev.name = o.get("name", "");
    ev.phase = o.get("phase", "");
    ev.resource_version = static_cast<std::uint64_t>(o.get_int("resource_version", 0));
    w->apply_event(ev);
}

// Snapshot as JSON.
char* rmcp_watch_snapshot(void* h) {
    auto* w = static_cast<ClusterWatch*>(h);
    WatchSnapshot s = w->snapshot();
    minijson::Writer jw;
    jw.begin();
    jw.kv_int("total_resources", static_cast<long>(s.total_resources));
    jw.kv_int("pods_running", static_cast<long>(s.pods_running));
    jw.kv_int("pods_not_running", static_cast<long>(s.pods_not_running));
    jw.kv_array_str("namespaces", s.namespaces);
    jw.kv_array_str("operators", s.operators);
    jw.end();
    return dup_cstr(jw.str());
}

// Quick queries.
int rmcp_watch_namespace_exists(void* h, const char* ns) {
    return static_cast<ClusterWatch*>(h)->namespace_exists(ns ? ns : "") ? 1 : 0;
}
int rmcp_watch_operator_installed(void* h, const char* frag) {
    return static_cast<ClusterWatch*>(h)->operator_installed(frag ? frag : "") ? 1 : 0;
}
int rmcp_watch_size(void* h) {
    return static_cast<int>(static_cast<ClusterWatch*>(h)->size());
}

// ── policy core ──

// Evaluate a change against the watch engine's live facts. Both handles required.
// change JSON: {"action","kind","api_version","name","ns","requested_by",
//               "attrs":{...flat string map...}}
// protected_namespaces JSON array string, e.g. ["default","kube-system"]
// Returns JSON: {"decision":"allow|require_approval|deny","summary":"...",
//                "findings":[{"rule_id","decision","message","severity"}]}
char* rmcp_policy_evaluate(void* policy_h, void* watch_h,
                           const char* change_json, const char* protected_json) {
    auto* eng = static_cast<PolicyEngine*>(policy_h);
    auto* w = static_cast<ClusterWatch*>(watch_h);

    minijson::Object o = minijson::parse_object(change_json ? change_json : "{}");
    Change c;
    c.action = o.get("action", "");
    c.kind = o.get("kind", "");
    c.api_version = o.get("api_version", "");
    c.name = o.get("name", "");
    c.ns = o.get("ns", "");
    c.requested_by = o.get("requested_by", "");
    c.attrs = o.get_string_map("attrs");

    std::vector<std::string> prot = minijson::parse_string_array(protected_json ? protected_json : "[]");
    ClusterFacts facts = w ? w->to_facts(prot) : ClusterFacts{};
    if (!w) facts.protected_namespaces = prot;

    Verdict v = eng->evaluate(c, facts);

    minijson::Writer jw;
    jw.begin();
    jw.kv_str("decision", to_string(v.decision));
    jw.kv_str("summary", v.summary());
    jw.begin_array("findings");
    for (const auto& f : v.findings) {
        jw.begin_object_in_array();
        jw.kv_str("rule_id", f.rule_id);
        jw.kv_str("decision", to_string(f.decision));
        jw.kv_str("message", f.message);
        jw.kv_int("severity", f.severity);
        jw.end_object_in_array();
    }
    jw.end_array();
    jw.end();
    return dup_cstr(jw.str());
}

int rmcp_policy_rule_count(void* h) {
    return static_cast<int>(static_cast<PolicyEngine*>(h)->rule_count());
}

}  // extern "C"

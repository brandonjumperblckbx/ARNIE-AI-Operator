// ============================================================================
//  RMCP Cluster Watch Engine — live cluster awareness, in C++.
//
//  Where the Python cluster-vision client ASKS the cluster questions on demand,
//  this engine WATCHES — maintaining a continuously-updated, in-memory model of
//  cluster state. It is the "always-on eyes" beneath ARNIE's on-demand vision.
//
//  Why C++: a watch engine holds long-lived streaming connections and an in-memory
//  index over potentially thousands of objects, updated as events arrive. It must
//  be memory-efficient, concurrency-friendly, and fast to query. That is squarely
//  C++ territory — Python polling cannot match it.
//
//  TRUST INVARIANT — READ-ONLY BY CONSTRUCTION:
//  This engine only ever consumes the Kubernetes *watch* API (GET/streaming reads).
//  It exposes NO method that mutates the cluster. Like the Python vision client, it
//  cannot change anything — all changes still flow through the governed AAP pipeline
//  with human approval. The watch engine observes; it never acts.
//
//  This header defines the model + interface. The streaming transport (HTTP/2 watch)
//  is pluggable: the engine accepts events from a feeder, so it is testable without a
//  live cluster and transport-agnostic.
//
//  Built on the RMCP engine by BLCKBX.
// ============================================================================
#ifndef RMCP_CLUSTER_WATCH_HPP
#define RMCP_CLUSTER_WATCH_HPP

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <optional>
#include <cstdint>

#include "rmcp_policy_core.hpp"  // to project state into ClusterFacts

namespace rmcp {

// The type of a watch event, mirroring the Kubernetes watch API.
enum class EventType { Added, Modified, Deleted };

// A single observed object, flattened to what the engine indexes.
struct ResourceEvent {
    EventType type;
    std::string kind;          // "Pod", "ClusterServiceVersion", "Namespace", ...
    std::string api_version;
    std::string ns;            // "" for cluster-scoped
    std::string name;
    std::string phase;         // status.phase if present ("Running", "Succeeded", ...)
    std::uint64_t resource_version = 0;  // monotonic-ish; for ordering/debug
};

// The engine's view of a single tracked resource.
struct TrackedResource {
    std::string kind;
    std::string ns;
    std::string name;
    std::string phase;
    std::uint64_t resource_version = 0;

    std::string key() const { return kind + "/" + ns + "/" + name; }
};

// Aggregate, queryable snapshot derived from the live model.
struct WatchSnapshot {
    std::size_t total_resources = 0;
    std::vector<std::string> namespaces;
    std::vector<std::string> operators;           // installed CSV names
    std::size_t pods_running = 0;
    std::size_t pods_not_running = 0;
};

// ── The watch engine ──
// Thread-safe: a feeder thread calls apply_event(); query threads call the
// read methods. A single mutex guards the model (simple + correct; the workload
// is read-heavy and events are cheap to apply).
class ClusterWatch {
public:
    ClusterWatch();

    // Feed a single observed event into the model. This is the ONLY input. There
    // is deliberately no apply/create/delete-on-cluster method anywhere in this
    // class — the engine cannot mutate the cluster, by construction.
    void apply_event(const ResourceEvent& ev);

    // Bulk-load an initial list (the "list" half of list-then-watch).
    void prime(const std::vector<ResourceEvent>& initial);

    // ── read-only queries over the live model ──
    bool namespace_exists(const std::string& ns) const;
    bool operator_installed(const std::string& name_fragment) const;
    bool resource_exists(const std::string& kind, const std::string& ns,
                         const std::string& name) const;
    std::optional<TrackedResource> get(const std::string& kind, const std::string& ns,
                                       const std::string& name) const;
    std::vector<TrackedResource> in_namespace(const std::string& ns) const;

    WatchSnapshot snapshot() const;

    // Project the live model into the ClusterFacts the policy core consumes, so a
    // decision is always evaluated against the freshest known state.
    ClusterFacts to_facts(const std::vector<std::string>& protected_namespaces) const;

    std::size_t size() const;

private:
    mutable std::mutex mu_;
    // key "kind/ns/name" -> resource
    std::unordered_map<std::string, TrackedResource> model_;
    // fast namespace presence set
    std::unordered_map<std::string, bool> namespaces_;
    // installed operator CSV names (lowercased) -> present
    std::unordered_map<std::string, bool> operators_;

    static std::string make_key(const std::string& kind, const std::string& ns,
                                const std::string& name);
};

}  // namespace rmcp

#endif  // RMCP_CLUSTER_WATCH_HPP

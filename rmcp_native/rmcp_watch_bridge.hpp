// ============================================================================
//  RMCP Watch Bridge
//  Connects the existing ARNIE EventStreamProcessor (cpp/performance) to the
//  RMCP cluster watch engine (rmcp_native), so live Kubernetes events feed the
//  watch model. This is the wire that makes the watch engine's model reflect the
//  real cluster instead of being empty.
//
//  Flow:
//    EventStreamProcessor observes a k8s event
//        -> WatchBridge::feed() converts it to an rmcp::ResourceEvent
//        -> ClusterWatch::apply_event() updates the live model
//        -> the policy core then evaluates changes against fresh state
//
//  The bridge is read-only end to end: it only moves observed events into an
//  in-memory model. Nothing here mutates the cluster.
//
//  Built on the RMCP engine by BLCKBX.
// ============================================================================
#ifndef RMCP_WATCH_BRIDGE_HPP
#define RMCP_WATCH_BRIDGE_HPP

#include "rmcp_cluster_watch.hpp"
// The event processor lives in cpp/performance; include its header when building
// together. The bridge only needs its ResourceEvent + EventType definitions.
#include "event_processor.hpp"   // arnie::performance::ResourceEvent / EventType

namespace rmcp {

// Convert an arnie::performance event into an rmcp watch event.
inline ResourceEvent from_performance_event(const arnie::performance::ResourceEvent& e) {
    ResourceEvent out;
    switch (e.type) {
        case arnie::performance::EventType::Added:    out.type = EventType::Added; break;
        case arnie::performance::EventType::Modified: out.type = EventType::Modified; break;
        case arnie::performance::EventType::Deleted:  out.type = EventType::Deleted; break;
        case arnie::performance::EventType::Error:    out.type = EventType::Modified; break;
    }
    out.kind = e.kind;
    out.api_version = "";  // performance event doesn't carry it; not needed for the model
    out.ns = e.ns;
    out.name = e.name;
    // Pull a phase from labels if present (the processor extracts labels).
    auto it = e.labels.find("status.phase");
    out.phase = (it != e.labels.end()) ? it->second : "";
    out.resource_version = 0;
    return out;
}

// A bridge holding a reference to the watch engine; register feed() as a sink on
// the EventStreamProcessor so each observed event updates the model.
class WatchBridge {
public:
    explicit WatchBridge(ClusterWatch& watch) : watch_(watch) {}

    void feed(const arnie::performance::ResourceEvent& e) {
        watch_.apply_event(from_performance_event(e));
    }

private:
    ClusterWatch& watch_;
};

}  // namespace rmcp

#endif  // RMCP_WATCH_BRIDGE_HPP

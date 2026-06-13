#pragma once
/// ARNIE Event Stream Processor
/// Low-latency monitoring of Kubernetes events for playbook outcome tracking
/// and real-time drift detection. Part of the RMCP C++ performance layer.

#include <string>
#include <vector>
#include <queue>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <unordered_map>
#include <optional>

namespace arnie {
namespace performance {

/// Event types from Kubernetes watch API
enum class EventType {
    Added,
    Modified,
    Deleted,
    Error,
};

/// A Kubernetes resource event
struct ResourceEvent {
    EventType type;
    std::string kind;
    std::string name;
    std::string ns;
    std::string resource_version;
    std::string raw_json;
    std::chrono::system_clock::time_point timestamp;

    /// Labels extracted from the resource
    std::unordered_map<std::string, std::string> labels;
};

/// Event processing metrics
struct ProcessingMetrics {
    std::atomic<uint64_t> events_received{0};
    std::atomic<uint64_t> events_processed{0};
    std::atomic<uint64_t> events_failed{0};
    std::atomic<uint64_t> drift_detected{0};
    std::atomic<uint64_t> total_latency_us{0};

    double avg_latency_us() const {
        auto processed = events_processed.load();
        return processed > 0
            ? static_cast<double>(total_latency_us.load()) / processed
            : 0.0;
    }
};

/// Callback for drift notifications
using DriftCallback = std::function<void(
    const std::string& playbook_id,
    const std::string& resource_kind,
    const std::string& resource_name,
    const std::string& drift_description
)>;

/// High-performance event stream processor for Kubernetes events
class EventStreamProcessor {
public:
    EventStreamProcessor();
    ~EventStreamProcessor();

    /// Start processing events
    void start();

    /// Stop processing
    void stop();

    /// Enqueue an event for processing
    void enqueue(ResourceEvent event);

    /// Register a callback for drift detection
    void on_drift(DriftCallback callback);

    /// Get current processing metrics
    ProcessingMetrics get_metrics() const;

    /// Check if a resource is managed by ARNIE
    bool is_arnie_managed(const ResourceEvent& event) const;

private:
    void process_loop();
    void handle_event(const ResourceEvent& event);
    void check_drift(const ResourceEvent& event);

    std::queue<ResourceEvent> event_queue_;
    mutable std::mutex queue_mutex_;
    std::atomic<bool> running_{false};
    ProcessingMetrics metrics_;
    std::vector<DriftCallback> drift_callbacks_;

    /// Cache of expected resource states (from playbook execution)
    std::unordered_map<std::string, std::string> expected_state_cache_;
    mutable std::mutex cache_mutex_;
};

} // namespace performance
} // namespace arnie

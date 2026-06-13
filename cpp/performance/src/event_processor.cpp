/// ARNIE Event Stream Processor — Implementation
/// Processes Kubernetes watch events at high throughput for drift detection.

#include "event_processor.hpp"
#include <thread>
#include <iostream>

namespace arnie {
namespace performance {

EventStreamProcessor::EventStreamProcessor() = default;

EventStreamProcessor::~EventStreamProcessor() {
    stop();
}

void EventStreamProcessor::start() {
    running_ = true;
    std::thread worker([this]() { process_loop(); });
    worker.detach();
}

void EventStreamProcessor::stop() {
    running_ = false;
}

void EventStreamProcessor::enqueue(ResourceEvent event) {
    metrics_.events_received++;
    std::lock_guard<std::mutex> lock(queue_mutex_);
    event_queue_.push(std::move(event));
}

void EventStreamProcessor::on_drift(DriftCallback callback) {
    drift_callbacks_.push_back(std::move(callback));
}

ProcessingMetrics EventStreamProcessor::get_metrics() const {
    return ProcessingMetrics{
        metrics_.events_received.load(),
        metrics_.events_processed.load(),
        metrics_.events_failed.load(),
        metrics_.drift_detected.load(),
        metrics_.total_latency_us.load(),
    };
}

bool EventStreamProcessor::is_arnie_managed(const ResourceEvent& event) const {
    auto it = event.labels.find("arnie.blckbx.io/managed");
    return it != event.labels.end() && it->second == "true";
}

void EventStreamProcessor::process_loop() {
    while (running_) {
        ResourceEvent event;
        bool has_event = false;

        {
            std::lock_guard<std::mutex> lock(queue_mutex_);
            if (!event_queue_.empty()) {
                event = std::move(event_queue_.front());
                event_queue_.pop();
                has_event = true;
            }
        }

        if (!has_event) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }

        auto start = std::chrono::steady_clock::now();

        try {
            handle_event(event);
            metrics_.events_processed++;
        } catch (const std::exception& e) {
            std::cerr << "[ARNIE] Event processing failed: " << e.what() << std::endl;
            metrics_.events_failed++;
        }

        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - start
        );
        metrics_.total_latency_us += duration.count();
    }
}

void EventStreamProcessor::handle_event(const ResourceEvent& event) {
    // Only process ARNIE-managed resources
    if (!is_arnie_managed(event)) {
        return;
    }

    switch (event.type) {
        case EventType::Modified:
            check_drift(event);
            break;

        case EventType::Deleted:
            // Resource deleted — always drift if we expected it to exist
            {
                std::string key = event.ns + "/" + event.kind + "/" + event.name;
                std::lock_guard<std::mutex> lock(cache_mutex_);
                if (expected_state_cache_.count(key) > 0) {
                    metrics_.drift_detected++;
                    for (auto& cb : drift_callbacks_) {
                        auto playbook_it = event.labels.find("arnie.blckbx.io/playbook-id");
                        std::string pb_id = playbook_it != event.labels.end()
                            ? playbook_it->second : "unknown";
                        cb(pb_id, event.kind, event.name,
                           "Resource deleted outside of ARNIE");
                    }
                }
            }
            break;

        case EventType::Added:
            // New resource — cache it if ARNIE-managed
            {
                std::string key = event.ns + "/" + event.kind + "/" + event.name;
                std::lock_guard<std::mutex> lock(cache_mutex_);
                expected_state_cache_[key] = event.raw_json;
            }
            break;

        default:
            break;
    }
}

void EventStreamProcessor::check_drift(const ResourceEvent& event) {
    std::string key = event.ns + "/" + event.kind + "/" + event.name;

    std::lock_guard<std::mutex> lock(cache_mutex_);
    auto it = expected_state_cache_.find(key);
    if (it == expected_state_cache_.end()) {
        return; // No cached expected state
    }

    // Compare raw JSON (fast path — hash comparison in production)
    if (it->second != event.raw_json) {
        metrics_.drift_detected++;

        for (auto& cb : drift_callbacks_) {
            auto playbook_it = event.labels.find("arnie.blckbx.io/playbook-id");
            std::string pb_id = playbook_it != event.labels.end()
                ? playbook_it->second : "unknown";
            cb(pb_id, event.kind, event.name,
               "Resource modified outside of ARNIE");
        }

        // Update cache with actual state
        it->second = event.raw_json;
    }
}

} // namespace performance
} // namespace arnie

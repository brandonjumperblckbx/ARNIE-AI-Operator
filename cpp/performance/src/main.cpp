/// ARNIE Performance Service — Entry Point
/// Runs the event stream processor and playbook analyzer as a standalone service.
/// Communicates with the Python backend via Unix socket or TCP.

#include "event_processor.hpp"
#include "playbook_analyzer.hpp"
#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <csignal>

static std::atomic<bool> g_running{true};

void signal_handler(int) {
    g_running = false;
}

int main(int argc, char* argv[]) {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    std::cout << "╔══════════════════════════════════════════╗" << std::endl;
    std::cout << "║  ARNIE Performance Service               ║" << std::endl;
    std::cout << "║  Event Processing & Playbook Analysis    ║" << std::endl;
    std::cout << "║  RMCP C++ Performance Layer              ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════╝" << std::endl;

    // Initialize components
    arnie::performance::EventStreamProcessor event_processor;
    arnie::performance::PlaybookAnalyzer playbook_analyzer;

    // Register drift callback
    event_processor.on_drift([](
        const std::string& playbook_id,
        const std::string& kind,
        const std::string& name,
        const std::string& description) {
        std::cout << "[DRIFT] playbook=" << playbook_id
                  << " resource=" << kind << "/" << name
                  << " — " << description << std::endl;
    });

    // Start event processing
    event_processor.start();
    std::cout << "[ARNIE] Event processor started" << std::endl;

    // Main loop — report metrics periodically
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::seconds(30));

        auto metrics = event_processor.get_metrics();
        std::cout << "[METRICS]"
                  << " received=" << metrics.events_received.load()
                  << " processed=" << metrics.events_processed.load()
                  << " failed=" << metrics.events_failed.load()
                  << " drift=" << metrics.drift_detected.load()
                  << " avg_latency=" << metrics.avg_latency_us() << "us"
                  << std::endl;
    }

    event_processor.stop();
    std::cout << "[ARNIE] Performance service stopped" << std::endl;
    return 0;
}

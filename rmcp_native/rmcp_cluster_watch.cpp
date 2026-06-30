// ============================================================================
//  RMCP Cluster Watch Engine — implementation.
//  Read-only by construction: consumes events, never mutates the cluster.
//  Built on the RMCP engine by BLCKBX.
// ============================================================================
#include "rmcp_cluster_watch.hpp"

#include <algorithm>
#include <cctype>

namespace rmcp {

static std::string lower_copy(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return s;
}

ClusterWatch::ClusterWatch() {}

std::string ClusterWatch::make_key(const std::string& kind, const std::string& ns,
                                   const std::string& name) {
    return kind + "/" + ns + "/" + name;
}

void ClusterWatch::apply_event(const ResourceEvent& ev) {
    std::lock_guard<std::mutex> lk(mu_);
    const std::string key = make_key(ev.kind, ev.ns, ev.name);

    if (ev.type == EventType::Deleted) {
        model_.erase(key);
        // Maintain derived indexes.
        if (ev.kind == "Namespace") namespaces_.erase(ev.name);
        if (ev.kind == "ClusterServiceVersion") operators_.erase(lower_copy(ev.name));
        return;
    }

    // Added or Modified -> upsert.
    TrackedResource tr;
    tr.kind = ev.kind;
    tr.ns = ev.ns;
    tr.name = ev.name;
    tr.phase = ev.phase;
    tr.resource_version = ev.resource_version;
    model_[key] = std::move(tr);

    if (ev.kind == "Namespace") namespaces_[ev.name] = true;
    if (ev.kind == "ClusterServiceVersion") operators_[lower_copy(ev.name)] = true;
}

void ClusterWatch::prime(const std::vector<ResourceEvent>& initial) {
    for (const auto& ev : initial) {
        ResourceEvent e = ev;
        e.type = EventType::Added;
        apply_event(e);
    }
}

bool ClusterWatch::namespace_exists(const std::string& ns) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = namespaces_.find(ns);
    return it != namespaces_.end() && it->second;
}

bool ClusterWatch::operator_installed(const std::string& frag) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::string f = lower_copy(frag);
    for (const auto& [name, present] : operators_) {
        if (present && name.find(f) != std::string::npos) return true;
    }
    return false;
}

bool ClusterWatch::resource_exists(const std::string& kind, const std::string& ns,
                                   const std::string& name) const {
    std::lock_guard<std::mutex> lk(mu_);
    return model_.find(make_key(kind, ns, name)) != model_.end();
}

std::optional<TrackedResource> ClusterWatch::get(const std::string& kind,
                                                 const std::string& ns,
                                                 const std::string& name) const {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = model_.find(make_key(kind, ns, name));
    if (it == model_.end()) return std::nullopt;
    return it->second;
}

std::vector<TrackedResource> ClusterWatch::in_namespace(const std::string& ns) const {
    std::lock_guard<std::mutex> lk(mu_);
    std::vector<TrackedResource> out;
    for (const auto& [key, tr] : model_) {
        if (tr.ns == ns) out.push_back(tr);
    }
    return out;
}

WatchSnapshot ClusterWatch::snapshot() const {
    std::lock_guard<std::mutex> lk(mu_);
    WatchSnapshot s;
    s.total_resources = model_.size();
    for (const auto& [ns, present] : namespaces_) {
        if (present) s.namespaces.push_back(ns);
    }
    for (const auto& [op, present] : operators_) {
        if (present) s.operators.push_back(op);
    }
    for (const auto& [key, tr] : model_) {
        if (tr.kind == "Pod") {
            if (tr.phase == "Running") ++s.pods_running;
            else ++s.pods_not_running;
        }
    }
    std::sort(s.namespaces.begin(), s.namespaces.end());
    std::sort(s.operators.begin(), s.operators.end());
    return s;
}

ClusterFacts ClusterWatch::to_facts(const std::vector<std::string>& protected_namespaces) const {
    std::lock_guard<std::mutex> lk(mu_);
    ClusterFacts f;
    for (const auto& [ns, present] : namespaces_) {
        f.namespaces[ns] = present;
    }
    for (const auto& [op, present] : operators_) {
        if (present) f.installed_operators.push_back(op);
    }
    f.protected_namespaces = protected_namespaces;
    for (const auto& [key, tr] : model_) {
        f.existing_resources.push_back(key);
    }
    return f;
}

std::size_t ClusterWatch::size() const {
    std::lock_guard<std::mutex> lk(mu_);
    return model_.size();
}

}  // namespace rmcp

/// ARNIE Playbook Analyzer — Implementation

#include "playbook_analyzer.hpp"
#include <regex>
#include <chrono>
#include <algorithm>

namespace arnie {
namespace performance {

PlaybookAnalyzer::PlaybookAnalyzer() {
    cluster_scoped_kinds_ = {
        "Namespace", "ClusterRole", "ClusterRoleBinding",
        "PersistentVolume", "StorageClass", "CustomResourceDefinition",
        "Node", "SecurityContextConstraints",
    };

    destructive_modules_ = {
        "k8s_drain", "community.kubernetes.k8s_drain",
        "ansible.builtin.file", // with state: absent
    };
}

AnalysisResult PlaybookAnalyzer::analyze(const std::string& yaml_content) const {
    auto start = std::chrono::steady_clock::now();

    AnalysisResult result{};
    result.yaml_valid = validate_yaml_fast(yaml_content);
    result.resource_kinds = extract_resource_kinds(yaml_content);
    result.resource_count = static_cast<int>(result.resource_kinds.size());

    // Count tasks
    std::regex task_re(R"(^\s+- name:)", std::regex::multiline);
    auto tasks_begin = std::sregex_iterator(yaml_content.begin(), yaml_content.end(), task_re);
    auto tasks_end = std::sregex_iterator();
    result.task_count = std::distance(tasks_begin, tasks_end);

    // Count deletions
    std::regex absent_re(R"(state:\s*absent)");
    auto absent_begin = std::sregex_iterator(yaml_content.begin(), yaml_content.end(), absent_re);
    result.deletion_count = std::distance(absent_begin, std::sregex_iterator());

    // Extract namespaces
    std::regex ns_re(R"(namespace:\s*(\S+))");
    auto ns_begin = std::sregex_iterator(yaml_content.begin(), yaml_content.end(), ns_re);
    for (auto it = ns_begin; it != std::sregex_iterator(); ++it) {
        result.namespaces.insert((*it)[1].str());
    }

    // Check for cluster-scoped resources
    result.has_cluster_scoped = contains_cluster_scoped(result.resource_kinds);

    // Check for destructive operations
    result.has_destructive_ops = result.deletion_count > 0;

    // Assess risk
    result.risk_level = assess_risk(
        result.deletion_count,
        result.has_cluster_scoped,
        result.resource_count
    );

    // Estimate blast radius
    result.estimated_blast_radius = estimate_blast_radius(yaml_content);

    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - start
    );
    result.analysis_time_us = static_cast<double>(duration.count());

    return result;
}

bool PlaybookAnalyzer::validate_yaml_fast(const std::string& content) const {
    if (content.empty()) return false;

    // Fast checks — not a full YAML parser, but catches common issues
    int indent_errors = 0;
    bool has_content = false;

    for (size_t i = 0; i < content.size(); ++i) {
        char c = content[i];
        if (c == '\t') {
            // Tabs are invalid in YAML
            return false;
        }
        if (c != ' ' && c != '\n' && c != '\r' && c != '-') {
            has_content = true;
        }
    }

    return has_content;
}

std::vector<std::string> PlaybookAnalyzer::extract_resource_kinds(
    const std::string& content) const {

    std::vector<std::string> kinds;
    std::regex kind_re(R"(kind:\s*(\w+))");

    auto begin = std::sregex_iterator(content.begin(), content.end(), kind_re);
    auto end = std::sregex_iterator();

    std::unordered_set<std::string> seen;
    for (auto it = begin; it != end; ++it) {
        std::string kind = (*it)[1].str();
        if (seen.insert(kind).second) {
            kinds.push_back(kind);
        }
    }

    return kinds;
}

double PlaybookAnalyzer::estimate_blast_radius(const std::string& content) const {
    double radius = 0.0;

    auto kinds = extract_resource_kinds(content);
    radius += kinds.size() * 1.0;

    // Cluster-scoped resources have higher blast radius
    for (const auto& kind : kinds) {
        if (cluster_scoped_kinds_.count(kind) > 0) {
            radius += 5.0;
        }
    }

    // Deletions increase blast radius
    std::regex absent_re(R"(state:\s*absent)");
    auto begin = std::sregex_iterator(content.begin(), content.end(), absent_re);
    int deletions = std::distance(begin, std::sregex_iterator());
    radius += deletions * 3.0;

    return radius;
}

bool PlaybookAnalyzer::contains_cluster_scoped(
    const std::vector<std::string>& kinds) const {
    return std::any_of(kinds.begin(), kinds.end(),
        [this](const std::string& k) {
            return cluster_scoped_kinds_.count(k) > 0;
        });
}

std::string PlaybookAnalyzer::assess_risk(
    int deletions, bool cluster_scoped, int resource_count) const {
    if (deletions > 0 && cluster_scoped) return "critical";
    if (deletions > 3 || cluster_scoped) return "high";
    if (deletions > 0 || resource_count > 5) return "medium";
    return "low";
}

} // namespace performance
} // namespace arnie

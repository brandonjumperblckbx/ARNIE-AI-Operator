#pragma once
/// ARNIE Playbook Analyzer
/// Fast YAML/Ansible analysis for pre-flight validation.
/// Runs syntax checks, resource counting, and blast radius estimation
/// at native speed before the Python validator runs deeper checks.

#include <string>
#include <vector>
#include <unordered_set>

namespace arnie {
namespace performance {

/// Result of fast playbook analysis
struct AnalysisResult {
    bool yaml_valid;
    int task_count;
    int resource_count;
    std::vector<std::string> resource_kinds;
    std::unordered_set<std::string> namespaces;
    int deletion_count;
    bool has_cluster_scoped;
    bool has_destructive_ops;
    std::string risk_level;         // low, medium, high, critical
    double estimated_blast_radius;
    std::vector<std::string> warnings;
    double analysis_time_us;
};

/// High-performance playbook pre-analyzer
class PlaybookAnalyzer {
public:
    PlaybookAnalyzer();

    /// Fast analysis of playbook YAML content
    AnalysisResult analyze(const std::string& yaml_content) const;

    /// Quick YAML syntax validation (faster than Python yaml.safe_load)
    bool validate_yaml_fast(const std::string& content) const;

    /// Extract resource kinds from playbook without full YAML parse
    std::vector<std::string> extract_resource_kinds(const std::string& content) const;

    /// Estimate blast radius from raw content
    double estimate_blast_radius(const std::string& content) const;

private:
    bool contains_cluster_scoped(const std::vector<std::string>& kinds) const;
    std::string assess_risk(int deletions, bool cluster_scoped, int resource_count) const;

    std::unordered_set<std::string> cluster_scoped_kinds_;
    std::unordered_set<std::string> destructive_modules_;
};

} // namespace performance
} // namespace arnie

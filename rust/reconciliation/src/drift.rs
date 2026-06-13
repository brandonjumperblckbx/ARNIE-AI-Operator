//! Drift detection for deployed Ansible playbook outcomes.
//! Compares the intended cluster state (from playbook) against actual state.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type of drift detected
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DriftType {
    /// Resource defined in playbook is missing from cluster
    ResourceMissing,
    /// Resource exists but has been modified outside of ARNIE
    ResourceModified,
    /// Unexpected resource found that wasn't in the playbook
    UnexpectedResource,
    /// Resource configuration doesn't match playbook spec
    ConfigurationDrift,
    /// Replica count changed
    ScaleDrift,
}

/// Severity of detected drift
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

/// A single drift detection record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftRecord {
    pub id: String,
    pub playbook_id: String,
    pub drift_type: DriftType,
    pub severity: Severity,
    pub resource_kind: String,
    pub resource_name: String,
    pub namespace: String,
    pub expected_state: Option<serde_json::Value>,
    pub actual_state: Option<serde_json::Value>,
    pub delta: serde_json::Value,
    pub detected_at: DateTime<Utc>,
    pub playbook_applied_at: Option<DateTime<Utc>>,
}

/// Drift detection engine
pub struct DriftDetector {
    /// Cache of expected states from previously run playbooks
    expected_states: HashMap<String, Vec<ExpectedResource>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpectedResource {
    pub kind: String,
    pub name: String,
    pub namespace: String,
    pub spec: serde_json::Value,
    pub applied_at: DateTime<Utc>,
    pub playbook_id: String,
}

impl DriftDetector {
    pub fn new() -> Self {
        Self {
            expected_states: HashMap::new(),
        }
    }

    /// Register expected state from a successfully executed playbook
    pub fn register_expected_state(
        &mut self,
        playbook_id: &str,
        resources: Vec<ExpectedResource>,
    ) {
        self.expected_states
            .insert(playbook_id.to_string(), resources);
    }

    /// Compare expected state against actual cluster state
    pub fn detect_drift(
        &self,
        playbook_id: &str,
        actual_resources: &[serde_json::Value],
    ) -> Vec<DriftRecord> {
        let mut records = Vec::new();

        let expected = match self.expected_states.get(playbook_id) {
            Some(e) => e,
            None => return records,
        };

        for exp in expected {
            let matching = actual_resources.iter().find(|actual| {
                let kind = actual.get("kind").and_then(|v| v.as_str()).unwrap_or("");
                let name = actual
                    .get("metadata")
                    .and_then(|m| m.get("name"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let ns = actual
                    .get("metadata")
                    .and_then(|m| m.get("namespace"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");

                kind == exp.kind && name == exp.name && ns == exp.namespace
            });

            match matching {
                None => {
                    records.push(DriftRecord {
                        id: format!("drift-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
                        playbook_id: playbook_id.to_string(),
                        drift_type: DriftType::ResourceMissing,
                        severity: Severity::High,
                        resource_kind: exp.kind.clone(),
                        resource_name: exp.name.clone(),
                        namespace: exp.namespace.clone(),
                        expected_state: Some(exp.spec.clone()),
                        actual_state: None,
                        delta: serde_json::json!({"status": "missing"}),
                        detected_at: Utc::now(),
                        playbook_applied_at: Some(exp.applied_at),
                    });
                }
                Some(actual) => {
                    let actual_spec = actual.get("spec").cloned().unwrap_or(serde_json::json!({}));
                    if actual_spec != exp.spec {
                        records.push(DriftRecord {
                            id: format!("drift-{}", uuid::Uuid::new_v4().to_string()[..8].to_string()),
                            playbook_id: playbook_id.to_string(),
                            drift_type: DriftType::ConfigurationDrift,
                            severity: Severity::Medium,
                            resource_kind: exp.kind.clone(),
                            resource_name: exp.name.clone(),
                            namespace: exp.namespace.clone(),
                            expected_state: Some(exp.spec.clone()),
                            actual_state: Some(actual_spec),
                            delta: serde_json::json!({"status": "modified"}),
                            detected_at: Utc::now(),
                            playbook_applied_at: Some(exp.applied_at),
                        });
                    }
                }
            }
        }

        records
    }
}

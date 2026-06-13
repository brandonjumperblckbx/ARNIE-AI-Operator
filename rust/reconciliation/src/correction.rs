//! Correction planning for detected drift.
//! Generates remediation playbooks to restore intended state.

use serde::{Deserialize, Serialize};

use crate::drift::{DriftRecord, DriftType, Severity};

/// A planned correction action
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectionAction {
    pub action_type: CorrectionType,
    pub resource_kind: String,
    pub resource_name: String,
    pub namespace: String,
    pub payload: serde_json::Value,
    pub priority: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CorrectionType {
    Recreate,
    Patch,
    Delete,
    Scale,
    Noop,
}

/// A complete correction plan derived from drift records
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectionPlan {
    pub playbook_id: String,
    pub actions: Vec<CorrectionAction>,
    pub requires_approval: bool,
    pub estimated_blast_radius: u32,
    pub remediation_yaml: String,
}

impl CorrectionPlan {
    /// Build a correction plan from drift records
    pub fn from_drift(playbook_id: &str, drift: &[DriftRecord]) -> Self {
        let mut actions = Vec::new();
        let mut blast_radius = 0u32;
        let mut requires_approval = false;

        for record in drift {
            let action = match &record.drift_type {
                DriftType::ResourceMissing => {
                    blast_radius += 1;
                    CorrectionAction {
                        action_type: CorrectionType::Recreate,
                        resource_kind: record.resource_kind.clone(),
                        resource_name: record.resource_name.clone(),
                        namespace: record.namespace.clone(),
                        payload: record.expected_state.clone().unwrap_or_default(),
                        priority: 1,
                    }
                }
                DriftType::ConfigurationDrift | DriftType::ScaleDrift => {
                    blast_radius += 1;
                    CorrectionAction {
                        action_type: CorrectionType::Patch,
                        resource_kind: record.resource_kind.clone(),
                        resource_name: record.resource_name.clone(),
                        namespace: record.namespace.clone(),
                        payload: record.expected_state.clone().unwrap_or_default(),
                        priority: 2,
                    }
                }
                DriftType::UnexpectedResource => {
                    blast_radius += 1;
                    requires_approval = true;
                    CorrectionAction {
                        action_type: CorrectionType::Delete,
                        resource_kind: record.resource_kind.clone(),
                        resource_name: record.resource_name.clone(),
                        namespace: record.namespace.clone(),
                        payload: serde_json::json!({}),
                        priority: 3,
                    }
                }
                DriftType::ResourceModified => {
                    blast_radius += 1;
                    CorrectionAction {
                        action_type: CorrectionType::Patch,
                        resource_kind: record.resource_kind.clone(),
                        resource_name: record.resource_name.clone(),
                        namespace: record.namespace.clone(),
                        payload: record.expected_state.clone().unwrap_or_default(),
                        priority: 2,
                    }
                }
            };

            // Critical drift always requires approval
            if record.severity == Severity::Critical {
                requires_approval = true;
            }

            actions.push(action);
        }

        // Sort by priority
        actions.sort_by_key(|a| a.priority);

        // Generate remediation YAML
        let remediation_yaml = Self::generate_remediation_yaml(playbook_id, &actions);

        CorrectionPlan {
            playbook_id: playbook_id.to_string(),
            actions,
            requires_approval: requires_approval || blast_radius > 5,
            estimated_blast_radius: blast_radius,
            remediation_yaml,
        }
    }

    fn generate_remediation_yaml(playbook_id: &str, actions: &[CorrectionAction]) -> String {
        let mut yaml = format!(
            "---\n- name: \"ARNIE drift remediation for {}\"\n  hosts: localhost\n  connection: local\n  gather_facts: false\n  tasks:\n",
            playbook_id
        );

        for (i, action) in actions.iter().enumerate() {
            let state = match &action.action_type {
                CorrectionType::Recreate | CorrectionType::Patch => "present",
                CorrectionType::Delete => "absent",
                _ => "present",
            };

            yaml.push_str(&format!(
                "    - name: \"Remediate {}/{} in {}\"\n      kubernetes.core.k8s:\n        state: {}\n        definition: {}\n\n",
                action.resource_kind,
                action.resource_name,
                action.namespace,
                state,
                "\"{{ lookup('template', 'remediation.j2') }}\"",
            ));
        }

        yaml
    }
}

//! Playbook workflow state machine
//! Manages the lifecycle of generated Ansible playbooks through ARNIE's
//! approval and execution pipeline.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::transitions::{TransitionError, TransitionTrigger};

/// Playbook lifecycle states
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum WorkflowState {
    /// Playbook generation requested
    Generating,
    /// AI model produced the playbook YAML
    Generated,
    /// Pre-flight validation running (syntax, lint, security scan)
    Validating,
    /// Validation passed — staged for human review
    PendingApproval,
    /// Human approved — pushing to GitHub
    Approved,
    /// Committed to Git repository
    Pushed,
    /// AAP project synced, job template launching
    Executing,
    /// AAP job completed successfully
    Completed,
    /// Playbook rejected by human operator
    Rejected,
    /// Workflow failed at some stage
    Failed(FailureReason),
    /// Approval window expired
    Expired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FailureReason {
    pub code: String,
    pub message: String,
    pub recoverable: bool,
    pub stage: String,
}

/// Record of a single state transition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    pub from: WorkflowState,
    pub to: WorkflowState,
    pub timestamp: DateTime<Utc>,
    pub triggered_by: TransitionTrigger,
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Full workflow context for a playbook
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkflowContext {
    pub workflow_id: Uuid,
    pub playbook_id: String,
    pub intent: String,
    pub current_state: WorkflowState,
    pub history: Vec<StateTransition>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// The playbook workflow state machine
pub struct PlaybookWorkflow {
    workflows: Arc<RwLock<HashMap<Uuid, WorkflowContext>>>,
}

impl PlaybookWorkflow {
    pub fn new() -> Self {
        Self {
            workflows: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Create a new playbook workflow
    pub async fn create(
        &self,
        playbook_id: &str,
        intent: &str,
    ) -> Uuid {
        let workflow_id = Uuid::new_v4();
        let now = Utc::now();

        let context = WorkflowContext {
            workflow_id,
            playbook_id: playbook_id.to_string(),
            intent: intent.to_string(),
            current_state: WorkflowState::Generating,
            history: Vec::new(),
            metadata: HashMap::new(),
            created_at: now,
            updated_at: now,
        };

        let mut workflows = self.workflows.write().await;
        workflows.insert(workflow_id, context);
        workflow_id
    }

    /// Transition a workflow to a new state
    pub async fn transition(
        &self,
        workflow_id: Uuid,
        to_state: WorkflowState,
        trigger: TransitionTrigger,
        metadata: Option<HashMap<String, serde_json::Value>>,
    ) -> Result<(), TransitionError> {
        let mut workflows = self.workflows.write().await;

        let context = workflows
            .get_mut(&workflow_id)
            .ok_or(TransitionError::WorkflowNotFound(workflow_id))?;

        if !self.is_valid_transition(&context.current_state, &to_state) {
            return Err(TransitionError::InvalidTransition {
                from: context.current_state.clone(),
                to: to_state,
            });
        }

        let transition = StateTransition {
            from: context.current_state.clone(),
            to: to_state.clone(),
            timestamp: Utc::now(),
            triggered_by: trigger,
            metadata: metadata.unwrap_or_default(),
        };

        context.history.push(transition);
        context.current_state = to_state;
        context.updated_at = Utc::now();

        Ok(())
    }

    /// Get a workflow by ID
    pub async fn get(&self, workflow_id: Uuid) -> Option<WorkflowContext> {
        let workflows = self.workflows.read().await;
        workflows.get(&workflow_id).cloned()
    }

    /// List workflows in a specific state
    pub async fn list_in_state(&self, state: WorkflowState) -> Vec<WorkflowContext> {
        let workflows = self.workflows.read().await;
        workflows
            .values()
            .filter(|ctx| ctx.current_state == state)
            .cloned()
            .collect()
    }

    /// Validate state transitions
    fn is_valid_transition(&self, from: &WorkflowState, to: &WorkflowState) -> bool {
        use WorkflowState::*;

        matches!(
            (from, to),
            // Happy path
            (Generating, Generated)
                | (Generated, Validating)
                | (Validating, PendingApproval)
                | (PendingApproval, Approved)
                | (Approved, Pushed)
                | (Pushed, Executing)
                | (Executing, Completed)

                // Rejection path
                | (PendingApproval, Rejected)

                // Expiration
                | (PendingApproval, Expired)

                // Failure paths (any active state can fail)
                | (Generating, Failed(_))
                | (Generated, Failed(_))
                | (Validating, Failed(_))
                | (Approved, Failed(_))
                | (Pushed, Failed(_))
                | (Executing, Failed(_))

                // Retry from failure
                | (Failed(_), Generating)

                // Edit loop — back to validation after edit
                | (PendingApproval, Validating)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transitions::TransitionTrigger;

    #[tokio::test]
    async fn test_playbook_lifecycle() {
        let sm = PlaybookWorkflow::new();
        let wf_id = sm.create("pb-test123", "Create a test namespace").await;

        // Happy path
        sm.transition(wf_id, WorkflowState::Generated, TransitionTrigger::Automatic, None).await.unwrap();
        sm.transition(wf_id, WorkflowState::Validating, TransitionTrigger::Automatic, None).await.unwrap();
        sm.transition(wf_id, WorkflowState::PendingApproval, TransitionTrigger::Automatic, None).await.unwrap();
        sm.transition(wf_id, WorkflowState::Approved, TransitionTrigger::Human {
            actor: "operator".to_string(),
            reason: "Looks good".to_string(),
        }, None).await.unwrap();
        sm.transition(wf_id, WorkflowState::Pushed, TransitionTrigger::Automatic, None).await.unwrap();
        sm.transition(wf_id, WorkflowState::Executing, TransitionTrigger::Automatic, None).await.unwrap();
        sm.transition(wf_id, WorkflowState::Completed, TransitionTrigger::Automatic, None).await.unwrap();

        let ctx = sm.get(wf_id).await.unwrap();
        assert_eq!(ctx.current_state, WorkflowState::Completed);
        assert_eq!(ctx.history.len(), 7);
    }

    #[tokio::test]
    async fn test_rejection() {
        let sm = PlaybookWorkflow::new();
        let wf_id = sm.create("pb-reject", "Delete production").await;

        sm.transition(wf_id, WorkflowState::Generated, TransitionTrigger::Automatic, None).await.unwrap();
        sm.transition(wf_id, WorkflowState::Validating, TransitionTrigger::Automatic, None).await.unwrap();
        sm.transition(wf_id, WorkflowState::PendingApproval, TransitionTrigger::Automatic, None).await.unwrap();
        sm.transition(wf_id, WorkflowState::Rejected, TransitionTrigger::Human {
            actor: "operator".to_string(),
            reason: "Too risky".to_string(),
        }, None).await.unwrap();

        let ctx = sm.get(wf_id).await.unwrap();
        assert_eq!(ctx.current_state, WorkflowState::Rejected);
    }

    #[tokio::test]
    async fn test_invalid_transition() {
        let sm = PlaybookWorkflow::new();
        let wf_id = sm.create("pb-invalid", "test").await;

        // Can't go directly from Generating to Completed
        let result = sm.transition(wf_id, WorkflowState::Completed, TransitionTrigger::Automatic, None).await;
        assert!(result.is_err());
    }
}

//! State transition types and error definitions

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::workflow::WorkflowState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransitionTrigger {
    /// System-initiated automatic transition
    Automatic,
    /// Human operator action
    Human { actor: String, reason: String },
    /// Internal system component
    System { component: String },
}

#[derive(Debug, thiserror::Error)]
pub enum TransitionError {
    #[error("Workflow not found: {0}")]
    WorkflowNotFound(Uuid),

    #[error("Invalid transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: WorkflowState,
        to: WorkflowState,
    },

    #[error("Workflow expired: {0}")]
    WorkflowExpired(Uuid),
}

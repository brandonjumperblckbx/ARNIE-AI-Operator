//! ARNIE State Machine — RMCP Workflow Engine
//! Tracks playbook lifecycle: generated → validated → approved → pushed → executed

pub mod workflow;
pub mod transitions;

pub use workflow::{WorkflowState, WorkflowContext, PlaybookWorkflow};
pub use transitions::{TransitionError, TransitionTrigger};

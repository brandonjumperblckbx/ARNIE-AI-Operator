//! ARNIE Reconciliation Engine
//! Monitors deployed playbook outcomes and detects drift from intended state.

pub mod drift;
pub mod correction;

pub use drift::{DriftDetector, DriftRecord, DriftType};
pub use correction::{CorrectionPlan, CorrectionAction};

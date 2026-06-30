//! Governed reconciliation — the decide-then-reconcile gate.
//!
//! The DriftDetector finds drift (a resource missing, modified, scaled, etc.). The
//! natural response is a *correction* — re-apply the expected state. But ARNIE never
//! changes the cluster without a policy decision. This module is the gate: it takes a
//! DriftRecord, frames the implied correction as a Change, asks the RMCP policy core
//! for a verdict, and returns what should happen.
//!
//!   Deny            -> block the correction (e.g. it would delete a PVC)
//!   RequireApproval -> route to the human approval gate (the default for mutations)
//!   Allow           -> safe to auto-correct
//!
//! This makes the Rust reconciliation loop a *governed* loop: it cannot apply a
//! correction the native policy core would forbid.
//!
//! Built on the RMCP engine by BLCKBX.

use crate::drift::{DriftRecord, DriftType};
use crate::policy_ffi::{Change, Decision, PolicyCore, Verdict};

/// What the reconciliation loop should do with a detected drift, after governance.
#[derive(Debug, Clone, PartialEq)]
pub enum CorrectionOutcome {
    /// Safe to apply the correction automatically.
    AutoApply,
    /// The correction must be approved by a human first.
    NeedsApproval,
    /// The correction is forbidden by policy and must not be applied.
    Blocked,
}

/// The governed decision for a single drift record.
#[derive(Debug, Clone)]
pub struct GovernedCorrection {
    pub drift_id: String,
    pub outcome: CorrectionOutcome,
    pub verdict_summary: String,
    pub action: String,   // the correction action the verdict was for
}

/// Frame the correction implied by a drift record as a policy Change.
fn correction_change(d: &DriftRecord) -> Change {
    // The corrective action depends on the kind of drift:
    //   ResourceMissing      -> re-create the resource
    //   ConfigurationDrift   -> update it back to expected
    //   UnexpectedResource   -> (would be a delete; treated cautiously)
    //   Scale/Modified       -> update
    let action = match d.drift_type {
        DriftType::ResourceMissing => "create",
        DriftType::UnexpectedResource => "delete",
        _ => "update",
    };
    Change {
        action: action.to_string(),
        kind: d.resource_kind.clone(),
        api_version: String::new(),
        name: d.resource_name.clone(),
        ns: d.namespace.clone(),
        requested_by: "reconciliation".to_string(),
    }
}

/// Gate a single drift correction through the policy core.
pub fn govern_correction(core: &PolicyCore, drift: &DriftRecord) -> GovernedCorrection {
    let change = correction_change(drift);
    let verdict: Verdict = core.evaluate(&change);
    let outcome = match verdict.decision {
        Decision::Allow => CorrectionOutcome::AutoApply,
        Decision::RequireApproval => CorrectionOutcome::NeedsApproval,
        Decision::Deny => CorrectionOutcome::Blocked,
        Decision::Unknown => CorrectionOutcome::NeedsApproval, // fail safe: never auto-apply
    };
    GovernedCorrection {
        drift_id: drift.id.clone(),
        outcome,
        verdict_summary: verdict.summary,
        action: change.action,
    }
}

/// Gate a batch of drift records. Returns one governed decision per record.
pub fn govern_all(core: &PolicyCore, drifts: &[DriftRecord]) -> Vec<GovernedCorrection> {
    drifts.iter().map(|d| govern_correction(core, d)).collect()
}

//! `epoch_processing` runner: decode pre, run one epoch sub-phase, classify
//! against the expected post. Ported from
//! `moonglass/tests/src/adapters/epoch_processing.rs` (AGPL-3.0-only; same
//! license as this crate); the reftest-only `pre_epoch`/`post_epoch` sidecar
//! check is dropped, since those files never travel on the wire.

use crate::protocol::{CaseRequest, Verdict};
use crate::runner::{decode_pre, finish};
use moonglass_core::containers::BeaconState;
use moonglass_core::error::TransitionError;

/// A single epoch sub-phase: mutate the beacon state in place, or return the
/// transition error the spec expects for an invalid vector.
type EpochPhase = fn(&mut BeaconState) -> Result<(), TransitionError>;

/// Map an epoch handler name to its `BeaconState` sub-phase, or `None` for an
/// unknown handler. Pure lookup, no filesystem access. The 18 handlers are
/// ported from `EpochHandler::process` in the cited adapter (adapter-wins on
/// the method names); `pending_deposits_churn` shares `process_pending_deposits`.
fn dispatch_for(handler: &str) -> Option<EpochPhase> {
    Some(match handler {
        "builder_pending_payments" => BeaconState::process_builder_pending_payments,
        "effective_balance_updates" => BeaconState::process_effective_balance_updates,
        "eth1_data_reset" => BeaconState::process_eth1_data_reset,
        "historical_summaries_update" => BeaconState::process_historical_summaries_update,
        "inactivity_updates" => BeaconState::process_inactivity_updates,
        "justification_and_finalization" => BeaconState::process_justification_and_finalization,
        "participation_flag_updates" => BeaconState::process_participation_flag_updates,
        "pending_consolidations" => BeaconState::process_pending_consolidations,
        "pending_deposits" | "pending_deposits_churn" => BeaconState::process_pending_deposits,
        "proposer_lookahead" => BeaconState::process_proposer_lookahead,
        "ptc_window" => BeaconState::process_ptc_window,
        "randao_mixes_reset" => BeaconState::process_randao_mixes_reset,
        "registry_updates" => BeaconState::process_registry_updates,
        "rewards_and_penalties" => BeaconState::process_rewards_and_penalties,
        "slashings" => BeaconState::process_slashings,
        "slashings_reset" => BeaconState::process_slashings_reset,
        "sync_committee_updates" => BeaconState::process_sync_committee_updates,
        _ => return None,
    })
}

/// Run one `epoch_processing` case: decode pre, run the sub-phase, classify
/// against the expected post. An unknown handler is todo before any I/O. Ported
/// from `run_epoch_case` in the cited adapter, dropping the reftest-only
/// full-epoch sidecar check. `bls_setting` is not consulted: epoch sub-phases
/// verify no signatures, so BLS-disabled vectors run identically — matching the
/// upstream adapter, which has no BLS gate here.
pub(crate) fn run(req: &CaseRequest) -> Verdict {
    // Dispatch precedes any filesystem I/O, so an unrecognised handler stays a
    // todo instead of turning a missing pre file into a bug.
    let Some(phase) = dispatch_for(&req.handler) else {
        return Verdict::fail(
            "todo",
            format!("unsupported epoch_processing handler {}", req.handler),
        );
    };

    let (pre_bytes, mut state) = match decode_pre(req, "epoch_processing") {
        Ok(pair) => pair,
        Err(v) => return v,
    };

    let result: Result<(), String> = phase(&mut state).map_err(|e| e.to_string());

    finish(result, &state, pre_bytes.len(), req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// The 18 wire handler names, one per consensus-spec-tests
    /// `epoch_processing` handler directory (`pending_deposits_churn` shares
    /// `process_pending_deposits`).
    const HANDLERS_FOR_TEST: &[&str] = &[
        "builder_pending_payments",
        "effective_balance_updates",
        "eth1_data_reset",
        "historical_summaries_update",
        "inactivity_updates",
        "justification_and_finalization",
        "participation_flag_updates",
        "pending_consolidations",
        "pending_deposits",
        "pending_deposits_churn",
        "proposer_lookahead",
        "ptc_window",
        "randao_mixes_reset",
        "registry_updates",
        "rewards_and_penalties",
        "slashings",
        "slashings_reset",
        "sync_committee_updates",
    ];

    fn req_stub(handler: &str, bls_setting: u8) -> CaseRequest {
        CaseRequest {
            runner: "epoch_processing".to_string(),
            handler: handler.to_string(),
            pre: None,
            post: None,
            bls_setting,
            blocks_count: 0,
            fork_epoch: None,
            inputs: Vec::new(),
            fork_block: None,
            execution_valid: false,
        }
    }

    #[test]
    fn unknown_epoch_handler_is_todo_before_io() {
        let mut req = req_stub("no_such_phase", 1);
        req.pre = Some(PathBuf::from("/nonexistent/pre.ssz"));
        let line = run(&req).line();
        assert!(line.starts_with("fail\ttodo\t"), "{line}");
        assert!(line.contains("no_such_phase"), "{line}");
    }

    #[test]
    fn missing_pre_is_a_bug() {
        assert!(run(&req_stub("slashings", 1)).line().starts_with("fail\tbug\t"));
    }

    #[test]
    fn bls_setting_is_ignored() {
        // epoch sub-phases verify no signatures, so bls_setting=2 is no longer a
        // todo: it runs like any other case (here, missing pre → bug), matching
        // the upstream adapter's lack of a BLS gate.
        assert!(run(&req_stub("slashings", 2)).line().starts_with("fail\tbug\t"));
    }

    #[test]
    fn every_documented_handler_dispatches() {
        for h in HANDLERS_FOR_TEST {
            assert!(dispatch_for(h).is_some(), "{h} missing from the table");
        }
    }
}

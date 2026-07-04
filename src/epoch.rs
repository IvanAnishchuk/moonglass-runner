//! `epoch_processing` runner: decode pre, run one epoch sub-phase, classify
//! against the expected post. Ported from
//! `moonglass/tests/src/adapters/epoch_processing.rs` (AGPL-3.0-only; same
//! license as this crate); the reftest-only `pre_epoch`/`post_epoch` sidecar
//! check is dropped, since those files never travel on the wire.

use crate::protocol::{CaseRequest, Verdict};
use crate::verdict::classify;
use moonglass_core::containers::BeaconState;
use moonglass_core::error::TransitionError;
use moonglass_core::ssz::{Deserialize, Serialize};

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

/// Run one `epoch_processing` case: read pre, run the sub-phase, classify
/// against the expected post. `bls_setting` == 2 is todo (no verify-off path);
/// an unknown handler is todo before any I/O. Ported from `run_epoch_case` in
/// the cited adapter, dropping the reftest-only full-epoch sidecar check.
pub(crate) fn run(req: &CaseRequest) -> Verdict {
    // `bls_setting` == 2 (BLS-disabled) has no verify-off path in moonglass-core,
    // so those cases land in the todo bucket.
    if req.bls_setting == 2 {
        return Verdict::fail("todo", "bls_setting=2 unsupported");
    }

    // Dispatch precedes any filesystem I/O, so an unrecognised handler stays a
    // todo instead of turning a missing pre file into a bug.
    let Some(phase) = dispatch_for(&req.handler) else {
        return Verdict::fail(
            "todo",
            format!("unsupported epoch_processing handler {}", req.handler),
        );
    };

    let Some(pre_path) = &req.pre else {
        return Verdict::fail("bug", "epoch_processing case without a pre state");
    };
    let pre_bytes = match std::fs::read(pre_path) {
        Ok(b) => b,
        Err(e) => return Verdict::fail("bug", format!("read pre: {e}")),
    };
    let mut state = match BeaconState::deserialize(&pre_bytes) {
        Ok(s) => s,
        Err(e) => return Verdict::fail("bug", format!("decode pre: {e:?}")),
    };

    let result: Result<(), String> = phase(&mut state).map_err(|e| e.to_string());

    // Serialize the post state only on the success path; an errored state may be
    // partial, and classify ignores got_post when result is Err.
    let mut got_post = Vec::new();
    if result.is_ok()
        && let Err(e) = state.serialize(&mut got_post)
    {
        return Verdict::fail("bug", format!("serialize post: {e}"));
    }

    let expected_post = match &req.post {
        Some(p) => match std::fs::read(p) {
            Ok(b) => Some(b),
            Err(e) => return Verdict::fail("bug", format!("read post: {e}")),
        },
        None => None,
    };

    classify(result, &got_post, expected_post.as_deref())
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
    fn bls_disabled_is_todo() {
        assert!(run(&req_stub("slashings", 2)).line().starts_with("fail\ttodo\t"));
    }

    #[test]
    fn every_documented_handler_dispatches() {
        for h in HANDLERS_FOR_TEST {
            assert!(dispatch_for(h).is_some(), "{h} missing from the table");
        }
    }
}

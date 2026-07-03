//! `operations` runner: decode pre-state + one operation, apply the matching
//! `BeaconState` method, classify against the expected post (`EthCL`'s honest
//! verdict model: a faithful rejection of an invalid vector is a pass).

use crate::protocol::{CaseRequest, Verdict};
use moonglass_core::containers::{
    Attestation, AttesterSlashing, BeaconBlock, BeaconState, BuilderDepositRequest,
    BuilderExitRequest, ConsolidationRequest, DepositRequest, PayloadAttestation, ProposerSlashing,
    SignedBLSToExecutionChange, SignedExecutionPayloadBid, SignedVoluntaryExit, SyncAggregate,
    WithdrawalRequest,
};
use moonglass_core::error::TransitionError;
use moonglass_core::ssz::{Deserialize, Serialize};

/// Pure verdict table. `result` is the transition outcome (error stringified),
/// `got_post` the canonical SSZ of the resulting state, `expected_post` the
/// expected-post file bytes (None = the vector is invalid, a reject is expected).
pub fn classify(
    result: Result<(), String>,
    got_post: Vec<u8>,
    expected_post: Option<Vec<u8>>,
) -> Verdict {
    match (result, expected_post) {
        (Ok(()), Some(exp)) if got_post == exp => Verdict::pass("ok", ""),
        (Ok(()), Some(exp)) => {
            let detail = if got_post.len() != exp.len() {
                format!(
                    "post differs: got {} B, want {} B",
                    got_post.len(),
                    exp.len()
                )
            } else {
                let offset = got_post
                    .iter()
                    .zip(exp.iter())
                    .position(|(a, b)| a != b)
                    .unwrap_or(0);
                format!(
                    "post differs: got {} B, want {} B, first diff at byte {}",
                    got_post.len(),
                    exp.len(),
                    offset
                )
            };
            Verdict::fail("mismatch", detail)
        }
        (Err(e), Some(_)) => Verdict::fail("reject-valid", e),
        (Err(e), None) => Verdict::pass("reject", e),
        (Ok(()), None) => Verdict::fail("accept-invalid", "ran clean, reject expected"),
    }
}

/// Decode a single SSZ operation of type `T` from `op_bytes` then call
/// `apply(state, &op)`, converting both error kinds to `String`.
fn decode_and_apply<T>(
    state: &mut BeaconState,
    op_bytes: &[u8],
    apply: fn(&mut BeaconState, &T) -> Result<(), TransitionError>,
) -> Result<(), String>
where
    T: Deserialize,
{
    let op = T::deserialize(op_bytes).map_err(|e| format!("decode op: {e:?}"))?;
    apply(state, &op).map_err(|e| e.to_string())
}

/// How a handler consumes the case: with an SSZ-encoded input object, or purely
/// from the pre-state (no extra input bytes needed).
enum Dispatch {
    Input(fn(&mut BeaconState, &[u8]) -> Result<(), String>),
    StateOnly(fn(&mut BeaconState) -> Result<(), String>),
}

/// The 17 wire handlers, ported verbatim from
/// `moonglass/tests/src/adapters/operations.rs` (AGPL-3.0-only; same license
/// as this crate). Container types and `BeaconState` method names match the
/// adapter's statics (lines 197–261 of that file).
/// Returns `None` for an unknown handler — never touches the filesystem.
fn dispatch_for(handler: &str) -> Option<Dispatch> {
    Some(match handler {
        "attestation" => Dispatch::Input(|s, b| {
            decode_and_apply::<Attestation>(s, b, BeaconState::process_attestation)
        }),
        "attester_slashing" => Dispatch::Input(|s, b| {
            decode_and_apply::<AttesterSlashing>(s, b, BeaconState::process_attester_slashing)
        }),
        "proposer_slashing" => Dispatch::Input(|s, b| {
            decode_and_apply::<ProposerSlashing>(s, b, BeaconState::process_proposer_slashing)
        }),
        // voluntary_exit and voluntary_exit_churn both use SignedVoluntaryExit /
        // process_voluntary_exit (adapter line 114).
        "voluntary_exit" | "voluntary_exit_churn" => Dispatch::Input(|s, b| {
            decode_and_apply::<SignedVoluntaryExit>(s, b, BeaconState::process_voluntary_exit)
        }),
        "bls_to_execution_change" => Dispatch::Input(|s, b| {
            decode_and_apply::<SignedBLSToExecutionChange>(
                s,
                b,
                BeaconState::process_bls_to_execution_change,
            )
        }),
        "sync_aggregate" => Dispatch::Input(|s, b| {
            decode_and_apply::<SyncAggregate>(s, b, BeaconState::process_sync_aggregate)
        }),
        "block_header" => Dispatch::Input(|s, b| {
            decode_and_apply::<BeaconBlock>(s, b, BeaconState::process_block_header)
        }),
        "payload_attestation" => Dispatch::Input(|s, b| {
            decode_and_apply::<PayloadAttestation>(s, b, BeaconState::process_payload_attestation)
        }),
        "deposit_request" => Dispatch::Input(|s, b| {
            decode_and_apply::<DepositRequest>(s, b, BeaconState::process_deposit_request)
        }),
        "builder_deposit_request" => Dispatch::Input(|s, b| {
            decode_and_apply::<BuilderDepositRequest>(
                s,
                b,
                BeaconState::process_builder_deposit_request,
            )
        }),
        "builder_exit_request" => Dispatch::Input(|s, b| {
            decode_and_apply::<BuilderExitRequest>(
                s,
                b,
                BeaconState::process_builder_exit_request,
            )
        }),
        "withdrawal_request" => Dispatch::Input(|s, b| {
            decode_and_apply::<WithdrawalRequest>(s, b, BeaconState::process_withdrawal_request)
        }),
        "consolidation_request" => Dispatch::Input(|s, b| {
            decode_and_apply::<ConsolidationRequest>(
                s,
                b,
                BeaconState::process_consolidation_request,
            )
        }),
        "execution_payload_bid" => Dispatch::Input(|s, b| {
            decode_and_apply::<SignedExecutionPayloadBid>(
                s,
                b,
                BeaconState::process_execution_payload_bid,
            )
        }),
        "parent_execution_payload" => Dispatch::Input(|s, b| {
            decode_and_apply::<BeaconBlock>(s, b, BeaconState::process_parent_execution_payload)
        }),
        "withdrawals" => {
            Dispatch::StateOnly(|state| state.process_withdrawals().map_err(|e| e.to_string()))
        }
        _ => return None,
    })
}

/// Run one `operations` case: read pre-state + operation, dispatch, classify.
///
/// Ported from `moonglass/tests/src/adapters/operations.rs` (AGPL-3.0-only;
/// same license as this crate). `bls_setting` == 2 (BLS-disabled) has no
/// verify-off path in moonglass-core, so those cases are marked todo rather
/// than scored as false failures.
pub fn run(req: &CaseRequest) -> Verdict {
    // `bls_setting` == 2 means BLS-disabled execution; moonglass-core has no
    // verify-off path for any handler, so push to the xfail/todo bucket.
    if req.bls_setting == 2 {
        return Verdict::fail("todo", "bls_setting=2 unsupported");
    }

    // Unknown-handler check comes before any filesystem I/O so that an
    // unrecognised handler never touches pre/op files and lands cleanly
    // in the todo bucket rather than the bug bucket.
    let Some(d) = dispatch_for(&req.handler) else {
        return Verdict::fail(
            "todo",
            format!("unsupported operations handler {}", req.handler),
        );
    };

    let Some(pre_path) = &req.pre else {
        return Verdict::fail("bug", "operations case without a pre state");
    };
    let pre_bytes = match std::fs::read(pre_path) {
        Ok(b) => b,
        Err(e) => return Verdict::fail("bug", format!("read pre: {e}")),
    };
    let mut state = match BeaconState::deserialize(&pre_bytes) {
        Ok(s) => s,
        Err(e) => return Verdict::fail("bug", format!("decode pre: {e:?}")),
    };

    // Read the operation bytes only for input-based handlers; state-only
    // handlers (withdrawals) never touch req.inputs.
    let result: Result<(), String> = match d {
        Dispatch::Input(f) => {
            let op_bytes = match req.inputs.first().map(std::fs::read) {
                Some(Ok(b)) => b,
                Some(Err(e)) => return Verdict::fail("bug", format!("read op: {e}")),
                None => Vec::new(),
            };
            f(&mut state, &op_bytes)
        }
        Dispatch::StateOnly(f) => f(&mut state),
    };

    // Only serialize the post state on the success path; an errored state may
    // be in a partial/inconsistent state and got_post is unused by classify
    // when result is Err.
    let mut got_post = Vec::new();
    if result.is_ok() {
        if let Err(e) = state.serialize(&mut got_post) {
            return Verdict::fail("bug", format!("serialize post: {e}"));
        }
    }

    let expected_post = match &req.post {
        Some(p) => match std::fs::read(p) {
            Ok(b) => Some(b),
            Err(e) => return Verdict::fail("bug", format!("read post: {e}")),
        },
        None => None,
    };

    classify(result, got_post, expected_post)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn req_stub(handler: &str, bls_setting: u8) -> CaseRequest {
        CaseRequest {
            runner: "operations".to_string(),
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

    // --- classify tests ---

    #[test]
    fn valid_vector_with_matching_post_passes() {
        let v = classify(Ok(()), b"abc".to_vec(), Some(b"abc".to_vec()));
        assert_eq!(v.line(), "pass\tok\t");
    }

    #[test]
    fn valid_vector_with_differing_post_fails_as_mismatch() {
        let v = classify(Ok(()), b"abc".to_vec(), Some(b"abd".to_vec()));
        assert!(v.line().starts_with("fail\tmismatch\t"));
        // Equal lengths → first-diff offset is included in the detail.
        assert!(v.line().contains("first diff at byte 2"));
    }

    #[test]
    fn mismatch_detail_shows_lengths_when_different() {
        let v = classify(Ok(()), b"short".to_vec(), Some(b"longer_expected".to_vec()));
        let line = v.line();
        assert!(line.starts_with("fail\tmismatch\t"));
        assert!(line.contains("got 5 B"));
        assert!(line.contains("want 15 B"));
        assert!(!line.contains("first diff at byte"));
    }

    #[test]
    fn invalid_vector_rejected_passes() {
        let v = classify(Err("bad sig".to_string()), Vec::new(), None);
        assert!(v.line().starts_with("pass\treject\t"));
        assert!(v.line().ends_with("bad sig"));
    }

    #[test]
    fn invalid_vector_accepted_fails() {
        let v = classify(Ok(()), b"abc".to_vec(), None);
        assert!(v.line().starts_with("fail\taccept-invalid\t"));
    }

    #[test]
    fn valid_vector_rejected_fails() {
        let v = classify(Err("spurious".to_string()), Vec::new(), Some(b"abc".to_vec()));
        assert!(v.line().starts_with("fail\treject-valid\t"));
        assert!(v.line().ends_with("spurious"));
    }

    // --- run() unit tests (no fixture files needed) ---

    #[test]
    fn bls_setting_2_is_a_todo() {
        let req = req_stub("attestation", 2);
        assert!(run(&req).line().starts_with("fail\ttodo\t"));
    }

    #[test]
    fn missing_pre_state_is_a_bug() {
        // Known handler, valid bls_setting, but pre: None → bug bucket.
        let req = req_stub("attestation", 1);
        assert!(run(&req).line().starts_with("fail\tbug\t"));
    }

    #[test]
    fn unsupported_handler_is_a_todo_without_touching_inputs() {
        // Unknown handler with a non-existent pre path: the dispatch_for lookup
        // happens before any filesystem I/O, so the missing file is never opened
        // and the verdict is still todo (not bug).
        let mut req = req_stub("no_such_handler", 1);
        req.pre = Some(PathBuf::from("/nonexistent/pre.ssz"));
        let line = run(&req).line();
        assert!(line.starts_with("fail\ttodo\t"));
        assert!(line.contains("no_such_handler"));
    }
}

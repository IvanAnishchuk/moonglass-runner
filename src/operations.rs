//! `operations` runner: decode pre-state + one operation, apply the matching
//! `BeaconState` method, classify against the expected post (EthCL's honest
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
        (Ok(()), Some(_)) => Verdict::fail("mismatch", "post state differs"),
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

/// Run one `operations` case: read pre-state + operation, dispatch, classify.
///
/// Ported from `moonglass/tests/src/adapters/operations.rs` (AGPL-3.0-only;
/// same license as this crate). bls_setting == 2 (BLS-disabled) has no
/// verify-off path in moonglass-core, so those cases are marked todo rather
/// than scored as false failures.
pub fn run(req: &CaseRequest) -> Verdict {
    // bls_setting == 2 means BLS-disabled execution; moonglass-core has no
    // verify-off path for any handler, so push to the xfail/todo bucket.
    if req.bls_setting == 2 {
        return Verdict::fail("todo", "bls_setting=2 unsupported");
    }

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

    // Input-based handlers read op_bytes from req.inputs[0].
    // State-only handlers (withdrawals) ignore op_bytes entirely.
    let op_bytes = match req.inputs.first().map(std::fs::read) {
        Some(Ok(b)) => b,
        Some(Err(e)) => return Verdict::fail("bug", format!("read op: {e}")),
        None => Vec::new(),
    };

    // Dispatch table ported verbatim from moonglass/tests/src/adapters/operations.rs.
    // Container types and BeaconState method names match the adapter's statics
    // (lines 197–261 of that file). voluntary_exit and voluntary_exit_churn both
    // use SignedVoluntaryExit / process_voluntary_exit (adapter line 114).
    let result: Result<(), String> = match req.handler.as_str() {
        "attestation" => decode_and_apply::<Attestation>(
            &mut state,
            &op_bytes,
            BeaconState::process_attestation,
        ),
        "attester_slashing" => decode_and_apply::<AttesterSlashing>(
            &mut state,
            &op_bytes,
            BeaconState::process_attester_slashing,
        ),
        "proposer_slashing" => decode_and_apply::<ProposerSlashing>(
            &mut state,
            &op_bytes,
            BeaconState::process_proposer_slashing,
        ),
        "voluntary_exit" | "voluntary_exit_churn" => decode_and_apply::<SignedVoluntaryExit>(
            &mut state,
            &op_bytes,
            BeaconState::process_voluntary_exit,
        ),
        "bls_to_execution_change" => decode_and_apply::<SignedBLSToExecutionChange>(
            &mut state,
            &op_bytes,
            BeaconState::process_bls_to_execution_change,
        ),
        "sync_aggregate" => decode_and_apply::<SyncAggregate>(
            &mut state,
            &op_bytes,
            BeaconState::process_sync_aggregate,
        ),
        "block_header" => decode_and_apply::<BeaconBlock>(
            &mut state,
            &op_bytes,
            BeaconState::process_block_header,
        ),
        "payload_attestation" => decode_and_apply::<PayloadAttestation>(
            &mut state,
            &op_bytes,
            BeaconState::process_payload_attestation,
        ),
        "deposit_request" => decode_and_apply::<DepositRequest>(
            &mut state,
            &op_bytes,
            BeaconState::process_deposit_request,
        ),
        "builder_deposit_request" => decode_and_apply::<BuilderDepositRequest>(
            &mut state,
            &op_bytes,
            BeaconState::process_builder_deposit_request,
        ),
        "builder_exit_request" => decode_and_apply::<BuilderExitRequest>(
            &mut state,
            &op_bytes,
            BeaconState::process_builder_exit_request,
        ),
        "withdrawal_request" => decode_and_apply::<WithdrawalRequest>(
            &mut state,
            &op_bytes,
            BeaconState::process_withdrawal_request,
        ),
        "consolidation_request" => decode_and_apply::<ConsolidationRequest>(
            &mut state,
            &op_bytes,
            BeaconState::process_consolidation_request,
        ),
        "execution_payload_bid" => decode_and_apply::<SignedExecutionPayloadBid>(
            &mut state,
            &op_bytes,
            BeaconState::process_execution_payload_bid,
        ),
        "parent_execution_payload" => decode_and_apply::<BeaconBlock>(
            &mut state,
            &op_bytes,
            BeaconState::process_parent_execution_payload,
        ),
        "withdrawals" => state.process_withdrawals().map_err(|e| e.to_string()),
        other => return Verdict::fail("todo", format!("unsupported operations handler {other}")),
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

    #[test]
    fn valid_vector_with_matching_post_passes() {
        let v = classify(Ok(()), b"abc".to_vec(), Some(b"abc".to_vec()));
        assert_eq!(v.line(), "pass\tok\t");
    }

    #[test]
    fn valid_vector_with_differing_post_fails_as_mismatch() {
        let v = classify(Ok(()), b"abc".to_vec(), Some(b"abd".to_vec()));
        assert!(v.line().starts_with("fail\tmismatch\t"));
    }

    #[test]
    fn invalid_vector_rejected_passes() {
        let v = classify(Err("bad sig".to_string()), Vec::new(), None);
        assert!(v.line().starts_with("pass\treject\t"));
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
    }
}

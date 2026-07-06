//! Shared state-transition runner harness. `operations` and `epoch_processing`
//! (and the state-transition runners still to come) all read a pre-state, run
//! one handler against it, then serialize and compare the post-state. This
//! module owns that common prologue ([`decode_pre`]) and epilogue ([`finish`]);
//! the per-runner dispatch table, handler invocation, and BLS-verification
//! policy stay in each runner module, where they legitimately differ.

use crate::protocol::{CaseRequest, Verdict};
use crate::verdict::classify;
use moonglass_core::containers::BeaconState;
use moonglass_core::ssz::{Deserialize, Serialize};
use std::path::Path;

/// Read one input file for a case, mapping an I/O error to a `bug` verdict.
/// `label` names the file in the detail (e.g. `pre`, `slots_count`,
/// `block <path>`), the one place the family's read-and-blame-a-bug idiom lives.
pub(crate) fn read_input(path: &Path, label: &str) -> Result<Vec<u8>, Verdict> {
    std::fs::read(path).map_err(|e| Verdict::fail("bug", format!("read {label}: {e}")))
}

/// Read and decode the pre-state for one case. Returns the raw pre bytes (a size
/// hint for the post-state buffer) and the decoded [`BeaconState`], or a `bug`
/// verdict when the case carries no pre file, the file is unreadable, or it
/// fails to decode. `runner` names the runner for the missing-pre detail.
pub(crate) fn decode_pre(
    req: &CaseRequest,
    runner: &str,
) -> Result<(Vec<u8>, BeaconState), Verdict> {
    let Some(pre_path) = &req.pre else {
        return Err(Verdict::fail("bug", format!("{runner} case without a pre state")));
    };
    let pre_bytes = read_input(pre_path, "pre")?;
    match BeaconState::deserialize(&pre_bytes) {
        Ok(state) => Ok((pre_bytes, state)),
        Err(e) => Err(Verdict::fail("bug", format!("decode pre: {e:?}"))),
    }
}

/// Serialize the post-state on the success path, read the expected-post file,
/// and classify. `result` is the transition outcome (error stringified); an
/// errored state is never serialized (it may be partial, and `classify` ignores
/// the post bytes on the Err path). `cap` sizes the post-state buffer up front;
/// pass the pre-state byte length, since a post-state is roughly its size.
pub(crate) fn finish(
    result: Result<(), String>,
    state: &BeaconState,
    cap: usize,
    req: &CaseRequest,
) -> Verdict {
    // Serialize the post state only on the success path; an errored state may be
    // partial, and classify ignores got_post when result is Err.
    let mut got_post = Vec::with_capacity(cap);
    if result.is_ok()
        && let Err(e) = state.serialize(&mut got_post)
    {
        return Verdict::fail("bug", format!("serialize post: {e}"));
    }

    let expected_post = match req.post.as_ref().map(std::fs::read).transpose() {
        Ok(b) => b,
        Err(e) => return Verdict::fail("bug", format!("read post: {e}")),
    };

    classify(result, &got_post, expected_post.as_deref())
}

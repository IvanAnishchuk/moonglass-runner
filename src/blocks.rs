//! `blocks` runner: the sanity / finality / random family. Apply a sequence of
//! signed blocks (`sanity/blocks`, `finality`, `random`) or advance the state by
//! a slot count (`sanity/slots`), then classify against the expected post.
//!
//! Ported from `moonglass/tests/src/adapters/sanity.rs` (AGPL-3.0-only; same
//! license as this crate). The reftest-only `meta.yaml` / `slots.yaml` reads are
//! replaced by the pre-chewed wire: blocks arrive as already-decompressed,
//! numerically-ordered `inputs`, and the slot count as a big-endian
//! minimal-length `slots_count.bin` (the consensus-diff harness's `vectors.py`
//! writes `n.to_bytes(max(1, ceil(bits/8)), "big")`).

use crate::protocol::{CaseRequest, Verdict};
use crate::runner::{decode_pre, finish};
use moonglass_core::containers::{BeaconState, SignedBeaconBlock};
use moonglass_core::primitives::Slot;
use moonglass_core::ssz::Deserialize;

/// The outcome of one shape driver: `Err(Verdict)` is a harness bug that
/// short-circuits (the adapter's `StateTransition::HarnessError` — a fixture it
/// could not read or decode); `Ok(inner)` is the transition result to hand to
/// `classify` (the adapter's `Applied`, stringified).
type Driven = Result<Result<(), String>, Verdict>;

/// The two case shapes the sanity family splits into.
#[derive(Clone, Copy)]
enum Shape {
    /// Apply a sequence of signed blocks (`sanity/blocks`, `finality`, `random`).
    Blocks,
    /// Advance the state by a slot count (`sanity/slots`).
    Slots,
}

/// Route a `(runner, handler)` pair to its case shape, or `None` for an
/// unsupported sanity handler (todo). `finality` and `random` are blocks-shaped
/// whatever their single handler, matching the adapter's three `CaseRunner`
/// impls that all funnel into one `run_shared`.
fn shape_for(runner: &str, handler: &str) -> Option<Shape> {
    match (runner, handler) {
        ("sanity", "blocks") | ("finality" | "random", _) => Some(Shape::Blocks),
        ("sanity", "slots") => Some(Shape::Slots),
        _ => None,
    }
}

/// Decode a big-endian, minimal-length slot count (wire: `slots_count.bin`, ≥1
/// byte and ≤8 for a `u64`).
fn decode_slots_count(bytes: &[u8]) -> Result<u64, String> {
    if bytes.is_empty() || bytes.len() > 8 {
        return Err(format!("slots blob must be 1..=8 bytes, got {}", bytes.len()));
    }
    let mut v: u64 = 0;
    for &b in bytes {
        v = (v << 8) | u64::from(b);
    }
    Ok(v)
}

/// Apply each `inputs` block in order, stopping at the first transition error.
/// The loop is driven by `inputs` (already numerically ordered by the harness),
/// not `blocks_count`; the two agree on every fixture the harness emits.
fn apply_blocks(state: &mut BeaconState, req: &CaseRequest) -> Driven {
    for path in &req.inputs {
        let bytes = std::fs::read(path)
            .map_err(|e| Verdict::fail("bug", format!("read block {}: {e}", path.display())))?;
        let block = SignedBeaconBlock::deserialize(&bytes)
            .map_err(|e| Verdict::fail("bug", format!("decode block {}: {e:?}", path.display())))?;
        if let Err(e) = state.state_transition(&block) {
            return Ok(Err(e.to_string()));
        }
    }
    Ok(Ok(()))
}

/// Advance the state by the slot count in the case's single input blob. Slot
/// arithmetic follows the adapter: a `u64` overflow on `current + advance` is a
/// harness bug, not a transition error.
fn apply_slots(state: &mut BeaconState, req: &CaseRequest) -> Driven {
    // A slots case carries exactly one `slots_count` blob; zero or more than one
    // is an inconsistent request (bug), not a case we guess our way through.
    let [path] = req.inputs.as_slice() else {
        return Err(Verdict::fail(
            "bug",
            format!("sanity/slots expects one slots_count input, got {}", req.inputs.len()),
        ));
    };
    let bytes = std::fs::read(path)
        .map_err(|e| Verdict::fail("bug", format!("read slots_count: {e}")))?;
    let advance = decode_slots_count(&bytes).map_err(|e| Verdict::fail("bug", e))?;
    let Some(target) = state.slot.0.checked_add(advance) else {
        return Err(Verdict::fail(
            "bug",
            format!("slot {} + {advance} overflows u64", state.slot.0),
        ));
    };
    Ok(state.process_slots(Slot::new(target)).map_err(|e| e.to_string()))
}

/// Run one sanity / finality / random case: gate BLS-disabled vectors, route to
/// the blocks or slots driver, decode the pre-state, apply, and classify against
/// the expected post.
///
/// `bls_setting` == 2 (BLS-disabled) has no verify-off path in moonglass-core —
/// block application always verifies signatures — so those cases are todo, the
/// same gate `operations::run` applies. Slots cases verify no signatures, but the
/// gloas corpus carries no `bls_setting: 2` slots case, so the shared gate costs
/// no coverage and keeps the family consistent with `operations`.
pub(crate) fn run(req: &CaseRequest) -> Verdict {
    if req.bls_setting == 2 {
        return Verdict::fail("todo", "bls_setting=2 unsupported");
    }

    // Route before any filesystem I/O: an unsupported sanity handler resolves to
    // todo without opening its (possibly missing) pre file.
    let Some(shape) = shape_for(&req.runner, &req.handler) else {
        return Verdict::fail(
            "todo",
            format!("unsupported {} handler {}", req.runner, req.handler),
        );
    };

    // A blocks-shaped case must carry exactly as many block inputs as its
    // field-6 `blocks_count`; a disagreement is an internally inconsistent
    // request we cannot run faithfully — applying whatever inputs happened to
    // arrive could silently false-pass a differential case — so it is a bug,
    // surfaced before any file I/O. Slots cases legitimately carry
    // `blocks_count == 0` alongside their single input, so this guard is
    // blocks-shaped only (the slots driver checks its own arity).
    if matches!(shape, Shape::Blocks) && req.blocks_count != req.inputs.len() {
        return Verdict::fail(
            "bug",
            format!("blocks_count {} != {} block inputs", req.blocks_count, req.inputs.len()),
        );
    }

    let (pre_bytes, mut state) = match decode_pre(req, &req.runner) {
        Ok(pair) => pair,
        Err(v) => return v,
    };

    let driven = match shape {
        Shape::Blocks => apply_blocks(&mut state, req),
        Shape::Slots => apply_slots(&mut state, req),
    };
    match driven {
        Ok(result) => finish(result, &state, pre_bytes.len(), req),
        Err(bug) => bug,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture-free `CaseRequest` for the routing / gate tests: no pre, no
    /// post, no inputs, so a dispatched case bottoms out at the missing-pre bug.
    fn req_stub_runner(runner: &str, handler: &str, bls_setting: u8) -> CaseRequest {
        CaseRequest {
            runner: runner.to_string(),
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
    fn slots_count_decodes_big_endian_minimal() {
        assert_eq!(decode_slots_count(&[0x01, 0x2c]).unwrap(), 300);
        assert_eq!(decode_slots_count(&[0x00]).unwrap(), 0);
        assert!(decode_slots_count(&[]).is_err());
        assert!(decode_slots_count(&[0u8; 9]).is_err()); // > u64
    }

    #[test]
    fn bls_disabled_is_todo() {
        assert!(run(&req_stub_runner("sanity", "blocks", 2)).line().starts_with("fail\ttodo\t"));
    }

    #[test]
    fn unknown_handler_is_todo() {
        assert!(run(&req_stub_runner("sanity", "shuffle", 1)).line().starts_with("fail\ttodo\t"));
    }

    #[test]
    fn blocks_count_mismatch_is_a_bug() {
        // A blocks-shaped request whose field-6 count disagrees with the block
        // inputs it carries is inconsistent: a bug, caught before any I/O.
        let mut req = req_stub_runner("sanity", "blocks", 1);
        req.blocks_count = 2; // claims two blocks, carries none
        let line = run(&req).line();
        assert!(line.starts_with("fail\tbug\t"), "{line}");
        assert!(line.contains("blocks_count"), "{line}");
    }

    #[test]
    fn finality_and_random_route_to_blocks() {
        // Both runners are blocks-shaped; a missing pre must be a bug (i.e. they
        // dispatched), not a todo.
        for r in ["finality", "random"] {
            let mut req = req_stub_runner(r, "finality", 1);
            req.handler = if r == "random" { "random".into() } else { "finality".into() };
            assert!(run(&req).line().starts_with("fail\tbug\t"), "{r}");
        }
    }
}

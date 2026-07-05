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
use crate::runner::{decode_pre, finish, read_input};
use moonglass_core::constants::SLOTS_PER_HISTORICAL_ROOT;
use moonglass_core::containers::{BeaconState, SignedBeaconBlock};
use moonglass_core::primitives::Slot;
use moonglass_core::ssz::Deserialize;

/// The outcome of one shape driver: `Err(Verdict)` is a harness bug that
/// short-circuits (the adapter's `StateTransition::HarnessError`, a fixture it
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
/// unsupported handler (todo). Each of `finality` and `random` pins to its one
/// real handler name, matching the adapter's three `CaseRunner` impls that all
/// funnel into one `run_shared`.
fn shape_for(runner: &str, handler: &str) -> Option<Shape> {
    match (runner, handler) {
        ("sanity", "blocks") | ("finality", "finality") | ("random", "random") => {
            Some(Shape::Blocks)
        }
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
    if bytes.len() > 1 && bytes[0] == 0 {
        return Err("slots blob must use minimal big-endian encoding".to_string());
    }
    let mut v: u64 = 0;
    for &b in bytes {
        v = (v << 8) | u64::from(b);
    }
    Ok(v)
}

/// Upper bound on a `sanity/slots` advance. The largest legitimate advance in the
/// corpus is `historical_accumulator`, which advances `SLOTS_PER_HISTORICAL_ROOT`
/// (64 minimal / 8192 mainnet), so this tracks the active preset with 2× headroom
/// — still refusing a runaway or hostile count before it livelocks the
/// one-slot-at-a-time `process_slots` loop. A fixed literal here silently rejected
/// the mainnet `historical_accumulator` (8192 exceeded the old 4096).
const MAX_SLOTS_ADVANCE: u64 = SLOTS_PER_HISTORICAL_ROOT as u64 * 2;

/// Sanity-check a decoded slot advance. 0 cannot run (`process_slots` requires a
/// strictly-later slot, so a 0 advance would be scored as a false `reject-valid`)
/// and an absurd count would livelock, so the advance must sit in
/// `1..=MAX_SLOTS_ADVANCE`.
fn check_slots_advance(advance: u64) -> Result<(), String> {
    if advance == 0 || advance > MAX_SLOTS_ADVANCE {
        return Err(format!("slots advance {advance} outside the sane range 1..={MAX_SLOTS_ADVANCE}"));
    }
    Ok(())
}

/// Apply each `inputs` block in order, stopping at the first transition error.
/// The loop iterates `inputs` (already numerically ordered by the harness); the
/// separate `blocks_count` field only guards arity, and the two agree on every
/// fixture the harness emits.
fn apply_blocks(state: &mut BeaconState, req: &CaseRequest) -> Driven {
    // Blocks apply in wire order (the harness delivers them numerically sorted).
    // A mis-ordered sequence can't pass silently: state_transition advances to
    // each block's slot and requires it strictly after the current state, so an
    // out-of-order block rejects rather than producing a wrong post.
    for path in &req.inputs {
        let bytes = read_input(path, &format!("block {}", path.display()))?;
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
/// harness bug (the transition never runs).
fn apply_slots(state: &mut BeaconState, req: &CaseRequest) -> Driven {
    // A slots case carries exactly one `slots_count` blob; zero or more than one
    // is an inconsistent request, so the driver rejects it as a bug.
    let [path] = req.inputs.as_slice() else {
        return Err(Verdict::fail(
            "bug",
            format!("sanity/slots expects one slots_count input, got {}", req.inputs.len()),
        ));
    };
    let bytes = read_input(path, "slots_count")?;
    let advance = decode_slots_count(&bytes).map_err(|e| Verdict::fail("bug", e))?;
    check_slots_advance(advance).map_err(|e| Verdict::fail("bug", e))?;
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
/// `bls_setting` == 2 (BLS-disabled) has no verify-off path in moonglass-core,
/// where block application always verifies signatures, so those cases are todo,
/// the same gate `operations::run` applies. Slots cases verify no signatures,
/// but the gloas corpus carries no `bls_setting: 2` slots case, so the shared
/// gate costs no coverage and keeps the family consistent with `operations`.
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
    // field-6 `blocks_count`. A disagreement is an internally inconsistent
    // request we cannot run faithfully: applying whatever inputs happened to
    // arrive could silently false-pass a differential case, so it is a bug,
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

    // TODO(ivan-epf-research#42): these cover routing and the gate checks only;
    // apply_blocks/apply_slots -> process_slots/state_transition -> classify (the
    // verdict-producing path) is exercised only by the consensus-diff differential
    // sweep, not by any in-crate test. Add a fixture-backed apply-path test.

    #[test]
    fn slots_count_decodes_big_endian_minimal() {
        assert_eq!(decode_slots_count(&[0x01, 0x2c]).unwrap(), 300);
        assert_eq!(decode_slots_count(&[0xff]).unwrap(), 255); // single non-minimal-looking byte
        assert_eq!(decode_slots_count(&[0xff; 8]).unwrap(), u64::MAX); // 8-byte upper boundary
        assert_eq!(decode_slots_count(&[0x00]).unwrap(), 0);
        assert!(decode_slots_count(&[]).is_err()); // empty blob
        assert!(decode_slots_count(&[0u8; 9]).is_err()); // 9 bytes exceeds the u64 width
        assert!(decode_slots_count(&[0x00, 0x01]).is_err()); // non-minimal leading zero
    }

    #[test]
    fn slots_advance_range_rejects_zero_and_absurd() {
        assert!(check_slots_advance(0).is_err()); // no-op advance can't run
        assert!(check_slots_advance(1).is_ok());
        // historical_accumulator, the largest legitimate advance, scales with the
        // preset (64 minimal / 8192 mainnet) and must be accepted under either —
        // the regression a fixed 4096 cap silently rejected on mainnet.
        assert!(check_slots_advance(SLOTS_PER_HISTORICAL_ROOT as u64).is_ok());
        assert!(check_slots_advance(MAX_SLOTS_ADVANCE).is_ok());
        assert!(check_slots_advance(MAX_SLOTS_ADVANCE + 1).is_err());
    }

    #[test]
    fn bls_disabled_is_todo() {
        assert!(run(&CaseRequest::stub("sanity", "blocks", 2)).line().starts_with("fail\ttodo\t"));
    }

    #[test]
    fn unknown_handler_is_todo() {
        assert!(run(&CaseRequest::stub("sanity", "shuffle", 1)).line().starts_with("fail\ttodo\t"));
    }

    #[test]
    fn blocks_count_mismatch_is_a_bug() {
        // A blocks-shaped request whose field-6 count disagrees with the block
        // inputs it carries is inconsistent: a bug, caught before any I/O.
        let mut req = CaseRequest::stub("sanity", "blocks", 1);
        req.blocks_count = 2; // claims two blocks, carries none
        let line = run(&req).line();
        assert!(line.starts_with("fail\tbug\t"), "{line}");
        assert!(line.contains("blocks_count"), "{line}");
    }

    #[test]
    fn finality_and_random_route_to_blocks() {
        // Prove the Blocks route (not Slots) resolved: a blocks_count that disagrees
        // with the (empty) inputs trips the Blocks-only arity guard — a bug that
        // names blocks_count, and one the Slots shape never produces. The missing-pre
        // bug alone can't tell the shapes apart, since both hit decode_pre.
        for (runner, handler) in [("finality", "finality"), ("random", "random")] {
            let mut req = CaseRequest::stub(runner, handler, 1);
            req.blocks_count = 1; // claims one block, carries none
            let line = run(&req).line();
            assert!(line.starts_with("fail\tbug\t"), "{runner}: {line}");
            assert!(line.contains("blocks_count"), "{runner}: {line}");
        }
    }

    #[test]
    fn finality_random_reject_unexpected_handler() {
        // The routing table pins each runner to its one real handler name, so a
        // stray or future handler resolves to todo (the blocks route needs the
        // exact name).
        assert!(run(&CaseRequest::stub("finality", "slots", 1)).line().starts_with("fail\ttodo\t"));
        assert!(run(&CaseRequest::stub("random", "blocks", 1)).line().starts_with("fail\ttodo\t"));
    }
}

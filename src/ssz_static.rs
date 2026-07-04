//! `ssz_static` runner: decode the container, round-trip the bytes, compare
//! the hash-tree-root. Ported from `moonglass/tests/src/adapters/ssz_static.rs`
//! (AGPL-3.0-only; same license as this crate) with the vector loading dropped.
//! The wire delivers decompressed bytes and the expected root directly.

use crate::protocol::{SszStaticRequest, Verdict};
use crate::verdict::byte_diff_detail;
use moonglass_core::containers::{
    AggregateAndProof, Attestation, AttestationData, AttesterSlashing, BLSToExecutionChange,
    BeaconBlock, BeaconBlockBody, BeaconBlockHeader, BeaconState, Builder, BuilderDepositRequest,
    BuilderExitRequest, BuilderPendingPayment, BuilderPendingWithdrawal, Checkpoint,
    ConsolidationRequest, ContributionAndProof, DataColumnSidecar, DataColumnsByRootIdentifier,
    Deposit, DepositData, DepositMessage, DepositRequest, Eth1Data, ExecutionPayload,
    ExecutionPayloadBid, ExecutionPayloadEnvelope, ExecutionRequests, Fork, ForkData,
    HistoricalSummary, IndexedAttestation, IndexedPayloadAttestation, MatrixEntry,
    PartialDataColumnGroupID, PartialDataColumnSidecar, PayloadAttestation, PayloadAttestationData,
    PayloadAttestationMessage, PendingConsolidation, PendingDeposit, PendingPartialWithdrawal,
    PowBlock, ProposerPreferences, ProposerSlashing, SignedAggregateAndProof,
    SignedBLSToExecutionChange, SignedBeaconBlock, SignedBeaconBlockHeader,
    SignedContributionAndProof, SignedExecutionPayloadBid, SignedExecutionPayloadEnvelope,
    SignedProposerPreferences, SignedVoluntaryExit, SigningData, SingleAttestation, SyncAggregate,
    SyncAggregatorSelectionData, SyncCommittee, SyncCommitteeContribution, SyncCommitteeMessage,
    Validator, VoluntaryExit, Withdrawal, WithdrawalRequest,
};
use moonglass_core::primitives::Root;
use moonglass_core::ssz::{Deserialize, Merkleized, Serialize};

/// Lowercase hex of a byte slice, no `0x` prefix. Expect-free: it is called on
/// failure-detail paths, and each nibble indexes a fixed 16-entry table.
fn hex_string(bytes: &[u8]) -> String {
    const HEX: [u8; 16] = *b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(char::from(HEX[usize::from(b >> 4)]));
        s.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    s
}

/// Decode a `0x`-optional fixed 32-byte root from hex; err on any non-64-nibble
/// or non-hex input.
fn decode_root(hex: &str) -> Result<[u8; 32], String> {
    let hex = hex.strip_prefix("0x").unwrap_or(hex);
    let bytes = hex.as_bytes();
    if bytes.len() != 64 {
        return Err(format!("expected 64 hex chars, got {}", bytes.len()));
    }
    if !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("expected hex digits (0-9a-fA-F) only".to_string());
    }
    let mut out = [0u8; 32];
    for (byte, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let s = std::str::from_utf8(pair).map_err(|_| "non-ascii hex".to_string())?;
        *byte = u8::from_str_radix(s, 16).map_err(|e| format!("bad hex byte: {e}"))?;
    }
    Ok(out)
}

/// Generic per-container check: decode, re-serialize for byte equality, then
/// compare the hash-tree-root. Mirrors the adapter's `run_one`.
///
/// Every `ssz_static` vector is a valid container carrying an expected root, so
/// a failure to decode, re-serialize, or merkleize is the backend rejecting a
/// valid vector (`reject-valid`, matching `operations::classify` and protocol
/// §5's canonical vocabulary). A serialization or root the backend produces
/// that differs from the vector is a `mismatch`. The detail strings (`decode:`,
/// `re-serialize:`, `hash_tree_root:`, `round-trip differs:`, `root:`) keep the
/// cases distinguishable for a human.
fn run_one<T>(bytes: &[u8], expected_root: &[u8; 32]) -> Verdict
where
    T: Deserialize + Serialize + Merkleized,
{
    let value = match T::deserialize(bytes) {
        Ok(v) => v,
        Err(e) => return Verdict::fail("reject-valid", format!("decode: {e:?}")),
    };
    let mut reencoded = Vec::with_capacity(bytes.len());
    if let Err(e) = value.serialize(&mut reencoded) {
        return Verdict::fail("reject-valid", format!("re-serialize: {e:?}"));
    }
    if reencoded != bytes {
        return Verdict::fail("mismatch", byte_diff_detail("round-trip differs", &reencoded, bytes));
    }
    let node = match value.hash_tree_root() {
        Ok(n) => n,
        Err(e) => return Verdict::fail("reject-valid", format!("hash_tree_root: {e:?}")),
    };
    let got = Root::from(node).0;
    if got == *expected_root {
        Verdict::pass("ok", "")
    } else {
        Verdict::fail(
            "mismatch",
            format!("root: got 0x{}, want 0x{}", hex_string(&got), hex_string(expected_root)),
        )
    }
}

/// Emit the container dispatch table over the adapter's 65 static containers.
///
/// Produces `dispatch_for`, a pure name → typed-[`run_one`] lookup (as a plain
/// function pointer, so the concrete container type is monomorphized here).
/// It never touches the filesystem, so [`run`] can answer `todo` for an unknown
/// container before any I/O, the same "dispatch precedes I/O" idiom as
/// `operations.rs`.
///
/// The 65 names below must stay in lockstep with the adapter's
/// `StaticContainer::ALL` table: a divergent or misspelled name silently falls
/// through to `todo` rather than failing the build.
macro_rules! ssz_containers {
    ($($name:literal => $ty:ty),+ $(,)?) => {
        /// Map a container name to its typed round-trip check, or `None` for an
        /// unrecognised container. Pure lookup, no filesystem access.
        fn dispatch_for(handler: &str) -> Option<fn(&[u8], &[u8; 32]) -> Verdict> {
            Some(match handler {
                $($name => run_one::<$ty> as fn(&[u8], &[u8; 32]) -> Verdict,)+
                _ => return None,
            })
        }
    };
}

// The 65 wire containers, ported verbatim from the adapter's
// `impl SupportedHandler for StaticContainer { const ALL }` (adapter-wins on names).
ssz_containers! {
    "Attestation" => Attestation,
    "AttestationData" => AttestationData,
    "AttesterSlashing" => AttesterSlashing,
    "AggregateAndProof" => AggregateAndProof,
    "BeaconBlock" => BeaconBlock,
    "BeaconBlockBody" => BeaconBlockBody,
    "BeaconBlockHeader" => BeaconBlockHeader,
    "BeaconState" => BeaconState,
    "BLSToExecutionChange" => BLSToExecutionChange,
    "Builder" => Builder,
    "BuilderDepositRequest" => BuilderDepositRequest,
    "BuilderExitRequest" => BuilderExitRequest,
    "BuilderPendingPayment" => BuilderPendingPayment,
    "BuilderPendingWithdrawal" => BuilderPendingWithdrawal,
    "Checkpoint" => Checkpoint,
    "ConsolidationRequest" => ConsolidationRequest,
    "ContributionAndProof" => ContributionAndProof,
    "DataColumnSidecar" => DataColumnSidecar,
    "DataColumnsByRootIdentifier" => DataColumnsByRootIdentifier,
    "Deposit" => Deposit,
    "DepositData" => DepositData,
    "DepositMessage" => DepositMessage,
    "DepositRequest" => DepositRequest,
    "Eth1Data" => Eth1Data,
    "ExecutionPayload" => ExecutionPayload,
    "ExecutionPayloadBid" => ExecutionPayloadBid,
    "ExecutionPayloadEnvelope" => ExecutionPayloadEnvelope,
    "ExecutionRequests" => ExecutionRequests,
    "Fork" => Fork,
    "ForkData" => ForkData,
    "HistoricalSummary" => HistoricalSummary,
    "IndexedAttestation" => IndexedAttestation,
    "IndexedPayloadAttestation" => IndexedPayloadAttestation,
    "MatrixEntry" => MatrixEntry,
    "PartialDataColumnGroupID" => PartialDataColumnGroupID,
    "PartialDataColumnSidecar" => PartialDataColumnSidecar,
    "PayloadAttestation" => PayloadAttestation,
    "PayloadAttestationData" => PayloadAttestationData,
    "PayloadAttestationMessage" => PayloadAttestationMessage,
    "PendingConsolidation" => PendingConsolidation,
    "PendingDeposit" => PendingDeposit,
    "PendingPartialWithdrawal" => PendingPartialWithdrawal,
    "PowBlock" => PowBlock,
    "ProposerPreferences" => ProposerPreferences,
    "ProposerSlashing" => ProposerSlashing,
    "SignedAggregateAndProof" => SignedAggregateAndProof,
    "SignedBeaconBlock" => SignedBeaconBlock,
    "SignedBeaconBlockHeader" => SignedBeaconBlockHeader,
    "SignedBLSToExecutionChange" => SignedBLSToExecutionChange,
    "SignedContributionAndProof" => SignedContributionAndProof,
    "SignedExecutionPayloadBid" => SignedExecutionPayloadBid,
    "SignedExecutionPayloadEnvelope" => SignedExecutionPayloadEnvelope,
    "SignedProposerPreferences" => SignedProposerPreferences,
    "SignedVoluntaryExit" => SignedVoluntaryExit,
    "SigningData" => SigningData,
    "SingleAttestation" => SingleAttestation,
    "SyncAggregate" => SyncAggregate,
    "SyncAggregatorSelectionData" => SyncAggregatorSelectionData,
    "SyncCommittee" => SyncCommittee,
    "SyncCommitteeContribution" => SyncCommitteeContribution,
    "SyncCommitteeMessage" => SyncCommitteeMessage,
    "Validator" => Validator,
    "VoluntaryExit" => VoluntaryExit,
    "Withdrawal" => Withdrawal,
    "WithdrawalRequest" => WithdrawalRequest,
}

/// Run one `ssz_static` case: dispatch on the container name, then read the
/// serialized bytes, decode the expected root, and run the typed round-trip.
///
/// Ordering matters (see the runner tests): the unknown-container check comes
/// first (→ `todo`, never touching the filesystem), then the file read
/// (→ `bug` on error), then the root decode (→ `bug` on error), so a malformed
/// root on an unreadable case still surfaces the read error first.
pub(crate) fn run(req: &SszStaticRequest) -> Verdict {
    let Some(check) = dispatch_for(&req.handler) else {
        return Verdict::fail("todo", format!("unsupported container {}", req.handler));
    };
    let bytes = match std::fs::read(&req.serialized) {
        Ok(b) => b,
        Err(e) => return Verdict::fail("bug", format!("read serialized: {e}")),
    };
    let expected_root = match decode_root(&req.root_hex) {
        Ok(r) => r,
        Err(e) => return Verdict::fail("bug", format!("bad expected root: {e}")),
    };
    check(&bytes, &expected_root)
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    /// Per-call counter making each test temp-dir name unique within one process.
    static TEMP_DIR_SEQ: AtomicU32 = AtomicU32::new(0);

    /// Serialize a default `Checkpoint` and its expected root, exactly the way
    /// [`run`] computes them, in memory, no filesystem.
    fn checkpoint_bytes_and_root() -> (Vec<u8>, [u8; 32]) {
        let cp = Checkpoint::default();
        let mut bytes = Vec::new();
        cp.serialize(&mut bytes).unwrap();
        let root = Root::from(cp.hash_tree_root().unwrap()).0;
        (bytes, root)
    }

    #[test]
    fn round_trip_and_root_pass() {
        let (bytes, root) = checkpoint_bytes_and_root();
        assert_eq!(run_one::<Checkpoint>(&bytes, &root).line(), "pass\tok\t");
    }

    #[test]
    fn wrong_root_is_a_mismatch() {
        let (bytes, _) = checkpoint_bytes_and_root();
        let line = run_one::<Checkpoint>(&bytes, &[0xab; 32]).line();
        assert!(line.starts_with("fail\tmismatch\troot:"), "{line}");
    }

    #[test]
    fn undecodable_bytes_are_reject_valid() {
        let line = run_one::<Checkpoint>(&[0xffu8; 3], &[0x00; 32]).line();
        assert!(line.starts_with("fail\treject-valid\tdecode:"), "{line}");
    }

    #[test]
    fn decode_root_accepts_optional_prefix_and_rejects_malformed() {
        // A valid 0x-prefixed 64-char root decodes to the right bytes.
        assert_eq!(decode_root(&format!("0x{}", "ab".repeat(32))).unwrap(), [0xab; 32]);
        // A bare (no 0x) 64-char root is accepted; the prefix is optional.
        assert_eq!(decode_root(&"cd".repeat(32)).unwrap(), [0xcd; 32]);
        // Wrong length is an error.
        assert!(decode_root("0x00").is_err());
        // 64 chars but non-hex (a stray 'g') is an error.
        assert!(decode_root(&format!("0x{}g", "0".repeat(63))).is_err());
        // A leading '+' is not a hex digit; from_str_radix would accept it, the
        // guard rejects it. 64 chars, one '+', must be an error.
        assert!(decode_root(&format!("+{}", "a".repeat(63))).is_err());
    }

    #[test]
    fn run_end_to_end_happy_path() {
        // The one hermetic file-backed test: exercise the read → decode_root →
        // dispatch glue in `run`, then clean up the unique temp dir.
        let (bytes, root) = checkpoint_bytes_and_root();
        let seq = TEMP_DIR_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("mgr-ssz-run-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("serialized.ssz");
        std::fs::write(&path, &bytes).unwrap();
        let req = SszStaticRequest {
            handler: "Checkpoint".into(),
            serialized: path,
            root_hex: format!("0x{}", hex_string(&root)),
        };
        assert_eq!(run(&req).line(), "pass\tok\t");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_container_is_a_todo() {
        let req = SszStaticRequest {
            handler: "LightClientUpdate".into(),
            serialized: "/nonexistent".into(),
            root_hex: "0x00".into(),
        };
        // dispatch check precedes file I/O (operations.rs idiom)
        assert!(run(&req).line().starts_with("fail\ttodo\tunsupported container"));
    }

    #[test]
    fn missing_file_is_a_bug() {
        let req = SszStaticRequest {
            handler: "Checkpoint".into(),
            serialized: "/nonexistent/serialized.ssz".into(),
            root_hex: "0x00".into(),
        };
        assert!(run(&req).line().starts_with("fail\tbug\tread serialized:"));
    }
}

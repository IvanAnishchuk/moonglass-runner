//! The `pyspec_server` wire protocol: one tab-separated request line in, one
//! `pass|fail\t<bucket>\t<detail>` line out. `-` marks an absent field.

use std::path::PathBuf;

/// A single `pyspec_server` request decoded from one tab-delimited stdin line.
pub(crate) struct CaseRequest {
    /// Test runner name (e.g. `operations`).
    // Dispatch happens on the raw first field before parsing (see main.rs
    // `respond`), so nothing reads the decoded copy until the non-operations
    // 10-field runners are implemented.
    // TODO(ivan-epf-research#41): consumed by the non-operations runners.
    #[allow(dead_code)]
    pub(crate) runner: String,
    /// Handler within the runner (e.g. `attestation`).
    pub(crate) handler: String,
    /// Path to the pre-state SSZ file; `None` when absent (`-` on the wire).
    pub(crate) pre: Option<PathBuf>,
    /// Path to the expected post-state SSZ file; `None` for invalid-vector cases.
    pub(crate) post: Option<PathBuf>,
    /// BLS setting flag from the wire protocol (0 = BLS on, 2 = BLS off).
    pub(crate) bls_setting: u8,
    /// Number of blocks in the test vector (M1 runners; unused by operations).
    // TODO(ivan-epf-research#41): consumed by the non-operations runners.
    #[allow(dead_code)]
    pub(crate) blocks_count: usize,
    /// Fork epoch override; `None` when absent.
    // TODO(ivan-epf-research#41): consumed by the non-operations runners.
    #[allow(dead_code)]
    pub(crate) fork_epoch: Option<u64>,
    /// Ordered list of additional input files (one operation per entry for operations tests).
    pub(crate) inputs: Vec<PathBuf>,
    /// Fork block override; `None` when absent.
    // TODO(ivan-epf-research#41): consumed by the non-operations runners.
    #[allow(dead_code)]
    pub(crate) fork_block: Option<u64>,
    /// Whether the execution payload is expected to be valid (M1 runners).
    // TODO(ivan-epf-research#41): consumed by the non-operations runners.
    #[allow(dead_code)]
    pub(crate) execution_valid: bool,
}

impl CaseRequest {
    /// Parse one tab-delimited `pyspec_server` request line into a [`CaseRequest`].
    pub(crate) fn parse(line: &str) -> Result<Self, String> {
        let line = line.trim_end_matches(['\r', '\n']);
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 10 {
            return Err(format!("expected 10 fields, got {}", f.len()));
        }
        let opt_path = |s: &str| (s != "-").then(|| PathBuf::from(s));
        let opt_u64 = |s: &str| -> Result<Option<u64>, String> {
            if s == "-" {
                Ok(None)
            } else {
                s.parse().map(Some).map_err(|e| format!("bad u64: {e}"))
            }
        };
        Ok(Self {
            runner: f[0].to_string(),
            handler: f[1].to_string(),
            pre: opt_path(f[2]),
            post: opt_path(f[3]),
            bls_setting: f[4].parse().map_err(|e| format!("bad bls_setting: {e}"))?,
            blocks_count: f[5].parse().map_err(|e| format!("bad blocks_count: {e}"))?,
            fork_epoch: opt_u64(f[6])?,
            inputs: if f[7].is_empty() {
                Vec::new()
            } else {
                f[7].split(',').map(PathBuf::from).collect()
            },
            fork_block: opt_u64(f[8])?,
            execution_valid: f[9] == "1",
        })
    }
}

/// The 4-field `ssz_static` request: container name, serialized bytes, expected root.
pub(crate) struct SszStaticRequest {
    /// Container type name (e.g. `BeaconBlock`).
    pub(crate) handler: String,
    /// Path to the decompressed serialized bytes.
    pub(crate) serialized: PathBuf,
    /// Expected hash-tree-root, hex as it travels on the wire (usually 0x-prefixed).
    pub(crate) root_hex: String,
}

impl SszStaticRequest {
    /// Parse one 4-field `ssz_static` line.
    pub(crate) fn parse(line: &str) -> Result<Self, String> {
        let line = line.trim_end_matches(['\r', '\n']);
        let f: Vec<&str> = line.split('\t').collect();
        if f.len() != 4 {
            return Err(format!("expected 4 fields, got {}", f.len()));
        }
        Ok(Self {
            handler: f[1].to_string(),
            serialized: PathBuf::from(f[2]),
            root_hex: f[3].to_string(),
        })
    }
}

/// A single `pyspec_server` response: pass or fail with a bucket tag and detail.
pub(crate) struct Verdict {
    /// Whether the test case passed.
    passed: bool,
    /// Short tag classifying the outcome (e.g. `ok`, `mismatch`, `todo`).
    bucket: &'static str,
    /// Human-readable detail appended after the bucket on the wire.
    detail: String,
}

impl Verdict {
    /// Construct a passing verdict.
    pub(crate) fn pass(bucket: &'static str, detail: impl Into<String>) -> Self {
        Self { passed: true, bucket, detail: detail.into() }
    }

    /// Construct a failing verdict.
    pub(crate) fn fail(bucket: &'static str, detail: impl Into<String>) -> Self {
        Self { passed: false, bucket, detail: detail.into() }
    }

    /// One response line; detail is flattened so it can never break the framing.
    pub(crate) fn line(&self) -> String {
        let detail: String = self
            .detail
            .split(['\t', '\n', '\r'])
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>()
            .join(" ");
        format!(
            "{}\t{}\t{}",
            if self.passed { "pass" } else { "fail" },
            self.bucket,
            detail
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_full_request_line() {
        let line = "operations\tattestation\t/t/pre.ssz\t/t/post.ssz\t1\t0\t-\t/t/op.ssz\t-\t1";
        let r = CaseRequest::parse(line).unwrap();
        assert_eq!(r.runner, "operations");
        assert_eq!(r.handler, "attestation");
        assert_eq!(r.pre.as_deref(), Some(std::path::Path::new("/t/pre.ssz")));
        assert_eq!(r.post.as_deref(), Some(std::path::Path::new("/t/post.ssz")));
        assert_eq!(r.bls_setting, 1);
        assert_eq!(r.fork_epoch, None);
        assert_eq!(r.inputs.len(), 1);
        assert!(r.execution_valid);
    }

    #[test]
    fn dash_means_absent_and_empty_inputs_ok() {
        let line = "operations\tattestation\t/t/pre.ssz\t-\t2\t0\t-\t\t-\t0";
        let r = CaseRequest::parse(line).unwrap();
        assert_eq!(r.post, None);
        assert_eq!(r.bls_setting, 2);
        assert!(r.inputs.is_empty());
        assert!(!r.execution_valid);
    }

    #[test]
    fn wrong_field_count_is_an_error() {
        assert!(CaseRequest::parse("operations\tattestation").is_err());
    }

    #[test]
    fn verdict_lines_are_single_line_tab_separated() {
        let v = Verdict::fail("mismatch", "post root differs\tweird\ndetail");
        assert_eq!(v.line(), "fail\tmismatch\tpost root differs weird detail");
    }

    #[test]
    fn trailing_newline_does_not_corrupt_the_last_field() {
        let line = "operations\tattestation\t/t/pre.ssz\t/t/post.ssz\t1\t0\t-\t/t/op.ssz\t-\t1\n";
        let r = CaseRequest::parse(line).unwrap();
        assert!(r.execution_valid);
    }

    #[test]
    fn multiple_inputs_split_on_commas() {
        let line = "operations\tattestation\t/t/pre.ssz\t/t/post.ssz\t1\t0\t-\t/t/a.ssz,/t/b.ssz,/t/c.ssz\t-\t1";
        let r = CaseRequest::parse(line).unwrap();
        assert_eq!(r.inputs.len(), 3);
        assert_eq!(r.inputs[1], std::path::PathBuf::from("/t/b.ssz"));
    }

    #[test]
    fn numeric_optionals_parse_and_reject() {
        let ok_line = "operations\tattestation\t-\t-\t0\t0\t7\t\t-\t0";
        let r = CaseRequest::parse(ok_line).unwrap();
        assert_eq!(r.fork_epoch, Some(7));

        let bad_line = "operations\tattestation\t-\t-\t0\t0\tx\t\t-\t0";
        assert!(CaseRequest::parse(bad_line).is_err());
    }

    #[test]
    fn bad_bls_setting_is_an_error() {
        let line = "operations\tattestation\t-\t-\tx\t0\t-\t\t-\t0";
        assert!(CaseRequest::parse(line).is_err());
    }

    #[test]
    fn pass_verdict_line_format() {
        assert_eq!(Verdict::pass("ok", "").line(), "pass\tok\t");
    }

    #[test]
    fn ssz_static_request_parses_four_fields() {
        let r = SszStaticRequest::parse("ssz_static\tCheckpoint\t/t/serialized.ssz\t0xabcd").unwrap();
        assert_eq!(r.handler, "Checkpoint");
        assert_eq!(r.serialized, std::path::PathBuf::from("/t/serialized.ssz"));
        assert_eq!(r.root_hex, "0xabcd");
    }

    #[test]
    fn ssz_static_request_rejects_wrong_field_count() {
        assert!(SszStaticRequest::parse("ssz_static\tCheckpoint\t/t/s.ssz").is_err());
        assert!(SszStaticRequest::parse("ssz_static\tA\t/t/s.ssz\t0x1\textra").is_err());
    }
}

//! Shared verdict classification for the runner family. `classify` is the pure
//! `EthCL` verdict table (a faithful rejection of an invalid vector is a pass);
//! `byte_diff_detail` formats the mismatch detail both it and the `ssz_static`
//! round-trip check report.

use crate::protocol::Verdict;

/// Human detail for a byte-string mismatch: both lengths and the first
/// differing index. `first diff at byte K` is the earliest position where `got`
/// and `want` disagree over their common prefix, or the shorter length when one
/// is a prefix of the other. `prefix` names the comparison (e.g. `post differs`).
pub(crate) fn byte_diff_detail(prefix: &str, got: &[u8], want: &[u8]) -> String {
    let first_diff = got
        .iter()
        .zip(want.iter())
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| got.len().min(want.len()));
    format!(
        "{prefix}: got {} B, want {} B, first diff at byte {first_diff}",
        got.len(),
        want.len(),
    )
}

/// Pure verdict table. `result` is the transition outcome (error stringified),
/// `got_post` the canonical SSZ of the resulting state, `expected_post` the
/// expected-post file bytes (None = the vector is invalid, a reject is expected).
pub(crate) fn classify(
    result: Result<(), String>,
    got_post: &[u8],
    expected_post: Option<&[u8]>,
) -> Verdict {
    match (result, expected_post) {
        (Ok(()), Some(exp)) if got_post == exp => Verdict::pass("ok", ""),
        (Ok(()), Some(exp)) => {
            Verdict::fail("mismatch", byte_diff_detail("post differs", got_post, exp))
        }
        (Err(e), Some(_)) => Verdict::fail("reject-valid", e),
        (Err(e), None) => Verdict::pass("reject", e),
        (Ok(()), None) => Verdict::fail("accept-invalid", "ran clean, reject expected"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- byte_diff_detail ---

    #[test]
    fn equal_length_diff_reports_the_first_byte() {
        let d = byte_diff_detail("post differs", b"abc", b"abd");
        assert_eq!(d, "post differs: got 3 B, want 3 B, first diff at byte 2");
    }

    #[test]
    fn unequal_length_diff_still_reports_a_first_byte() {
        let d = byte_diff_detail("post differs", b"short", b"longer_expected");
        // 's' vs 'l' disagree at index 0.
        assert_eq!(d, "post differs: got 5 B, want 15 B, first diff at byte 0");
    }

    #[test]
    fn pure_prefix_reports_the_shorter_length_as_the_diff() {
        // No disagreement over the common prefix, so the diff is at the point
        // where the shorter run ends.
        let d = byte_diff_detail("round-trip differs", b"abc", b"abcde");
        assert_eq!(d, "round-trip differs: got 3 B, want 5 B, first diff at byte 3");
    }

    // --- classify ---

    #[test]
    fn valid_vector_with_matching_post_passes() {
        let v = classify(Ok(()), b"abc", Some(b"abc"));
        assert_eq!(v.line(), "pass\tok\t");
    }

    #[test]
    fn valid_vector_with_differing_post_fails_as_mismatch() {
        let v = classify(Ok(()), b"abc", Some(b"abd"));
        assert!(v.line().starts_with("fail\tmismatch\t"));
        // Equal lengths → first-diff offset is included in the detail.
        assert!(v.line().contains("first diff at byte 2"));
    }

    #[test]
    fn mismatch_detail_shows_lengths_when_different() {
        let v = classify(Ok(()), b"short", Some(b"longer_expected"));
        let line = v.line();
        assert!(line.starts_with("fail\tmismatch\t"));
        assert!(line.contains("got 5 B"));
        assert!(line.contains("want 15 B"));
        // A length mismatch now carries the first-diff byte too.
        assert!(line.contains("first diff at byte 0"));
    }

    #[test]
    fn invalid_vector_rejected_passes() {
        let v = classify(Err("bad sig".to_string()), &[], None);
        assert!(v.line().starts_with("pass\treject\t"));
        assert!(v.line().ends_with("bad sig"));
    }

    #[test]
    fn invalid_vector_accepted_fails() {
        let v = classify(Ok(()), b"abc", None);
        assert!(v.line().starts_with("fail\taccept-invalid\t"));
    }

    #[test]
    fn valid_vector_rejected_fails() {
        let v = classify(Err("spurious".to_string()), &[], Some(b"abc"));
        assert!(v.line().starts_with("fail\treject-valid\t"));
        assert!(v.line().ends_with("spurious"));
    }
}

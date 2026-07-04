//! Shared verdict classification for the runner family. `classify` is the pure
//! `EthCL` verdict table (a faithful rejection of an invalid vector is a pass);
//! it is called by every runner that produces a canonical post-state.

use crate::protocol::Verdict;

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
            let detail = if got_post.len() == exp.len() {
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
            } else {
                format!(
                    "post differs: got {} B, want {} B",
                    got_post.len(),
                    exp.len()
                )
            };
            Verdict::fail("mismatch", detail)
        }
        (Err(e), Some(_)) => Verdict::fail("reject-valid", e),
        (Err(e), None) => Verdict::pass("reject", e),
        (Ok(()), None) => Verdict::fail("accept-invalid", "ran clean, reject expected"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(!line.contains("first diff at byte"));
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

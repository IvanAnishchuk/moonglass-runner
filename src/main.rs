//! `moonglass-runner`: pyspec_server-protocol conformance runner backed by moonglass-core.
//!
//! Reads tab-delimited case requests from stdin and writes `pass|fail` verdict
//! lines to stdout, one per line, following the `pyspec_server` wire protocol.

mod epoch;
mod operations;
mod protocol;
mod runner;
mod ssz_static;
mod verdict;

use protocol::{CaseRequest, SszStaticRequest, Verdict};
use std::io::{BufRead, Write};

// The exactly-one-preset contract, stated at this crate's boundary. In practice
// moonglass-core fails such builds first (duplicate preset consts + its own guard);
// this keeps the contract local in case that upstream detail ever changes.
#[cfg(all(feature = "mainnet", feature = "minimal"))]
compile_error!(
    "enable exactly one preset feature: `--no-default-features --features minimal` or \
     `--no-default-features --features mainnet` (a bare `--features minimal` keeps the \
     default mainnet feature on too)"
);
#[cfg(not(any(feature = "mainnet", feature = "minimal")))]
compile_error!(
    "enable exactly one preset feature: after `--no-default-features`, add \
     `--features minimal` or `--features mainnet`"
);

/// Preset compiled into this binary (`minimal` or `mainnet`).
const COMPILED_PRESET: &str = if cfg!(feature = "minimal") { "minimal" } else { "mainnet" };

/// This bin target's name, one target per preset, see `[[bin]]` in Cargo.toml.
const BIN_NAME: &str = env!("CARGO_BIN_NAME");

/// Dispatch one request line on its first field, then parse, then run.
///
/// Order of arms is semantic: implemented runners parse strictly (malformed
/// line = `bug`); runners moonglass-core cannot serve by upstream design (no
/// genesis-builder, no `upgrade_to_*` API) answer `skip`; protocol runners not
/// yet implemented answer `todo`; anything else is an unknown verb
/// (consensus-diff `docs/protocol.md` §7).
fn respond(line: &str) -> Verdict {
    let first = line
        .trim_end_matches(['\r', '\n'])
        .split('\t')
        .next()
        .unwrap_or_default();
    match first {
        "operations" => match CaseRequest::parse(line) {
            Ok(req) => operations::run(&req),
            Err(e) => Verdict::fail("bug", format!("bad request line: {e}")),
        },
        "epoch_processing" => match CaseRequest::parse(line) {
            Ok(req) => epoch::run(&req),
            Err(e) => Verdict::fail("bug", format!("bad request line: {e}")),
        },
        "ssz_static" => match SszStaticRequest::parse(line) {
            Ok(req) => ssz_static::run(&req),
            Err(e) => Verdict::fail("bug", format!("bad request line: {e}")),
        },
        "fork" | "genesis" | "transition" => Verdict::fail(
            "skip",
            format!("unmodeled upstream: {first} has no moonglass-core API"),
        ),
        "finality" | "fork_choice" | "random" | "rewards" | "sanity" => {
            Verdict::fail("todo", format!("unsupported runner {first}"))
        }
        _ => Verdict::fail("todo", format!("unsupported verb {first}")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Invocation mirrors `pyspec_server <fork> <preset>`.
    if args.len() != 3 || args[1] != "gloas" || args[2] != COMPILED_PRESET {
        eprintln!(
            "usage: {BIN_NAME} gloas {COMPILED_PRESET} (this build supports only fork=gloas preset={COMPILED_PRESET})"
        );
        std::process::exit(2);
    }
    let stdin = std::io::stdin();
    let mut stdout = std::io::stdout();
    for line in stdin.lock().lines() {
        // A stdin read error is fatal (harness will respawn); a parse error answers fail-bug and continues.
        let Ok(line) = line else { break };
        if line.is_empty() {
            continue;
        }
        // AssertUnwindSafe: captures only &line; per-case state is discarded on panic, so this is sound.
        let verdict =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| respond(&line))).unwrap_or_else(
                |payload| {
                    let msg = payload
                        .downcast_ref::<&str>()
                        .map(std::string::ToString::to_string)
                        .or_else(|| payload.downcast_ref::<String>().cloned())
                        .unwrap_or_else(|| "non-string panic payload".to_string());
                    Verdict::fail("bug", format!("panic: {msg}"))
                },
            );
        if writeln!(stdout, "{}", verdict.line()).is_err() || stdout.flush().is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_choice_shape_degrades_to_todo() {
        let line = "fork_choice\tget_head\t/t/anchor_state.ssz\t-\t1\t0\t-\t/t/anchor_block.ssz,/t/fc.txt";
        assert_eq!(respond(line).line(), "fail\ttodo\tunsupported runner fork_choice");
    }

    #[test]
    fn ssz_static_malformed_line_is_a_bug() {
        // ssz_static now dispatches directly; a wrong-field-count line is
        // a harness-contract violation, the same as any implemented runner.
        assert_eq!(
            respond("ssz_static\tCheckpoint").line(),
            "fail\tbug\tbad request line: expected 4 fields, got 2"
        );
    }

    #[test]
    fn known_ten_field_runner_answers_todo() {
        let line = "sanity\tblocks\t/t/pre.ssz\t/t/post.ssz\t1\t2\t-\t/t/blocks_0.ssz,/t/blocks_1.ssz\t-\t1";
        assert_eq!(respond(line).line(), "fail\ttodo\tunsupported runner sanity");
    }

    #[test]
    fn known_runner_degrades_before_shape_parsing() {
        // A truncated line for an unimplemented runner is a coverage gap,
        // not a contract violation: no field-count check happens first.
        assert_eq!(respond("sanity\tblocks").line(), "fail\ttodo\tunsupported runner sanity");
    }

    #[test]
    fn unknown_first_field_is_an_unsupported_verb() {
        // Reserved verbs (compute, generate) and anything else unknown.
        let line = "compute\toperations\tattestation\t/t/pre.ssz";
        assert_eq!(respond(line).line(), "fail\ttodo\tunsupported verb compute");
    }

    #[test]
    fn malformed_line_for_an_implemented_runner_is_still_a_bug() {
        assert_eq!(
            respond("operations\tattestation").line(),
            "fail\tbug\tbad request line: expected 10 fields, got 2"
        );
    }

    #[test]
    fn epoch_processing_malformed_line_is_a_bug() {
        // epoch_processing now dispatches through CaseRequest::parse; a
        // wrong-field-count line is a harness-contract violation, like any
        // implemented 10-field runner.
        assert_eq!(
            respond("epoch_processing\tslashings").line(),
            "fail\tbug\tbad request line: expected 10 fields, got 2"
        );
    }

    #[test]
    fn unmodeled_runners_answer_skip() {
        // moonglass-core deliberately has no genesis-builder or upgrade_to_* API;
        // these are skip (deliberately unmodeled), not todo (coverage debt).
        for runner in ["genesis", "fork", "transition"] {
            let line = format!("{runner}\tsome_handler\t/t/pre.ssz\t-\t1\t0\t-\t\t-\t1");
            assert_eq!(
                respond(&line).line(),
                format!("fail\tskip\tunmodeled upstream: {runner} has no moonglass-core API")
            );
        }
    }

    #[test]
    fn tab_leading_line_is_an_empty_unsupported_verb() {
        // A line whose first field is empty degrades like any unknown verb.
        assert_eq!(respond("\tx").line(), "fail\ttodo\tunsupported verb ");
    }

    #[test]
    fn bare_runner_name_with_trailing_newline_still_dispatches() {
        assert_eq!(
            respond("genesis\n").line(),
            "fail\tskip\tunmodeled upstream: genesis has no moonglass-core API"
        );
    }
}

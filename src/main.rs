//! `moonglass-runner`: pyspec_server-protocol conformance runner backed by moonglass-core.
//!
//! Reads tab-delimited case requests from stdin and writes `pass|fail` verdict
//! lines to stdout, one per line, following the `pyspec_server` wire protocol.

mod blocks;
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

/// Map a runner name to its module entry point, for the runners that share the
/// 10-field `CaseRequest` wire shape. These arms are otherwise identical (parse
/// a `CaseRequest`, run, map a parse error to a bug), so the table replaces one
/// near-duplicate `match` arm per runner. `rewards` joins here once implemented;
/// `ssz_static` parses a different (4-field) line and `fork_choice` a different
/// grammar, so they stay their own arms in [`respond`].
fn state_runner(first: &str) -> Option<fn(&CaseRequest) -> Verdict> {
    Some(match first {
        "operations" => operations::run,
        "epoch_processing" => epoch::run,
        "sanity" | "finality" | "random" => blocks::run,
        _ => return None,
    })
}

/// Dispatch one request line on its first field, then parse, then run.
///
/// Order is semantic: implemented runners parse strictly (malformed line =
/// `bug`), the 10-field family via [`state_runner`] and `ssz_static` on its own
/// 4-field line; runners moonglass-core cannot serve by upstream design (no
/// genesis-builder, no `upgrade_to_*` API) answer `skip`; protocol runners not
/// yet implemented answer `todo`; anything else is an unknown verb
/// (consensus-diff `docs/protocol.md` §7).
fn respond(line: &str) -> Verdict {
    let first = line
        .trim_end_matches(['\r', '\n'])
        .split('\t')
        .next()
        .unwrap_or_default();
    if let Some(run) = state_runner(first) {
        return match CaseRequest::parse(line) {
            Ok(req) => run(&req),
            Err(e) => Verdict::fail("bug", format!("bad request line: {e}")),
        };
    }
    match first {
        "ssz_static" => match SszStaticRequest::parse(line) {
            Ok(req) => ssz_static::run(&req),
            Err(e) => Verdict::fail("bug", format!("bad request line: {e}")),
        },
        "fork" | "genesis" | "transition" => Verdict::fail(
            "skip",
            format!("unmodeled upstream: {first} has no moonglass-core API"),
        ),
        "fork_choice" | "rewards" => {
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
    fn rewards_ten_field_line_answers_todo() {
        // rewards is still an unimplemented runner: a well-formed 10-field line
        // degrades to todo without parsing.
        let line = "rewards\tbasic\t/t/pre.ssz\t/t/post.ssz\t1\t0\t-\t-\t-\t1";
        assert_eq!(respond(line).line(), "fail\ttodo\tunsupported runner rewards");
    }

    #[test]
    fn pending_runner_short_line_stays_todo() {
        // A truncated line for a not-yet-implemented 10-field runner degrades to
        // todo without a field-count check: it hits the literal arm, never parses
        // (the guardrail the old sanity degrade-before-parse test used to hold).
        assert_eq!(respond("rewards\tbasic").line(), "fail\ttodo\tunsupported runner rewards");
    }

    #[test]
    fn sanity_now_dispatches_and_missing_pre_is_a_bug() {
        // sanity is implemented now: a well-formed line for a known handler runs
        // the blocks driver, so a missing pre file surfaces as a bug once the
        // route resolves.
        let line = "sanity\tblocks\t/t/pre.ssz\t/t/post.ssz\t1\t2\t-\t/t/blocks_0.ssz,/t/blocks_1.ssz\t-\t1";
        assert!(respond(line).line().starts_with("fail\tbug\t"));
    }

    #[test]
    fn sanity_malformed_line_is_a_bug() {
        // A wrong-field-count line for an implemented runner is a
        // harness-contract violation, like operations and epoch_processing.
        assert_eq!(
            respond("sanity\tblocks").line(),
            "fail\tbug\tbad request line: expected 10 fields, got 2"
        );
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
        // these answer skip (deliberately unmodeled), leaving todo for real
        // coverage debt.
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

//! `moonglass-runner`: pyspec_server-protocol conformance runner backed by moonglass-core.
//!
//! Reads tab-delimited case requests from stdin and writes `pass|fail` verdict
//! lines to stdout, one per line, following the `pyspec_server` wire protocol.

mod operations;
mod protocol;

use protocol::{CaseRequest, Verdict};
use std::io::{BufRead, Write};

/// Preset compiled into this binary (`minimal` or `mainnet`).
const COMPILED_PRESET: &str = if cfg!(feature = "minimal") { "minimal" } else { "mainnet" };

/// Parse one request line, dispatch to the matching runner, return a verdict.
fn respond(line: &str) -> Verdict {
    match CaseRequest::parse(line) {
        Ok(req) => match req.runner.as_str() {
            "operations" => operations::run(&req),
            other => Verdict::fail("todo", format!("unsupported runner {other}")),
        },
        Err(e) => Verdict::fail("bug", format!("bad request line: {e}")),
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // Invocation mirrors `pyspec_server <fork> <preset>`.
    if args.len() != 3 || args[1] != "gloas" || args[2] != COMPILED_PRESET {
        eprintln!(
            "usage: moonglass-runner gloas {COMPILED_PRESET} (this build supports only fork=gloas preset={COMPILED_PRESET})"
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

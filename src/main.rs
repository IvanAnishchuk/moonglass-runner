mod operations;
mod protocol;

use protocol::{CaseRequest, Verdict};
use std::io::{BufRead, Write};

const COMPILED_PRESET: &str = if cfg!(feature = "minimal") { "minimal" } else { "mainnet" };

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
        let Ok(line) = line else { break };
        if line.is_empty() {
            continue;
        }
        let verdict = match CaseRequest::parse(&line) {
            Ok(req) => match req.runner.as_str() {
                "operations" => operations::run(&req),
                other => Verdict::fail("todo", format!("unsupported runner {other}")),
            },
            Err(e) => Verdict::fail("bug", format!("bad request line: {e}")),
        };
        let _ = writeln!(stdout, "{}", verdict.line());
        let _ = stdout.flush();
    }
}

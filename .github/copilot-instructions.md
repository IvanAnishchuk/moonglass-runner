# Copilot instructions for moonglass-runner

A Rust crate (AGPL-3.0-only) serving the pyspec conformance wire protocol
over stdio, backed by the rev-pinned moonglass consensus core. One of two
backends the sibling `consensus-diff` harness diffs over the full
consensus-spec-tests suite. The normative wire contract is consensus-diff
`docs/protocol.md`.

## Project conventions

- Toolchain pinned by `rust-toolchain.toml`; exactly one preset feature per
  build (`--no-default-features --features minimal|mainnet`, one `[[bin]]`
  per preset). Both preset builds must pass.
- Lints are maximal and deliberate: deny clippy all + pedantic, missing docs
  including private items, dead_code; `unsafe_code` forbidden. Do not
  suggest relaxing them.
- TDD; tests assert exact wire lines with synthetic in-test fixtures.
- Runner logic ported from `moonglass/tests/src/adapters/*` (same license)
  is attributed in-code; where a local rewrite and the cited adapter
  disagree, the adapter is right.

## Hard rules (do not weaken in suggestions)

- **Verdict buckets are semantic.** `bug` = harness-contract violation only;
  `todo` = coverage gap; `skip` = deliberately unmodeled upstream
  (genesis/fork/transition). A wrong bucket corrupts the differential
  census.
- **The dispatch path is panic-free.** `catch_unwind` in main is a backstop;
  never suggest `unwrap`/`expect` on the request path.
- **One-crate dependency surface** (moonglass-core, rev-pinned) is
  deliberate.

## Writing style (docs, comments, commits, PR text)

- No em-dashes used as subphrase separators. Use commas, or split into two
  sentences.
- No contrastive negation. State the positive directly instead of "not X, but Y".
- Vary sentence length. Prefer active voice.
- No filler openers or summary closers; avoid AI-tell vocabulary (delve,
  leverage, robust, seamless, and similar).

## What to focus reviews on

1. Wire-contract drift vs consensus-diff `docs/protocol.md` (parsing,
   verdict lines, bucket use).
2. Runner-logic correctness vs the consensus spec and the cited adapter
   source.
3. Behavior changes without a pinning test.
4. README runner-status table drift from the dispatch code.

Do NOT flag: what the deny-lint set enforces; `#[allow(dead_code)]` fields
with a `TODO(ivan-epf-research#41)` note; the pinned trailing-space wire
detail. Prefer a few high-confidence, high-severity findings over many
style nits.

# AGENTS.md

Guidance for AI coding/review agents (Codex, etc.) working in this repo.
Humans: see `README.md`.

## What this is

`moonglass-runner` is a Rust crate (AGPL-3.0-only) serving the pyspec
conformance wire protocol over stdio: one tab-separated request line in, one
`pass|fail\t<bucket>\t<detail>` verdict line out, backed by the rev-pinned
[moonglass](https://github.com/brech1/moonglass) consensus core. It is one of
two backends the sibling `consensus-diff` harness drives over the full
consensus-spec-tests suite; verdict disagreements between backends are the
signal the whole setup exists to find. The normative wire contract is
consensus-diff `docs/protocol.md`, not this repo.

## Setup & checks

```bash
cargo test                     # unit suite (tests pin exact wire lines)
cargo clippy --all-targets    # deny-everything policy; must be silent
cargo doc --no-deps           # rustdoc lints are deny too
cargo build --release --no-default-features --features minimal   # bin: moonglass-runner-minimal
cargo build --release --no-default-features --features mainnet   # bin: moonglass-runner-mainnet
```

The toolchain is pinned by `rust-toolchain.toml`. Exactly one preset feature
per build; the `[[bin]]` targets' `required-features` and the
`compile_error!` guards in `src/main.rs` enforce it. Both preset builds must
pass before any PR.

## Conventions

- Lints are maximal and deliberate: deny clippy all + pedantic, missing docs
  including private items, dead_code, unreachable_pub; `unsafe_code` is
  forbidden. Every const/fn carries a doc comment stating a constraint, not
  narrating the code.
- TDD. Tests assert exact wire lines (`respond(line).line()` string
  equality), use synthetic in-test fixtures, no committed binaries, no
  network.
- Runner logic ported from `moonglass/tests/src/adapters/*` (same AGPL
  license) is attributed in-code and keeps the adapter's moonglass-core
  calls; where a local rewrite and the cited adapter disagree, the adapter
  is right.
- Conventional Commits; one reviewable PR per runner stage
  (ivan-epf-research#41 tracks the widening plan). Ivan merges.

## Hard rules

- **Verdict buckets are semantic, never cosmetic.** `bug` = harness-contract
  violation only (malformed line of an implemented runner, file I/O error,
  pre-state decode failure, panic). `todo` = coverage gap we intend to
  close. `skip` = deliberately unmodeled upstream (genesis/fork/transition
  have no moonglass-core API by design). A wrong bucket silently corrupts
  the differential census.
- **The dispatch path is panic-free.** The `catch_unwind` in `main` is a
  backstop, not a license; never introduce `unwrap`/`expect` on the request
  path.
- **Never weaken the lint policy or grow the dependency surface** (one
  crate, rev-pinned) without an explicit, stated reason.

## Writing style

Binds on docs, comments, commit messages, and PR text.

- No em-dashes used as subphrase separators. Use commas, or split into two
  sentences.
- No contrastive negation. State the positive directly instead of "not X, but Y".
- Vary sentence length. Prefer active voice.
- No filler openers or summary closers.
- Avoid AI-tell vocabulary (delve, leverage, robust, seamless, tapestry,
  landscape, and similar).

## Review guidelines

Be strict; challenge the change. Flag, in priority order:

1. **Wire-contract drift:** parsing, verdict lines, or bucket use that
   disagrees with consensus-diff `docs/protocol.md`.
2. **Runner-logic correctness** against the consensus spec and the cited
   adapter source; a plausible-but-wrong verdict is the worst failure mode
   here.
3. **Behavior changes without a pinning test.**
4. **README runner-status drift** from the dispatch code.

Do NOT flag: what the deny-lint set already enforces;
`#[allow(dead_code)]` fields carrying a `TODO(ivan-epf-research#41)` note;
the pinned trailing-space wire detail for an empty verb; the one-crate
dependency surface.

Prefer a few high-confidence, high-severity findings over many low-value
ones. A green or empty automated review is not a human approval.

# Style guide for moonglass-runner

Gemini Code Assist applies this guide when reviewing pull requests in this
repo. moonglass-runner is a small Rust crate (AGPL-3.0-only) serving the
pyspec conformance wire protocol over stdio, backed by the rev-pinned
moonglass-core. The normative wire contract lives in the sibling
consensus-diff repo, `docs/protocol.md`.

Gemini Code Assist is a best-effort second opinion. The review gate is
`/code-review`, the strict cargo lint set, the test suite, and Ivan's
self-review. A green or empty Gemini review is not an approval.

## Hard rules (flag any violation, never suggest breaking these)

- **Verdict-bucket semantics are load-bearing.** `bug` is reserved for
  harness-contract violations only (malformed lines of implemented runners,
  file I/O errors, pre-state decode failures, panics). `todo` = coverage gap
  we intend to close. `skip` = deliberately unmodeled upstream
  (genesis/fork/transition; moonglass-core has no API for them by design).
  Flag anything that blurs these or drifts from the protocol doc.
- **The dispatch path is panic-free by design.** The `catch_unwind` in main
  is a backstop, not a license. Do not suggest `unwrap`/`expect` there.
- **Exactly one preset per build.** The two `[[bin]]` targets with
  `required-features` and the `compile_error!` guards implement it; flag any
  change that would let `minimal` and `mainnet` coexist in one build.
- **Adapter ports keep their source honest.** Code ported from
  `moonglass/tests/src/adapters/*` (same AGPL license) is attributed in-code
  and keeps the adapter's moonglass-core calls; flag a port that silently
  diverges from its cited source.

## What NOT to flag

- Anything the deny-lint set already enforces: clippy all + pedantic,
  missing docs (including private items), dead_code, unreachable_pub,
  unsafe (forbidden), rustdoc broken links.
- `#[allow(dead_code)]` fields carrying a `TODO(ivan-epf-research#41)` note;
  they are reserved wire fields for planned runners.
- Tests asserting exact wire lines, including the pinned trailing space for
  an empty verb; those are deliberate contract pins.
- The one-crate dependency surface and the maximal lint policy; both are
  deliberate.

## Writing style

Apply to all prose (docs, comments, commit messages, PR text):

- No em-dashes used as subphrase separators. Use commas, or split into two
  sentences.
- No contrastive negation. State the positive directly instead of "not X, but Y".
- Vary sentence length. Prefer active voice.
- No filler openers ("Let's dive in") or summary closers ("In conclusion").
- Avoid AI-tell vocabulary: delve, leverage, robust, seamless, tapestry,
  landscape, and similar.

## Review focus, in priority order

1. Wire-contract drift: request parsing, verdict lines, or bucket use that
   disagrees with consensus-diff `docs/protocol.md`.
2. Correctness of runner logic against the consensus spec and the cited
   adapter sources; a wrong verdict silently corrupts the differential census.
3. Behavior changes without a pinning test (tests here assert exact wire
   lines; a change the tests cannot see is a finding).
4. README runner-status table drift from the code.

Prefer a few high-confidence, high-severity findings over many style nits.

# moonglass-runner

A Rust binary that links `moonglass-core` and speaks the `pyspec_server` stdio wire
protocol used by etheorem's conformance harness, so the harness can drive the moonglass
consensus client over gloas-minimal operations vectors.

## Wire protocol

The runner reads one tab-separated request line per conformance case on stdin. Fields:
runner, handler, pre path, post path, bls_setting, blocks_count, fork_epoch,
comma-separated input paths, fork_block, execution_valid. A `-` marks an absent field.
For each case the runner writes one response line on stdout:
`pass|fail\t<bucket>\t<detail>`.
The protocol is documented canonically in the design doc and reimplemented from
etheorem's published behavior.

## Runner status

| Runner | Status | Wire answer |
|---|---|---|
| `operations` | implemented | `pass ok`, `pass reject`, `fail mismatch`, `fail reject-valid`, `fail accept-invalid`, `fail todo`, `fail bug` |
| `ssz_static` | implemented | `pass ok`, `fail mismatch`, `fail reject-valid`, `fail todo` (unknown container), `fail bug` (malformed line / read error / bad root hex) |
| `epoch_processing` | implemented | `pass ok`, `pass reject`, `fail mismatch`, `fail reject-valid`, `fail accept-invalid`, `fail todo` (unknown handler / `bls_setting=2`), `fail bug` |
| `finality`, `fork_choice`, `random`, `rewards`, `sanity` | planned | `fail todo` |
| `fork`, `genesis`, `transition` | unmodeled upstream (no moonglass-core API by design) | `fail skip` |

An unknown first field answers `fail todo` with an "unsupported verb" detail. `fail bug` covers harness-contract violations generally: malformed lines of implemented runners, file I/O errors, pre-state decode failures, panics.

## Building

One bin target per preset, so the binaries never collide and a default build cannot
silently replace a minimal one:

```
cargo build --release                                              # target/release/moonglass-runner-mainnet
cargo build --release --no-default-features --features minimal     # target/release/moonglass-runner-minimal
```

## Usage

```
moonglass-runner-<preset> <fork> <preset>
```

The preset is fixed at compile time via cargo features; the `<preset>` argument is validated against the build, not used to select it (this mirrors the `pyspec_server <fork> <preset>` invocation contract). A mismatched `<preset>` argument fails loudly with exit code 2.

## License

AGPL-3.0-only, same as upstream `brech1/moonglass`.

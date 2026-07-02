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

## Usage

```
moonglass-runner <fork> <preset>
```

The preset is fixed at compile time via cargo features; the `<preset>` argument is validated against the build, not used to select it (this mirrors the `pyspec_server <fork> <preset>` invocation contract).

## License

AGPL-3.0-only — same as upstream `brech1/moonglass`.

# hexy

Hex-file workspace: `hexy-core` reusable binary file modification library, `hexy-compat` cleanroom slash-compatible CLI package, and `hexy-py` Python bindings.

## Commands

```bash
cargo build                                            # Build workspace
cargo check                                            # Typecheck workspace
cargo test                                             # Run tests
cargo clippy --workspace --all-targets --all-features --locked
cargo run -p hexy-compat -- [args]                     # Run compat CLI
```

CI clippy is the release gate. Workspace warning lints are useful cleanup signals, but `-D warnings` is not a handoff or release blocker unless the policy changes.

## Structure

- `crates/hexy-core/src/` - Core library; `lib.rs` re-exports the public API
  - `hexfile.rs`, `segment.rs`, `range.rs` - Data model and HexView range text
  - `pipeline.rs` - `Pipeline`, HexView's stage order
  - `ops/` - Image operations, checksums, banked maps, validation structures
  - `processing/` - `/DP` and `/SV`: signatures, MACs, ciphers, compression, keys
  - `io/` - Parsers, writers and file helpers, including the C, flash kernel, Ford and GAC exports
- `crates/hexy-compat/src/` - `hexy` CLI; `args/` parses flags (`parse*.rs`, `types.rs`), builds and runs the `Pipeline` (`execute.rs`), reads `/DP` and `/SV` parameters (`processing/`), `/vs` INI settings (`validation.rs`) and exports (`export.rs`)
- `crates/hexy-py/` - PyO3 bindings over `hexy-core`; `python/hexy/__init__.pyi` documents the Python API, and `tests/test_cli_equivalence.py` checks CLI and `Pipeline` runs match

### Backlog
Backlog lives in GitHub Issues.

### Project philosophy
- CLI must be a cleanroom replacement for the supported slash-style workflows for non-proprietary formats: binary-equivalent outputs for Intel HEX, S-Record, HEX ASCII, and raw binary.
- Library API should center on `HexFile`, `Segment`, and `AddressRange`, with typed per-operation methods and format parse/write helpers that preserve compatibility semantics.
- CLI execution model should be explicit and linear: “for flag in flags, if present, call the corresponding `HexFile` operation”, preserving the cleanroom compatibility target operation order and behavior.
- The library should enable consumers to reproduce CLI behavior by composing those typed operations in the same order.

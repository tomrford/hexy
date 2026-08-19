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

- `crates/hexy-core/src/lib.rs` - Module declarations + public re-exports
- `crates/hexy-compat/src/main.rs` - Compat CLI entry point
- `crates/hexy-core/src/` - Core library modules
- `crates/hexy-compat/src/args/` - Compat CLI parser/executor modules
- `crates/hexy-py/src/` - PyO3 bindings over `hexy-core`

### Backlog
Backlog lives in GitHub Issues.

### Project philosophy
- CLI must be a cleanroom replacement for the supported slash-style workflows for non-proprietary formats: binary-equivalent outputs for Intel HEX, S-Record, HEX ASCII, and raw binary.
- Library API should center on `HexFile`, `Segment`, and `AddressRange`, with typed per-operation methods and format parse/write helpers that preserve compatibility semantics.
- CLI execution model should be explicit and linear: “for flag in flags, if present, call the corresponding `HexFile` operation”, preserving the cleanroom compatibility target operation order and behavior.
- The library should enable consumers to reproduce CLI behavior by composing those typed operations in the same order.

# hexy

Hex-file workspace: `hexy-core` reusable binary file modification library, `hexy-compat` cleanroom slash-compatible CLI package, and `hexy-py` Python bindings.

## Commands

```bash
nix develop -c cargo build                             # Build workspace
nix develop -c cargo check                             # Typecheck workspace
nix develop -c cargo test                              # Run tests
nix develop -c cargo clippy --all-targets --all-features -- -D warnings
nix develop -c cargo run -p hexy-compat -- [args]     # Run compat CLI
```

## Structure

- `crates/hexy-core/src/lib.rs` - Module declarations + public re-exports
- `crates/hexy-compat/src/main.rs` - Compat CLI entry point
- `crates/hexy-core/src/` - Core library modules
- `crates/hexy-compat/src/args/` - Compat CLI parser/executor modules
- `crates/hexy-py/src/` - PyO3 bindings over `hexy-core`

### Backlog
Backlog lives in the Linear `hexy` project.

### Project philosophy
- CLI must be a cleanroom replacement for the supported slash-style workflows for non-proprietary formats: binary-equivalent outputs for Intel HEX, S-Record, HEX ASCII, and raw binary.
- Library API should center on `HexFile`, `Segment`, and `AddressRange`, with typed per-operation methods and format parse/write helpers that preserve compatibility semantics.
- CLI execution model should be explicit and linear: “for flag in flags, if present, call the corresponding `HexFile` operation”, preserving the cleanroom compatibility target operation order and behavior.
- The library should enable consumers to reproduce CLI behavior by composing those typed operations in the same order.

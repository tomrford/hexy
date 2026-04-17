# hexy

Hex-file workspace: `hexy-core` library plus `hexy-compat`, a HexView-compatible CLI package that installs the `hexy` binary.

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

### TODOs (current)
- Review segment overflow policy (saturating `end_address` vs strict error) once validation suite runs.
- Finish CLI parsing cleanup (table-driven for remaining non-output options).
- Consider deeper ops error context inside core ops and CLI option wrappers.
- Crate reuse decision: keep hand-rolled Intel-HEX/S-Record/HEX-ASCII writers/parsers for parity; `bin_file` (used in mint) remains a candidate once validation suite proves equivalence.

### Project philosophy
- CLI must be a drop-in HexView replacement for non-proprietary formats: binary-equivalent outputs for Intel HEX, S-Record, HEX ASCII, and raw binary.
- Library API should center on `HexFile`, `Segment`, and `AddressRange`, with typed per-operation methods and format parse/write helpers that preserve HexView semantics.
- CLI execution model should be explicit and linear: “for flag in flags, if present, call the corresponding `HexFile` operation”, preserving HexView’s operation order and behavior.
- The library should enable consumers to reproduce CLI behavior by composing those typed operations in the same order.

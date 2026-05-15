# hexy

Workspace for a reusable hex-file library plus a cleanroom slash-compatible CLI.

Current packages:
- `hexy-core` - library crate with `HexFile`, `Segment`, `AddressRange`, parsers, writers, and typed operations
- `hexy-compat` - slash-flag cleanroom compatibility CLI package; installs the `hexy` binary
- `hexy-python` - PyO3 bindings for in-memory Python use of `hexy-core`

## Install

```bash
cargo install hexy-compat
```

## Quick examples

```bash
# Filter a range and export Intel HEX
hexy input.hex /AR:'0x1000-0x1FFF' /XI -o output.hex

# Fill, cut, checksum, then export S-Record
hexy app.hex /FR:'0x0-0xFFF' /FP:FF /CR:'0x800-0x8FF' /CS0 /XS -o app.s19

# Merge a calibration overlay and export binary
hexy base.hex /MO:cal.hex /XN -o combined.bin

# Export one binary per segment
hexy multi.hex /XSB -o segments.bin
```

## Workspace commands

```bash
nix develop -c cargo build
nix develop -c cargo test
nix develop -c cargo clippy --all-targets --all-features -- -D warnings
nix develop -c cargo run -p hexy-compat -- /XI input.hex -o output.hex
nix develop -c uv run --with maturin --with pytest --project crates/hexy-python maturin develop --manifest-path crates/hexy-python/Cargo.toml
nix develop -c uv run --with pytest --project crates/hexy-python pytest crates/hexy-python/tests
```

## Operation order

Compat flags execute in a fixed pipeline order, not in argument order:

1. Input (`/IN`, `/IA`, `/II2`)
2. Address mapping (`/S08MAP`, `/S12MAP`, `/S12XMAP`, `/REMAP`)
3. dsPIC transforms (`/CDSPX`, `/CDSPS`, `/CDSPG`)
4. Fill (`/FR` + `/FP`)
5. Cut (`/CR`)
6. Merge (`/MT` or `/MO`)
7. Address range filter (`/AR`)
8. Collapse (`/FA`), align (`/AD`, `/AL`, `/AF`), split (`/SB`), swap (`/SWAPWORD`, `/SWAPLONG`)
9. Checksum (`/CS`, `/CSR`, `/CSM`, `/CSMR`)
10. Signing (`/DP`) and verification (`/SV`)
11. Export (`/XI`, `/XS`, `/XN`, `/XSB`, `/XA`, `/XC`, `/XF`, `/XP`) via `-o`

## Library

```rust
use hexy_core::{AddressRange, IntelHexWriteOptions, parse_intel_hex, write_intel_hex};

let mut hf = parse_intel_hex(data)?;
hf.cut(AddressRange::from_start_end(0x800, 0x8FF)?);
let out = write_intel_hex(&hf, &IntelHexWriteOptions::default());
```

## Scope

`hexy-compat` targets non-proprietary cleanroom-compatible slash workflows. Proprietary or DLL-backed features such as `/PB`, `/expdat`, and OEM container formats remain out of scope.

The repo is structured so additional frontends can consume `hexy-core` without forcing their release surface or UX into the compat CLI.

## Python bindings

The Python package is an in-memory API over `hexy-core`. It exposes `HexFile`, `Segment`, `AddressRange`, deterministic parsers/writers for binary, Intel HEX, S-Record, and HEX ASCII data, and the main memory operations used by the compat CLI.

```python
import hexy

hf = hexy.HexFile.from_intel_hex(data)
hf.fill("0x1000-0x10ff", pattern=b"\xff")
hf.cut("0x1080-0x108f")
out = hf.to_srec()
```

Use `Pipeline` for reusable recipes. It applies operations in hexy CLI compatibility order, not in the order methods are called. For custom operation ordering, call methods directly on `HexFile`.

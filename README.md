# hexy

Hexy is a reusable binary file modification library based on a cleanroom implementation of Vector HexView.

## Which surface?

| Surface | Install | Use when |
|---------|---------|----------|
| `hexy-core` | `cargo add hexy-core` | Building Rust tools that need parsers, memory ops, checksums, or signatures |
| `hexy-compat` | `cargo install hexy-compat` | Running HexView-style slash-flag workflows from the shell (installs the `hexy` command) |
| `hexy-py` | `pip install hexy-py` | Scripting in Python with in-memory hex editing and `Pipeline` recipes |

`hexy-compat` is the HexView-compatible CLI built on `hexy-core`. `hexy-py` wraps a subset of the core API for Python. Coverage differs between surfaces — see [known divergences](docs/known-divergences.md) for what each crate exposes and where HexView parity is still incomplete.

For the full slash-flag reference, see [cli-reference.md](skill/hexy-compat/references/cli-reference.md).

## Install

```bash
cargo add hexy-core          # library
cargo install hexy-compat    # installs the `hexy` CLI binary
pip install hexy-py
```

## Quick examples

```bash
# Filter a range and export Intel HEX
hexy input.hex /AR:'0x1000-0x1FFF' /XI -o output.hex

# Fill, cut, checksum, then export S-Record
hexy app.hex /FR:'0x0-0xFFF' /FP:FF /CR:'0x800-0x8FF' /CS0 /XS -o app.s19

# Merge a calibration overlay and export binary
hexy base.hex /MO:cal.hex /XN -o combined.bin

# Export one binary per segment (writes segments_<addr>.bin alongside -o path)
hexy multi.hex /XSB -o segments.bin
# -> segments_1000.bin, segments_2000.bin, ...
```

## Workspace commands

```bash
nix develop -c cargo build
nix develop -c cargo test
nix develop -c cargo clippy --all-targets --all-features -- -D warnings
nix develop -c cargo run -p hexy-compat -- /XI input.hex -o output.hex
nix develop -c uv run --directory crates/hexy-py --group dev maturin develop
nix develop -c uv run --directory crates/hexy-py --group dev pytest tests
```

## Operation order

Compat flags execute in a fixed pipeline order, not in argument order:

1. Input (`/IN`, `/IA`, `/II2`)
2. Address mapping (`/S08MAP`, `/S12MAP`, `/S12XMAP`, `/REMAP`)
3. dsPIC transforms (`/CDSPX`, `/CDSPS`, `/CDSPG`)
4. Fill (`/FR`; `/FP` sets the pattern, random fill when omitted)
5. Cut (`/CR`)
6. Merge (`/MT` or `/MO`)
7. Address range filter (`/AR`)
8. Collapse (`/FA`), align (`/AD`, `/AL`, `/AF`), split (`/SB`), swap (`/SWAPWORD`, `/SWAPLONG`)
9. Checksum (`/CS`, `/CSR`, `/CSM`, `/CSMR`)
10. Signing (`/DP`) and verification (`/SV`)
11. Export (`/XI`, `/XS`, `/XN`, `/XSB`, `/XA`, `/XC`, `/XF`, `/XP`) via `-o`

See [cli-reference.md](skill/hexy-compat/references/cli-reference.md) for flag syntax and examples.

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

The Python package exposes `HexFile`, `Segment`, `AddressRange`, deterministic parsers/writers for binary, Intel HEX, S-Record, and HEX ASCII data, file helpers for auto-detected input and explicit-format output, and the main memory operations used by the compat CLI. Checksum, signing, and some export formats are core-only today — see [known divergences](docs/known-divergences.md).

```python
import hexy

hf = hexy.HexFile.from_file("input.hex")
hf.fill(["0x1000-0x10ff"], pattern=b"\xff")
hf.cut(["0x1080-0x108f"])
hf.write_srec("output.s19")
```

Use `Pipeline` for reusable recipes. It applies operations in hexy CLI compatibility order, not in the order methods are called. For custom operation ordering, call methods directly on `HexFile`.

```python
import hexy

source = hexy.HexFile.from_file("app.hex")
calibration = hexy.HexFile.from_file("calibration.hex")

pipeline = hexy.Pipeline()
pipeline.merge(calibration, mode="overwrite")
pipeline.fill(["0x1000-0x10ff"], pattern=b"\xff")
pipeline.filter(["0x0000-0x1fff"])
pipeline.align(16, fill=0xff, length=True)

patched = pipeline.apply(source)
patched.write_intel_hex("patched.hex")
```

Sparse files stay sparse for inspection and operations. Dense exports such as `to_bytes()` and `to_binary(fill_gaps=...)` allocate across the covered address span. In `hexy-compat`, `/FA` and `/XP` reject dense spans above 256 MiB.

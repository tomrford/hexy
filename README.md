# hexy

Workspace for a reusable hex-file library plus a HexView-compatible CLI.

Current packages:
- `hexy-core` - library crate with `HexFile`, `Segment`, `AddressRange`, parsers, writers, and typed operations
- `hexy-compat` - slash-flag HexView-compatible CLI package; installs the `hexy` binary

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
use hexy_core::{AddressRange, HexFile};

let mut hf = HexFile::from_ihex(data)?;
hf.cut(&[AddressRange::new(0x800, 0x8FF)]);
let out = hf.to_ihex(None, None);
```

## Scope

`hexy-compat` targets non-proprietary HexView workflows. Proprietary or DLL-backed features such as `/PB`, `/expdat`, and OEM container formats remain out of scope.

The repo is structured so additional frontends can consume `hexy-core` without forcing their release surface or UX into the compat CLI.

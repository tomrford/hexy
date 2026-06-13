# Known Divergences

Current compatibility and crate-surface notes for Hexy.

Hexy has three public surfaces:

- `hexy-core` is the authoritative Rust library. It owns the data model, parsers, writers, transforms, checksum machinery, signatures, and file helpers.
- `hexy-compat` is the HexView-style slash-flag CLI. It is designed as a drop-in replacement for HexView's CLI functionality.
- `hexy-py` is a Python binding layer over `hexy-core`. It currently exposes a smaller in-memory API than the Rust crate.

## Crate Surface Differences

### `hexy-core`

`hexy-core` exposes the broadest API:

- `HexFile`, `Segment`, `AddressRange`, range parsing, normalization, sparse reads, contiguous exports, and direct segment mutation
- binary, Intel HEX, 16-bit Intel HEX import, S-Record, HEX ASCII, C-code writing, and auto-detected file helpers
- filter, cut, fill, gap fill, merge, offset, align, split, byte swap, dsPIC transforms, address scaling, banked mapping, and remap operations
- checksum calculation and writeback through `ChecksumOptions`, `ChecksumTarget`, `ChecksumJob`, and `checksum_many_sequential`
- signature signing and verification primitives
- limited HexView log-file parsing and execution helpers for `FileOpen`, `FileClose`, and `FileNew`

### `hexy-compat`

`hexy-compat` exposes the subset of `hexy-core` that maps to supported HexView-style CLI flags:

- file input, auto-detection, binary import (`/IN`), HEX ASCII import (`/IA`), and 16-bit Intel HEX import (`/II2`)
- address range filtering (`/AR`), cut (`/CR`), fill (`/FR` + `/FP`), merge (`/MO`, `/MT`), fill-all (`/FA`), alignment (`/AD`, `/AL`, `/AF`), split (`/SB`), byte swap (`/SWAPWORD`, `/SWAPLONG`), remap, S08/S12/S12X mapping, and dsPIC transforms
- checksum operations through `/CS*` and `/CSR*`
- additional feature: sequential multi-checksum execution through `/CSM*` and `/CSMR*`
- signing and verification through the supported `/DP` and `/SV` subset
- output through Intel HEX (`/XI`), S-Record (`/XS`), binary (`/XN`), HEX ASCII (`/XA`), C code (`/XC`), Ford Intel HEX (`/XF`), Porsche (`/XP`), and separate binaries (`/XSB`)

`hexy-compat` does not expose every `hexy-core` operation as an independent CLI feature. Library-only surface includes direct segment mutation, arbitrary sparse reads, `to_bytes`-style contiguous inspection, standalone address scaling/unscaling APIs, direct banked-map configuration, direct C-code writer options, direct signature/key source types, and log parsing/execution as a reusable API.

### `hexy-py`

`hexy-py` exposes the in-memory parts of `hexy-core` that are useful from Python:

- `HexFile`, `Segment`, and `AddressRange`
- binary, Intel HEX, 16-bit Intel HEX import, S-Record, HEX ASCII, auto-detected file input, in-memory serializers, and file writers for binary, Intel HEX, S-Record, and HEX ASCII
- segment inspection, sparse reads, contiguous byte export, direct byte writes, normalization, append/prepend segment operations, filter, cut, fill, gap fill, merge, offset, align, split, byte swap, dsPIC transforms, remap, and S08/S12/S12X mapping
- `Pipeline`, which applies operations in hexy CLI compatibility order

`hexy-py` does not expose the full `hexy-core` surface. Missing Python bindings include checksum calculation/writeback, sequential checksum jobs, signing, verification, C-code export, Ford/Porsche/separate-binary exporters, log-file execution helpers, address scaling/unscaling, direct banked-map configuration, and the Rust option/source types that back those operations.

## HexView Compatibility Limits

Do not claim these areas as drop-in compatible with HexView yet.

### `/XP` Porsche export

- current behavior accepts some cases that the compatibility target appears to reject
- rejection parity is wrong or `/XP` preconditions are narrower than `hexy` currently assumes

### `/XC` C-array export

- generated `.c/.h` output shape is structurally different from the compatibility target
- the compatibility target emits its legacy flash-driver style wrapper/header/macros
- `hexy` emits a smaller `stdint.h`-based array/header pair

This is not a cosmetic whitespace issue; the exported contract differs.

### `/XF` Ford Intel HEX export

- minimal-header Ford export formats `RELEASE DATE` from the system date using UTC day boundaries
- HexView appears to use the Windows local date for this field, so output can differ around local midnight

### Other Limits

- in `hexy-compat`, `/L` executes `FileClose` and `FileNew`; `FileOpen <path>` is rejected with the attempted path
- exact `/E` and `/V` text/file semantics
- proprietary or DLL-backed features such as `/PB`, `/expdat`, and OEM container formats

The boundary here is compatibility claims, not implementation status. Resolved HexView parity findings are not kept as open divergences.

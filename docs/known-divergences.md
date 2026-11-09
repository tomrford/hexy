# Known Divergences

Current compatibility and crate-surface notes for Hexy.

Hexy has three public surfaces:

- `hexy-core` is the authoritative Rust library. It owns the data model, parsers, writers, transforms, checksum machinery, signatures, and file helpers.
- `hexy-compat` is the HexView-style slash-flag CLI. It is designed as a drop-in replacement for HexView's CLI functionality.
- `hexy-py` is a Python binding layer over `hexy-core`. It currently exposes a smaller in-memory API than the Rust crate.

## Crate Surface Differences

### `hexy-core`

`hexy-core` exposes the broadest API:

- `HexFile`, `Segment`, `AddressRange`, range parsing, normalization, sparse reads, contiguous exports, segment append/prepend, and byte writes
- binary, Intel HEX, 16-bit Intel HEX import, S-Record, HEX ASCII, C-code writing, and auto-detected file helpers
- filter, cut, fill, gap fill, merge, offset, align, split, byte swap, dsPIC transforms, address scaling, banked mapping, and remap operations
- checksum calculation and writeback through `ChecksumOptions` and a `Placement`
- data processing (signing) and signature verification, with typed key readers for HexView's key formats
- `Pipeline`, the HexView stage order with typed parameters per stage, which the compat CLI and `hexy-py` both drive

### `hexy-compat`

`hexy-compat` exposes the subset of `hexy-core` that maps to supported HexView-style CLI flags:

- file input, auto-detection, binary import (`/IN`), HEX ASCII import (`/IA`), and 16-bit Intel HEX import (`/II2`)
- the no-op switches `/G`, `/M`, `/BHFCT`, `/BTFST` and `/BTBS`
- address range filtering (`/AR`), cut (`/CR`), fill (`/FR` + `/FP`), merge (`/MO`, `/MT`), fill-all (`/FA`), alignment (`/AD`, `/AL`, `/AF`), split (`/SB`), small-block removal (`/RB`), byte swap (`/SWAPWORD`, `/SWAPLONG`), remap, S08/S12/S12X mapping, and dsPIC transforms
- checksum methods 0-22 through `/CS*` and `/CSR*`, including the `expdatproc.ini` constant (`/CS16`)
- additional feature: sequential multi-checksum execution through `/CSM*` and `/CSMR*`
- signing and verification through the supported `/DP` and `/SV` subset, with HexView's full `/DP` parameter grammar
- output through Intel HEX (`/XI`), S-Record (`/XS`), binary (`/XN`), HEX ASCII (`/XA`), C code (`/XC`), Ford Intel HEX (`/XF`), Porsche (`/XP`), and separate binaries (`/XSB`)

`hexy-compat` does not expose every `hexy-core` operation as an independent CLI feature. Library-only surface includes segment append/prepend, arbitrary sparse reads, `to_bytes`-style contiguous inspection, standalone address scaling/unscaling APIs, direct banked-map configuration, direct C-code writer options, and the typed key readers.

### `hexy-py`

`hexy-py` exposes the in-memory parts of `hexy-core` that are useful from Python:

- `HexFile`, `Segment`, and `AddressRange`
- binary, Intel HEX, 16-bit Intel HEX import, S-Record, HEX ASCII, auto-detected file input, in-memory serializers, and file writers for binary, Intel HEX, S-Record, and HEX ASCII
- segment inspection, sparse reads, contiguous byte export, direct byte writes, normalization, append/prepend segment operations, filter, cut, fill, gap fill, merge, offset, align, split, small-block removal, byte swap, dsPIC transforms, remap, and S08/S12/S12X mapping
- `Pipeline`, which applies stages in hexy CLI order, including checksum calculation and writeback, signing and verification
- signing and verification on `HexFile`

`hexy-py` does not expose the full `hexy-core` surface. Missing Python bindings include checksums outside `Pipeline`, C-code export, Ford/Porsche/separate-binary exporters, address scaling/unscaling, direct banked-map configuration, and the Rust option/source types that back those operations.

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
- exact `/E` and `/V` text/file semantics; hexy prints warnings (such as an ignored `/SB` below 0x100) to stderr
- HexView warns about unrecognised options, including `/RB:n` with a colon, and carries on; hexy rejects them
- HexView treats malformed range text such as `/CR:x` like a reversed range and stops reading the list there; hexy rejects it
- `/MO` with an invalid merge range: both merge the whole file, but HexView also exits with an error
- a zero-length forced checksum range (`;!0x1000,0`) changes HexView's result in a way not yet understood; hexy ignores the range
- input files with overlapping records: HexView fails to read them and writes nothing; hexy keeps the last record's bytes
- forced S1 or S2 records (`/XS:len:0`, `/XS:len:1`) for addresses that do not fit: HexView truncates the addresses; hexy rejects the export
- `/XI` and `/XS` record lengths above 255 crash HexView; hexy rejects them
- `/CS16` `HexDataString` values with characters other than hex digits: HexView's parse is irregular; hexy rejects them
- `/DP` and `/SV` key formats HexView rejects but hexy reads: RSA public keys as SPKI PEM, binary DER or X.509 certificates; RSA private keys as binary PKCS #1 DER; Ed25519 keys with the standard `id-Ed25519` OID, as SPKI, as binary DER or from certificates (see [data processing](data-processing.md))
- `/DP` hex key files of 2999 bytes or more: HexView fails to read them; hexy reads them
- `/DP` key text with stray characters, such as `12x34`: HexView reads some of them as zero bytes; hexy rejects the text
- `/DP` option values that are not valid, such as `#IV=00;sig.txt`: HexView ignores options a method does not use; hexy rejects them
- `/DP` with more than one `;`, or `@placement` without a following `:`: HexView fails the stage and still exports; hexy rejects the command
- `/DP` output file in a folder that does not exist: HexView writes the default output file instead; hexy fails
- `/DP` ignores `#IV`, `#AUTH`, `#TAG`, `#LZSS` and `#SALT` for methods that do not use them, as HexView does; hexy also warns. `#SALT` with `/DP38` and `/DP39` is not supported yet
- `/DP` ciphers whose padding grows a block into the next block, such as `/SB` pieces: HexView keeps both blocks and exports the overlapping bytes twice; hexy keeps the later block's bytes
- `/DP55` without `#IV`: HexView takes the IV from the data but drops 16 bytes of ciphertext; hexy rejects the command
- `/DP55` and `/DP56` with `#AUTH=@address,length`: HexView leaves that data unencrypted but also out of the tag; hexy rejects the command
- `/DP56` with a `#TAG` file: HexView never reads it, so the check always fails; hexy rejects the command
- `/DP56` with an image `#TAG` in the middle of a block: HexView decrypts part of the data before it fails; hexy fails without changing the data
- `/DP38`, `/DP39`: HexView's RSA-PSS salt is reproducible between runs; hexy uses a random salt, so only verification matches
- `/DP48`, `/DP49`: HexView signs the SHA-512 digest with Ed25519ph; hexy signs it with plain Ed25519
- `/CSM*` and `/CSMR*` are hexy extensions; HexView ignores them
- wildcards (`?`, `*`) in `/MO` and `/MT` file names are not supported
- `/IA` or `/II2` with a positional input file: HexView ignores the import with a warning; hexy adds `/IA` data to the input and rejects `/II2`
- `/AD` values that are not a power of two: HexView ignores them with a warning; hexy aligns to them
- `/AL:length` without `/AD`: HexView aligns block lengths only; hexy also aligns block starts
- `/CR=` and `/FR=`: HexView ignores the `=` forms; hexy accepts them
- `/FP` with an odd number of digits or a `0x` prefix: HexView accepts it; hexy rejects it
- `/CDSPX:range,target`: HexView ignores `,target` (`;` is the documented separator); hexy rejects it
- proprietary or DLL-backed features such as `/PB`, `/expdat`, and OEM container formats

The boundary here is compatibility claims, not implementation status. Resolved HexView parity findings are not kept as open divergences.

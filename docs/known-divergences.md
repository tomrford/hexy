# Known Divergences

Current compatibility and crate-surface notes for Hexy.

Hexy has three public surfaces:

- `hexy-core` is the authoritative Rust library. It owns the data model, parsers, writers, transforms, checksum machinery, signatures, and file helpers.
- `hexy-compat` is the HexView-style slash-flag CLI. It is designed as a drop-in replacement for HexView's CLI functionality.
- `hexy-py` is the Python binding layer over `hexy-core`.

## Crate Surface Differences

### `hexy-core`

`hexy-core` exposes the broadest API:

- `HexFile`, `Segment`, `AddressRange`, range parsing, normalization, sparse reads, contiguous exports, segment append/prepend, and byte writes
- binary, Intel HEX, 16-bit Intel HEX import, S-Record, HEX ASCII, auto-detected file helpers, and HexView's C-array, CCP/XCP flash kernel, GAC software interlock and Ford Intel HEX writers
- filter, cut, fill, gap fill, merge, offset, align, split, byte swap, dsPIC transforms, address scaling, banked mapping, and remap operations
- checksum calculation and writeback through `ChecksumOptions` and a `Placement`
- HexView's validation structures (`/vs`, `/vshsm`) and the `/vs` C files
- data processing (signing) and signature verification, with typed key readers for HexView's key formats
- `Pipeline`, the HexView stage order with typed parameters per stage, which the compat CLI and `hexy-py` both drive

### `hexy-compat`

`hexy-compat` exposes the subset of `hexy-core` that maps to supported HexView-style CLI flags:

- file input, auto-detection, binary import (`/IN`), HEX ASCII import (`/IA`), 16-bit Intel HEX import (`/II2`), and the `/L` log commands
- the no-op switches `/G`, `/M`, `/BHFCT`, `/BTFST` and `/BTBS`
- address range filtering (`/AR`), cut (`/CR`), fill (`/FR` + `/FP`), merge (`/MO`, `/MT`), fill-all (`/FA`), alignment (`/AD`, `/AL`, `/AF`), split (`/SB`), small-block removal (`/RB`), byte swap (`/SWAPWORD`, `/SWAPLONG`), remap, S08/S12/S12X mapping, and dsPIC transforms
- checksum methods 0-22 through `/CS*` and `/CSR*`, including the `expdatproc.ini` constant (`/CS16`)
- additional feature: sequential multi-checksum execution through `/CSM*` and `/CSMR*`
- signing and verification through the supported `/DP` and `/SV` subset, with HexView's full `/DP` parameter grammar
- validation structures (`/vs`, `/vshsm`)
- output through Intel HEX (`/XI`), S-Record (`/XS`), binary (`/XN`), HEX ASCII (`/XA`), C arrays (`/XC`), CCP/XCP flash kernels (`/XK`), GAC software interlock files (`/XGACSWIL`), Ford Intel HEX (`/XF`), Porsche (`/XP`), and separate binaries (`/XSB`)

`hexy-compat` does not expose every `hexy-core` operation as an independent CLI feature. Library-only surface includes segment append/prepend, arbitrary sparse reads, `to_bytes`-style contiguous inspection, standalone address scaling/unscaling APIs, direct banked-map configuration, direct C-code writer options, and the typed key readers.

### `hexy-py`

`hexy-py` exposes every `hexy-core` operation, parser, writer and `Pipeline` stage, with
the same parameters, so a CLI run is reproduced by configuring the `Pipeline` stages of
its flags. What the CLI does outside `hexy-core` stays in `hexy-compat`: reading
arguments and INI files, the `/L` log commands, the `/SWAPLONG` repeat of blocks of
16 MiB or more, the checksum and data processing output text files, and the `/XP` and
`/XSB` file layouts, which compose `to_binary`, `checksum` and `blocks`.

## HexView Compatibility Limits

Do not claim these areas as drop-in compatible with HexView yet.

- warning and error texts differ from HexView's, though each goes to the `/E` file on its own line as in HexView; `/V` writes `hexy V<version>`
- every failure exits with status 1; HexView returns a code per failure kind, such as 2 for a merge range or 11 for a checksum
- an import or merge file that does not exist: HexView warns and exports without it; hexy fails, so that a mistyped name cannot silently drop data. A wildcard name that matches nothing merges nothing in both
- a zero-length forced checksum range (`;!0x1000,0`) changes HexView's result in a way not yet understood; hexy ignores the range
- input files with overlapping records: HexView fails to read them and writes nothing; hexy keeps the last record's bytes
- forced S1 or S2 records (`/XS:len:0`, `/XS:len:1`) for addresses that do not fit: HexView truncates the addresses; hexy rejects the export
- `/XI` and `/XS` record lengths above 255 crash HexView; hexy rejects them
- `/CS16` `HexDataString` values with characters other than hex digits: HexView's parse is irregular; hexy rejects them
- `/DP` and `/SV` key formats HexView rejects but hexy reads: RSA public keys as SPKI PEM, binary DER or X.509 certificates; RSA private keys as binary PKCS #1 DER; ECC keys with the standard `id-Ed25519` OID or a PEM label other than `PRIVATE KEY` and `EC PRIVATE KEY`; ECC public keys as SPKI or from certificates; P-256 public keys inside PKCS #8 keys (see [data processing](data-processing.md))
- `/DP` hex key files of 2999 bytes or more: HexView fails to read them; hexy reads them
- `/DP` key text with stray characters, such as `12x34`: HexView reads some of them as zero bytes; hexy rejects the text
- `/DP` option values that are not valid, such as `#IV=00;sig.txt`: HexView ignores options a method does not use; hexy rejects them
- `/DP` with more than one `;`, or `@placement` without a following `:`: HexView fails the stage and still exports; hexy rejects the command
- `/DP` output file in a folder that does not exist: HexView writes the default output file instead; hexy fails
- `/DP` ignores `#IV`, `#AUTH`, `#TAG`, `#LZSS` and `#SALT` for methods that do not use them, as HexView does; hexy also warns
- `/DP` ciphers and compression that grow a block into the next block, such as `/SB` pieces or LZSS of random data: HexView keeps both blocks and exports the overlapping bytes twice; hexy keeps the later block's bytes
- `/DP36` ARLE compression of some data with zero bytes, such as `00 00 00 00 02 00 02`: HexView reads past the block and picks other runs; hexy's output decompresses to the same data. Zero bytes that end a block, and data without zero bytes, compress as in HexView
- `/DP19` to `/DP25` and `/DP29` (Vector-specific LZ compression, alone or with RIPEMD-160 signatures and MACs): hexy rejects them. The manual names only their window and length sizes; the coding is proprietary and undocumented, and it is not LZSS
- `/DP55` without `#IV`: HexView takes the IV from the data but drops 16 bytes of ciphertext; hexy rejects the command
- `/DP55` and `/DP56` with `#AUTH=@address,length`: HexView leaves that data unencrypted but also out of the tag; hexy rejects the command
- `/DP56` with a `#TAG` file: HexView never reads it, so the check always fails; hexy rejects the command
- `/DP56` with an image `#TAG` in the middle of a block: HexView decrypts part of the data before it fails; hexy fails without changing the data
- `/DP38`, `/DP39` without `#SALT`: HexView's salt is 32 bytes of the C runtime's `rand()` seeded with the time in seconds, so it changes every second; hexy uses a random salt. With `#SALT` the signatures match; without it each tool verifies the other's
- `/DP50`, `/DP51`: HexView signs with the same nonce for every key and message, which reveals the private key to anyone holding two of its signatures; hexy uses deterministic nonces (RFC 6979). Each tool verifies the other's signatures
- `/DP17`, `/DP40`, `/DP42`: HexView's padding comes from the C runtime's `rand()` with a fixed seed, so its output is the same on every run; hexy pads with random bytes. Each tool decrypts the other's output
- RSA encryption and decryption of more than one padded block: HexView handles only the first. It writes later `/DP17`, `/DP40` and `/DP42` blocks padded but unencrypted, leaves the padding on later `/DP18` blocks, fails later `/DP41` and `/DP43` blocks, and fails a padded `/DP17` block after a block of whole key lengths; hexy processes every block
- `/DP17` blocks that are longer than one padded key length but not a whole number of key lengths, and `/DP18` blocks that are not a whole number of key lengths: HexView writes unusable data; hexy fails
- `/DP52` on more than one block: both fail, but HexView first writes the signature of the first block to the output file; hexy writes no output file
- `/CSM*` and `/CSMR*` are hexy extensions; HexView ignores them
- numbers above 32 bits in range text, `/XC` `WordSize` values other than 0-2 and `/XK` on an empty image crash HexView; hexy reads such a range as unreadable and rejects the others
- a negative range length such as `/CR:8,-4`: HexView leaves overlapping blocks; hexy skips the range
- `/IN` or `/IA` data that would reach past `0xFFFFFFFF`: HexView wraps it around to address 0; hexy fails
- `/XF` with `FLASH ERASE SECTORS` in the INI file: HexView sometimes writes the block list instead, depending on the value and on `FLASH INDICATOR` and `DOWNLOAD FORMAT` (for example a `:start,length` list with `FLASH INDICATOR=1`); hexy always writes the INI text
- `/vs` with a checksum method that fails on the data, such as method 5 on an odd length: HexView still writes its C files; hexy fails the stage without them
- `/vs` with more than 255 blocks in a one-byte count: both write the count modulo 256
- `/L` lines `FileOpen<name>` without a blank, such as `FileOpenx`: HexView fails for some names; hexy empties the image like any other `FileOpen` with a name
- HexView options for OEM containers, GM headers, VBF files and external DLLs (`/XG*`, `/XGAC`, `/XGMFBL`, `/XV`, `/XVBF`, `/XVBFSUBST`, `/MVBF`, `/XB`, `/xfca_sign`, `/PB`, `/expdat`): hexy rejects them; see [the CLI reference](../skill/hexy-compat/references/cli-reference.md)

The boundary here is compatibility claims, not implementation status. Resolved HexView parity findings are not kept as open divergences.

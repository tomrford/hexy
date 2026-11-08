# hexy CLI reference

Compact reference for the cleanroom `hexy` command-line surface for non-proprietary slash-style workflows. Organize commands by execution order, because order controls behavior.

Use binary-form commands such as `hexy input.hex ... -o output.hex`.

The external compatibility target also supports additional proprietary or OEM-specific formats and DLL-backed features that are not covered here.

## Command model

- The first positional argument is the input file; HexView ignores later ones. Without it, the last of `/IN`, `/IA` and `/II2` loads the image, and without either the image starts empty.
- Use slash flags for operations: `/FLAG`, `/FLAG:value`, or `/FLAG=value`.
- Options HexView does not know, such as `/RB:8` with a colon, are reported as unrecognized and skipped, as HexView does. Options HexView knows but hexy does not reproduce are rejected (see the last section).
- Use `-o <file>` for the output path.
- Use `--` before an absolute Unix path if it would otherwise look like an option.
- Expect numeric values to accept decimal, `0x` hex, trailing `h` hex, `0b` or trailing `b` binary, and `_` or `.` separators. `/XI`, `/XS`, `/XA`, `/SB`, `/RB`, `/AL`, the `/IN` and `/IA` offsets, and the `/XC` INI values follow HexView instead: `0x` hex or decimal digits up to the first other character, and no digits reads as 0.
- If several output format flags are given, the last one wins.
- Ranges are `start,length` or `start-end`. As in HexView, each number is `0x` hex (lower-case `x`) or decimal after optional blanks, the start must be followed directly by `,` or `-`, and text after the second number is ignored. Empty ranges and ranges that reach past `0xFFFFFFFF` are skipped; a reversed or unreadable range, such as `1000h,4` or `x`, ends a range list.
- Data is kept as blocks: adjacent data forms one block after every stage that changes data, except that `/SB` pieces stay separate blocks until a checksum or data processing output is placed. `/RB`, `/XSB` and `/DP` work on blocks.

## Execution order

`hexy` applies operations in this order:

1. Read the positional input file, or the last import (`/IN`, `/IA`, `/II2`).
2. Open error log with `/E`.
3. Enable silent mode with `/S`.
4. Apply address mapping with `/S08MAP`, `/S12MAP`, `/S12XMAP`, or `/REMAP`.
5. Apply dsPIC transforms with `/CDSPX`, `/CDSPS`, `/CDSPG`.
6. Fill ranges with `/FR` and `/FP`.
7. Cut ranges with `/CR`.
8. Merge files with `/MT` or `/MO`.
9. Filter address ranges with `/AR`.
10. Execute log commands with `/L`.
11. Collapse to a single region with `/FA`.
12. Align addresses or length with `/AD`, `/AL`, `/AF`, `/AE`.
13. Split blocks with `/SB`.
14. Swap bytes with `/SWAPWORD` or `/SWAPLONG`.
15. Remove small blocks with `/RB`.
16. Apply checksum operations with `/CS`, `/CSR`, `/CSM`, `/CSMR`.
17. Apply supported data processing (signing, MACs, XOR, AES, RSA encryption, compression) with `/DP`.
18. Apply supported signature verification with `/SV`.
19. Export with `/X...` and `-o`.

## Input and runtime

`input.hex`
- Load the main input file as the first positional argument.
- Use `-- /absolute/path.hex` when a Unix path would otherwise be parsed as a slash option.

`/E:error.log`
- Create or truncate an error log file before execution.
- Every warning and error goes there on its own CRLF-terminated line, as in HexView, followed by the `/V` line and the unrecognized options.

`/S`
- Suppress stderr output for warnings and errors.
- Keep using `/E` if you still want an error artifact.

`/V`
- Add `hexy V<version>` to the `/E` log, also after a failure.
- Use it with `/E`; by itself it has nowhere to write.

`/BHFCT`, `/BTFST`, `/BTBS`
- Accept compatibility threshold flags for compatibility.
- Parse the values, but treat them as no-op tuning hints in `hexy`.

`/G`, `/M[:license-file]`
- Accept HexView's disclaimer and license switches; they have no effect in `hexy`.

## Explicit imports

Imports replace the positional input file, so HexView ignores them next to one, with a warning. Only the last import option is used. A missing import file is an error.

`/IN:file[;offset]`
- Import raw binary at `offset`, default `0`. A negative offset wraps around the address space.
- Use this instead of a positional input when the source is not auto-detectable.

`/IA:file[;offset]`
- Import HEX ASCII at `offset`, default `0`.
- Every pair of hex digits is a byte, and a single digit before a separator is a byte of its own (`123` reads `12 03`). A lower-case `x` is skipped, dropping a `0` right before it (`0x12` reads `12`); other characters separate.

`/II2:file`
- Import 16-bit Intel HEX with address values scaled by two.
- All of the value is the file name; it takes no offset.

## Address mapping

`/S08MAP`
- Map Star08 pages to `0x100000 + page * 0x4000`: `0x0000`, `0x4000` and `0xC000` are pages 0, 1 and 3, and the `0x8000-0xBFFF` window of bank `PP` is page `PP` for banks 0, 2 and 4 to `0x1F`. Banks 1 and 3 stay where they are, and `0x0000-0x3FFF` stays when its data would land on data of the bank 0 window.
- Use it before later filtering, checksums, or export.

`/S12MAP`
- Remap S12 physical addresses to linear addresses.
- Do not combine it with `/S12XMAP`, `/S08MAP`, or `/REMAP`.

`/S12XMAP`
- Remap S12X physical addresses to linear addresses.
- Do not combine it with `/S12MAP`, `/S08MAP`, or `/REMAP`.

`/REMAP:start-end,linear,size,inc`
- Banked remap: within `start-end`, source banks start every `inc` bytes, only the first `size` bytes of each bank are remapped, and output windows are packed contiguously from `linear`.
- Use it when you need explicit control instead of the built-in S08/S12 rules.

Mapping cuts blocks where windows start and end. When a mapped piece lands on other data, one block is dropped whole: `/S12MAP` keeps the data already there, the other mappings keep the mapped piece. Between two mapped pieces, the one from the lower source address wins, so non-banked pages win over banks.

## dsPIC transforms

`/CDSPX:range[;target][:range[;target]]...`
- Expand dsPIC words by inserting two zero bytes per two-byte word.
- Omit `target` to write back in place using the default mapping. Text after a range, such as `,target`, is ignored, as in HexView.

`/CDSPS:range[;target]`
- Shrink dsPIC data by keeping the lower two bytes from each four-byte group.
- Use it to convert expanded storage back to packed words.

`/CDSPG:range`
- Clear every fourth byte over the given range for dsPIC ghost-byte cleanup.
- Use multiple ranges with the normal compatibility range syntax.

## Range edits and merges

`/FR:'range1':'range2':...`
- Fill the listed ranges before cuts, merges, and checksums.
- Pair it with `/FP:xxyyzz...`; without `/FP`, `hexy` uses pseudo-random fill bytes.
- HexView ignores `/FR=`; only `/FR:` fills.

`/FP:xxyyzz...`
- Set the fill pattern for `/FR`, read like `/IA` data: `/FP:ABC` is `AB 0C` and `/FP:0xAB` is `AB`. Without any hex digits the fill is random.
- Reuse the pattern cyclically over the requested range.

`/CR:'range1':'range2':...`
- Remove bytes from the listed ranges.
- Use it before `/AR` if the cut should affect later filtering.
- HexView ignores `/CR=`; only `/CR:` cuts.

`/MT:file[;offset][:range][+...]`
- Merge transparently and preserve existing bytes on overlap.
- Use `+` to chain several merge inputs in one flag value.
- `*` and `?` in a file name merge every matching file in its folder, in name order and regardless of case; the offset and range apply to the first match only. A name without wildcards must exist.
- A reversed or unreadable range merges the whole file and fails the run after the export, as in HexView.

`/MO:file[;offset][:range][+...]`
- Merge opaquely and overwrite existing bytes on overlap.
- Takes the same forms as `/MT`. Only the last `/MO` or `/MT` option is used.

`/AR:range[:range...]`
- Keep only the data inside the intersection of the listed ranges; disjoint ranges keep nothing.
- If `/AR` appears more than once, the last `/AR` wins.

`/L:logfile`
- Run HexView log commands after `/AR`, matched case-sensitively at the start of each line. As in HexView's command-line run, `FileNew` and `FileOpen` leave an empty image, and `FileOpen` without a file name also fails; other lines, `FileClose` among them, are ignored.
- A log file that cannot be read is ignored.

`/FA`
- Fill gaps and collapse the image into a single contiguous region.
- Use `/AF` first if the gap fill byte must differ from the default `0xFF`.

## Alignment, split, and swap

`/ADxx`, `/AD:xx`, or `/AD=xx`
- Align block starts down to `xx`; `/ADxx` reads `xx` as hex.
- Use `/AL` if block lengths must also align.

`/AL[:length]`
- Grow each block, counted from its aligned start, to a multiple of `length`, or without it of the `/AD` value. `/AL:length` without `/AD` leaves block starts as they are.
- HexView aligns with the bit mask of the value minus one, and so does hexy: for a power of two that is the multiple, for other values (with a warning for `/AD`) it clears or sets the mask bits instead.

`/AFxx`, `/AF:xx`, or `/AF=xx`
- Set the fill byte for alignment and `/FA` gap filling.
- Default is `0xFF`.

`/AE:xxx`
- Set the erase alignment of the `/XF` erase sectors: each block is widened to the bits of `xxx - 1` around it, and sectors that touch are joined.
- Treat it as Ford-export metadata, not a general transform by itself.

`/SB:maxblocksize`
- Split each block into pieces no larger than `maxblocksize`; the pieces stay separate blocks.
- Values below `0x100` are ignored with a warning, as in HexView.

`/RB=size`
- Remove blocks shorter than `size` bytes, after `/SB` and the swaps. Only `=` is accepted.

`/SWAPWORD`
- Swap bytes within each 16-bit word.
- Like `/SWAPLONG`, nothing changes unless the span from the lowest to the highest address starts and ends on a word boundary; a word whose first byte holds data is swapped, its missing bytes taking the values of the last complete word.
- Apply it after structural edits, before checksum or export.

`/SWAPLONG`
- Swap bytes within each 32-bit word.
- As in HexView, a block of 16 MiB or more repeats its second swapped word after the first.

## Checksums

`/CSx[:target]` and `/CSRx[:target]`
- Compute checksum method `x`; `/CSR` flips the output endianness from the algorithm's native format.
- Omit `:target` to calculate without writing the result anywhere.
- Methods 0-22 are supported. Method 16 writes a constant instead of a checksum: `NumBytes` bytes (default 2) of `HexDataString` (default `0815`) from the `[constant]` section of `expdatproc.ini` in the working directory. Methods 21 and 22 are CRC-16 with the CCITT polynomial and start value `0xCAFE`, little- and big-endian.
- A failed checksum gives a non-zero exit, but the later stages and the export still run, as in HexView.

`/CSMx[:target]` and `/CSMRx[:target]`
- Run multi-checksum mode and allow repeated checksum flags in order.
- Do not combine any `/CS*` form with any `/CSM*` form in one command.

`target`
- Use `@append`, `@begin`, `@upfront`, `@end`, `@0xADDR`, or a file path.
- File targets write the checksum bytes as `0xAA, 0xBB` text instead of modifying the image.

`range modifiers`
- Add `;range` to limit the checksum region; an invalid limiting range covers nothing.
- Add `;!forced_range[#fill]` to force bytes to exist over a range before calculating.
- Add `/exclude_range` after the limited range to subtract specific sub-ranges.

## Data processing and verification

`/DPn[:@placement]:[param1][,param2,param3][;param4][#NAME=value]...`
- Run after checksum operations. Supported methods: `/DP0` (no action), `/DP1` (XOR), AES `/DP2`/`/DP3` (ECB), `/DP11`/`/DP12` (CBC), `/DP53`/`/DP54` (CTR) and `/DP55`/`/DP56` (GCM), HMAC `/DP4`-`/DP7`, `/DP13`, `/DP14`, `/DP30`, `/DP31`, CMAC `/DP44`, `/DP45`, RSA signatures `/DP8`-`/DP10`, `/DP15`, `/DP16`, `/DP28`, `/DP32`, `/DP33`, `/DP38`, `/DP39`, RSA encryption `/DP17`, `/DP18`, `/DP40`-`/DP43`, Ed25519 `/DP46`-`/DP49`, `/DP52`, ECDSA P-256 `/DP50`, `/DP51`, LZSS `/DP26`, `/DP27`, `/DP57`, `/DP58`, LZSS with AES-CBC `/DP34`, `/DP35`, `/DP59`, `/DP60`, and ARLE `/DP36`, `/DP37`. HexView's Vector-specific LZ methods (`/DP19`-`/DP25`, `/DP29`) are rejected before any output is written, and unknown numbers fail when the stage runs. See [data processing](../../../docs/data-processing.md) for the method table.
- param1 is the key: hex text inline (for example a HIS `FF49...` RSA key, a HIS `FF5B...` MAC key, an AES key, an Ed25519 seed or a P-256 scalar), `file,section,key` to read it from an INI file, or a key file (hex text, PEM or DER; symmetric keys must be hex text). See [data processing](../../../docs/data-processing.md) for the key formats.
- For signatures and MACs, param4 is the output file. Without it, the output goes to HexView's default file, such as `SignD_SHA256.RSA` for `/DP32` or `SignD_SHA1.txt` for `/DP4`. The file holds `0xAA ,0xBB` text.
- Everything after the first `#` is options (`#SALT=`, `#IV=`, `#AUTH=`, `#TAG=`, `#LZSS=`), so `key#IV=00;sig.txt` has no param4. Methods ignore options they do not use, with a warning. `#SALT=hex` is the `/DP38` and `/DP39` RSA-PSS salt (at most 255 hex digits are read); without it the salt is 32 random bytes.
- `/DP1` XORs the data with param1, repeated across the blocks; without a hex key it inverts the data.
- AES: the key length picks AES-128, -192 or -256. param4 is the padding (`PKCS7`, `ANSIX.923` or `RFC1321`; the first four letters count). ECB, CBC and CTR process and pad each block on its own; without padding, ECB and CBC need each block to be a multiple of 16 bytes. `#IV=hex` is the CBC or CTR IV, padded with zeros; without it the first 16 bytes of the first block are the IV and stay unencrypted.
- AES-GCM encrypts all blocks as one stream: `#IV` (required) is the nonce, `#AUTH=hex` or a binary file adds authenticated data, and `/DP55` writes the 16-byte tag to `#TAG=file` and to `@placement`. `/DP56` checks `#TAG=hex` or `#TAG=@address,length`, image bytes at the start or end of a block that stay in place.
- RSA encryption (`/DP17` PKCS #1 v1.5, `/DP40` OAEP SHA-1, `/DP42` OAEP SHA-256) encrypts each block on its own with a public key; `/DP17` encrypts blocks of whole key lengths without padding. Decryption needs the private key: `/DP41` and `/DP43` require exactly one key length per block, while `/DP18` accepts whole key lengths and removes PKCS #1 v1.5 padding from a single key length when it is valid.
- Compression replaces each block from its start address. LZSS (`/DP26`/`/DP27`) uses a 10-bit window and 4-bit lengths; `/DP57`/`/DP58` take `#LZSS=window,length` (`0 < length < window < 16`) and fail on any other parameter text, including `#LZSS12,5` without `=`. A block that decompresses to nothing keeps its data. ARLE (`/DP36`/`/DP37`) fails on an incomplete token or empty output.
- `/DP59` compresses with LZSS (`#LZSS` or the default) and then encrypts with AES-CBC; `/DP60` decrypts and then decompresses. `/DP34`/`/DP35` do the same with the default LZSS bits and ignore `#LZSS`. Param4 is the padding and `#IV` the IV; without `#IV` the IV is zero bytes.
- `/DP50`/`/DP51` (ECDSA P-256 over SHA-256) write r and s, 64 bytes; hexy's nonces are deterministic (RFC 6979), so its signatures differ from HexView's but verify the same. `/DP52` (Ed25519 without pre-hash) fails on more than one block.
- Relative paths, including the output file, resolve against the input file's folder, or the working directory without a positional input file.
- The metadata methods (`/DP5`, `/DP7`, `/DP9`, `/DP10`, `/DP14`, `/DP16`, `/DP31`, `/DP33`, `/DP39`, `/DP45`, `/DP47`, `/DP49`, `/DP51`) cover each block's big-endian start address and length followed by its data.
- A failed `/DP` is reported, but the remaining stages still run and the export is still written; the exit status is non-zero. A cipher that fails keeps the blocks it already processed.

`placement`
- Use the same placement targets as checksums except file targets are invalid for in-image placement. The output file is written as well. XOR, AES ECB, CBC and CTR, and RSA encryption have no output, so they ignore placement.

`/SVn:keyinfo!signatureinfo`
- Verify a signature after `/DP`, so a placed signature is part of the verified data. `/SV0`-`/SV3` verify `/DP28`, `/DP9`, `/DP8`, `/DP10`; `/SV4`-`/SV11` verify `/DP32`, `/DP33`, `/DP38`, `/DP39`, `/DP46`-`/DP49`; `/SV12`-`/SV14` verify `/DP50`-`/DP52`. RSA-PSS verification accepts any salt length.
- `keyinfo` takes the `/DP` param1 forms; a private key gives its public key. An ECC private key must include its public key.
- `signatureinfo` is hex text inline, or a file of hex text such as a `/DP` output file.
- A failed verification is reported like a failed `/DP`.

## Output and export

`-o output.ext`
- Write the export to `output.ext`.
- Without `-o`, the export goes to the input file name with the format's extension: `.hex` for `/XI`, `.s19` for `/XS`, `.bin` for `/XN`, `/XP`, `/XSB` and `/XGACSWIL`, `.asc` for `/XA`, `.c` for `/XC`, `.fkl` for `/XK` and `_f.hex` for `/XF`. `/XI` without `-o` therefore overwrites a `.hex` input.
- Without an `/X...` flag nothing is exported, even with `-o`.

`/XI[:reclinelen[:rectype]]`
- Export Intel HEX, 32 bytes per record by default or for length 0.
- `rectype` 1 forces extended linear and 2 extended segment address records; others select automatically (segment records up to 1 MiB). An extended address record is written only where the upper address changes, starting from zero.

`/XS[:reclinelen[:rectype]]`
- Export Motorola S-Record, 32 bytes per record by default.
- `rectype` 0, 1 and 2 force S1, S2 and S3 records; others select automatically.
- A record length of 0, including an empty one (`/XS::2`), writes only the termination record, as HexView does.

`/XN`
- Export one raw binary stream by concatenating segments in ascending address order.
- Use `/FA` first if a single contiguous image matters.

`/XSB`
- Export one binary file per block as `<stem>_<address>` plus the extension of the output name, if any (`-o out.bin` gives `out_1000.bin`).
- Use it when block boundaries matter downstream.

`/XA[:linelen[:separator]]`
- Export HEX ASCII, 16 bytes per line by default or for length 0.
- Every byte is followed by CRLF when it ends a line and by the separator otherwise, the last byte included. The separator is used verbatim, quotes included.

`/XC`
- Export HexView's flash-driver C arrays: `-o` with its extension replaced by `.c` and `.h`, one `<Prefix>Blk<n>` array and `_ADDRESS`, `_LENGTH` and `_CHECKSUM` macros per block. Without `-o`, the files are named after the input file's full path.
- `[C_EXPORT]` in the INI file sets `Prefix` (default empty), `WordSize` (0 bytes, 1 16-bit, 2 32-bit words), `WordType` (0 Intel, otherwise Motorola), `Decryption` (default on; off drops the XOR) and `Decryptvalue` (the XOR value, default 0). A partial last word is padded with zero bytes, and `_CHECKSUM` is the 16-bit (32-bit for `WordSize=2`) sum of the plain words.
- Each file records its creation time, and `<PREFIX>_GEN_RAND` is a time-seeded number that ties the two files together, as in HexView.

`/XK`
- Export a CCP/XCP flash kernel (`.fkl`): a `[FLASH_KERNEL_CONFIG]` header followed by the kernel as Intel HEX. The image must be a single block; use `/FA` to make it one.
- `[FLASH_KERNEL_CONFIG]` in the INI file sets `FLASH_KERNEL_NAME` (default the output file name), `FLASH_KERNEL_COMMENT` (default `Flash kernel <name>`), `FLASH_KERNEL_FILE_ADDR`, `FLASH_KERNEL_SIZE`, `FLASH_KERNEL_RAM_ADDR` and `FLASH_KERNEL_RAM_START` (default the block's start and length). Values are copied as text.
- `FLASH_KERNEL_RAM_START=@file.map:pattern` takes the address from the first map file line that `pattern` matches, with `%lx` at the address, as C's `sscanf` reads it; without a match the text is kept.
- As HexView does, the name, comment and RAM values that the INI file lacks are written back to it, creating it if needed.

`/XGACSWIL`
- Export a GAC software interlock file: the block count as one byte, each block's big-endian start address and length, then the data of every block. An empty image writes no file.

`/XF`
- Export a Ford Intel HEX file: a `KEY>value` header from `[FORDHEADER]`, `$`, then the data as Intel HEX.
- Header lines appear in HexView's order and only for keys the INI file sets, except `FILE NAME` (default the output file name), `RELEASE DATE` (default today's local date), `DOWNLOAD FORMAT` (default `0x01`), `FILE CHECKSUM` (always the 16-bit sum of the data bytes), `FLASH INDICATOR` (default `1`) and `FLASH ERASE SECTORS` (default the blocks as `:start,length`, widened by `/AE`).
- Without `PRODUCTION MODULE PART NUMBER` or `MODULE ID` the file stops before that line and holds no data, with a warning; the run still succeeds, as in HexView.

`/XP`
- Export the image as one region, gaps filled with the `/AF` byte, followed by the checksum of the first `/CS` or `/CSM` method over it, big-endian and without the method's ranges. The `/CS` stage still runs as usual, so `/CS0:@append` places its checksum before `/XP` adds its own.
- Without a `/CS` method, or with one HexView does not know, the data is written alone and the run fails, as in HexView.

## INI-backed exports

`/P:file.ini`
- Supply extra parameters for export modes that require side metadata: `[C_EXPORT]` for `/XC`, `[FLASH_KERNEL_CONFIG]` for `/XK` and `[FORDHEADER]` for `/XF`.
- If omitted, `hexy` looks for `<input>.ini`, or the import file with `.ini`.

## Unsupported or out-of-scope

These HexView options are rejected, because their formats or DLLs are not documented well enough to reproduce:

- `/XG`, `/XGC`, `/XGCC`, `/XGCS`, `/XGCR`, `/XGCK` and `/XGC_*` (GM file headers, defined in GMW3110), `/XGMFBL` (GM-FBL header info) and `/XGAC` (GAC file header)
- `/XV` (VAG SGML container), `/XVBF`, `/XVBFSUBST` and `/MVBF` (Ford and Volvo VBF), `/XB` (Fiat binary and parameter files) and `/xfca_sign` (FCA header)
- `/PB` (post-build DLL) and `/expdat` (alternative data processing DLL)
- `/vs` and `/vshsm` (validation structures)

The GM header parameters (`/DLS`, `/DCID`, `/MPFH`, `/MODID`, `/PN`, `/SWMI`, `/sigver`, `/sigkeyid`, `/gmad`, `/gmal`, `/XML`), `/DIFF` (which needs a diff DLL HexView does not ship) and the `/tms570-parity` and `/tms570-ECC` options, which HexView 1.15.2 does not recognize, are reported as unrecognized and have no effect.

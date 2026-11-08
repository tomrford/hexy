# hexy CLI reference

Compact reference for the cleanroom `hexy` command-line surface for non-proprietary slash-style workflows. Organize commands by execution order, because order controls behavior.

Use binary-form commands such as `hexy input.hex ... -o output.hex`.

The external compatibility target also supports additional proprietary or OEM-specific formats and DLL-backed features that are not covered here.

## Command model

- Use one positional input file unless an explicit import flag replaces it.
- Use slash flags for operations: `/FLAG`, `/FLAG:value`, or `/FLAG=value`.
- Use `-o <file>` for the output path.
- Use `--` before an absolute Unix path if it would otherwise look like an option.
- Expect numeric values to accept decimal, `0x` hex, trailing `h` hex, `0b` or trailing `b` binary, and `_` or `.` separators. `/XI`, `/XS`, `/XA`, `/SB` and `/RB` values follow HexView instead: `0x` hex or decimal digits up to the first other character, and no digits reads as 0.
- If several output format flags are given, the last one wins.
- Ranges that are empty or reach past `0xFFFFFFFF` are skipped and a reversed range ends a range list, as in HexView; malformed range text is an error.
- Data is kept as blocks: adjacent data forms one block after every stage that changes data, except that `/SB` pieces stay separate blocks until a checksum or signature is placed. `/RB`, `/XSB` and `/DP` metadata work on blocks.

## Execution order

`hexy` applies operations in this order:

1. Read positional input file.
2. Open error log with `/E`.
3. Enable silent mode with `/S`.
4. Import 16-bit Intel HEX with `/II2`.
5. Apply address mapping with `/S08MAP`, `/S12MAP`, `/S12XMAP`, or `/REMAP`.
6. Apply dsPIC transforms with `/CDSPX`, `/CDSPS`, `/CDSPG`.
7. Fill ranges with `/FR` and `/FP`.
8. Cut ranges with `/CR`.
9. Merge files with `/MT` or `/MO`.
10. Filter address ranges with `/AR`.
11. Execute log commands with `/L`.
12. Collapse to a single region with `/FA`.
13. Align addresses or length with `/AD`, `/AL`, `/AF`, `/AE`.
14. Split blocks with `/SB`.
15. Swap bytes with `/SWAPWORD` or `/SWAPLONG`.
16. Remove small blocks with `/RB`.
17. Apply checksum operations with `/CS`, `/CSR`, `/CSM`, `/CSMR`.
18. Apply supported data processing (signing) with `/DP`.
19. Apply supported signature verification with `/SV`.
20. Export with `/X...` and `-o`.

## Input and runtime

`input.hex`
- Load the main input file as the first positional argument.
- Use `-- /absolute/path.hex` when a Unix path would otherwise be parsed as a slash option.

`/E:error.log`
- Create or truncate an error log file before execution.
- Write the final error text there on failure.

`/S`
- Suppress stderr output for normal CLI failures.
- Keep using `/E` if you still want an error artifact.

`/V`
- Append the version string to the `/E` log after successful execution.
- Use it with `/E`; by itself it has nowhere to write.

`/BHFCT`, `/BTFST`, `/BTBS`
- Accept compatibility threshold flags for compatibility.
- Parse the values, but treat them as no-op tuning hints in `hexy`.

`/G`, `/M[:license-file]`
- Accept HexView's disclaimer and license switches; they have no effect in `hexy`.

## Explicit imports

`/IN:file[;offset]`
- Import raw binary at `offset`, default `0`.
- Use this instead of a positional input when the source is not auto-detectable.

`/IA:file[;offset]`
- Import HEX ASCII at `offset`, default `0`.
- Use it to force ASCII-hex parsing even when the source is not the main positional file.

`/II2:file`
- Import 16-bit Intel HEX with address values scaled by two.
- Do not combine it with `/IN`, `/IA`, or a positional input file.

## Address mapping

`/S08` or `/S08MAP`
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

`/CDSPX:range[;target]`
- Expand dsPIC words by inserting two zero bytes per two-byte word.
- Omit `target` to write back in place using the default mapping.

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

`/FP:xxyyzz...`
- Set the fill pattern for `/FR`.
- Reuse the pattern cyclically over the requested range.

`/CR:'range1':'range2':...`
- Remove bytes from the listed ranges.
- Use it before `/AR` if the cut should affect later filtering.

`/MT:file[;offset][:range][+...]`
- Merge transparently and preserve existing bytes on overlap.
- Use `+` to chain several merge inputs in one flag value.

`/MO:file[;offset][:range][+...]`
- Merge opaquely and overwrite existing bytes on overlap.
- Do not combine `/MO` and `/MT` in the same command.

`/AR:range[:range...]`
- Keep only the data inside the intersection of the listed ranges; disjoint ranges keep nothing.
- If `/AR` appears more than once, the last `/AR` wins.

`/L:logfile`
- Replay supported slash-style log commands from a file.
- Use it for `FileClose` and `FileNew` cleanup/reset steps.
- `FileOpen <path>` is rejected in command-line export; pass inputs through normal CLI input paths.

`/FA`
- Fill gaps and collapse the image into a single contiguous region.
- Use `/AF` first if the gap fill byte must differ from the default `0xFF`.

## Alignment, split, and swap

`/ADxx`, `/AD:xx`, or `/AD=xx`
- Align segment starts to `xx`.
- Use `/AL` if the final region length must also align.

`/AL[:length]`
- Align overall length in addition to address alignment.
- If `length` is provided, it also sets the alignment value.

`/AFxx`, `/AF:xx`, or `/AF=xx`
- Set the fill byte for alignment and `/FA` gap filling.
- Default is `0xFF`.

`/AE:xxx`
- Set the erase-alignment value used by Ford export sector formatting.
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

## Signing and verification

`/DPn[:@placement]:[param1][,param2,param3][;param4][#NAME=value]...`
- Run after checksum operations. Supported methods are `/DP32`, `/DP33`, `/DP38`, `/DP39`, `/DP46`, `/DP47`, `/DP48`, `/DP49`; other HexView methods are rejected before any output is written, and unknown numbers fail when the stage runs.
- param1 is the key: hex text inline (for example a HIS `FF49...` key or an Ed25519 seed), `file,section,key` to read it from an INI file, or a key file (hex text, PEM or DER). See [data processing](../../../docs/signatures.md) for the key formats.
- param4 is the output file. Without it, the signature goes to HexView's default file, such as `SignD_SHA256.RSA` for `/DP32`. The file holds `0xAA ,0xBB` text.
- Everything after the first `#` is options (`#SALT=`, `#IV=`, `#AUTH=`, `#TAG=`, `#LZSS=`), so `key#IV=00;sig.txt` has no param4. The signing methods ignore these options with a warning; `#SALT` with `/DP38` and `/DP39` is not supported yet.
- Relative paths, including the output file, resolve against the input file's folder, or the working directory without a positional input file.
- The metadata methods (`/DP33`, `/DP39`, `/DP47`, `/DP49`) sign each block's big-endian start address and length followed by its data.
- A failed `/DP` is reported, but the remaining stages still run and the export is still written; the exit status is non-zero.

`placement`
- Use the same placement targets as checksums except file targets are invalid for in-image placement. The output file is written as well.

`/SVn:keyinfo!signatureinfo`
- Verify a signature after `/DP`, so a placed signature is part of the verified data. Supported methods are `/SV4` through `/SV11`.
- `keyinfo` takes the `/DP` param1 forms; a private key gives its public key.
- `signatureinfo` is hex text inline, or a file of hex text such as a `/DP` output file.
- A failed verification is reported like a failed `/DP`.

## Output and export

`-o output.ext`
- Write the export to `output.ext`.
- Without `-o`, the export goes to the input file name with the format's extension: `.hex` for `/XI`, `.s19` for `/XS`, `.bin` for `/XN`, `/XP` and `/XSB`, `.asc` for `/XA`, `.c` for `/XC` and `_f.hex` for `/XF`. `/XI` without `-o` therefore overwrites a `.hex` input.
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
- Export C source and header output using INI-driven settings from `/P`.
- Use it when a bootloader or firmware build needs C arrays instead of hex files.

`/XF`
- Export Ford Intel-HEX container output using `[FORDHEADER]` values from `/P`.
- Use `/AE` when Ford erase-sector formatting must align to a specific boundary.

`/XP`
- Export Porsche binary output with the required trailer checksum.
- Use it only when the downstream format expects Porsche-style single-region binary output.

## INI-backed exports

`/P:file.ini`
- Supply extra parameters for export modes that require side metadata.
- Use it with `/XC` and `/XF`; if omitted, `hexy` looks for `<input>.ini`.

## Unsupported or out-of-scope

- Treat `/PB`, `/expdat`, OEM containers, GM/VBF/FIAT-specific exports, and other proprietary external-tool extensions as out of scope here.
- Output formats `/XG*` (GCC), `/XK` (Keil), `/XV`, `/XVBF`, and `/XB` are recognized by the parser but not yet implemented; using them produces an error.
- Treat this reference as the shared CLI surface that `hexy` implements for non-proprietary workflows.

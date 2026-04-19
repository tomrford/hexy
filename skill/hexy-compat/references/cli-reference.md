# hexy / HexView CLI reference

Compact reference for the shared non-proprietary `hexy` and HexView command-line surface. Organize commands by execution order, because order controls behavior.

Use binary-form commands such as `hexy input.hex ... -o output.hex`. Keep one output format per command.

HexView also supports additional proprietary or OEM-specific formats and DLL-backed features that are not covered here.

## Command model

- Use one positional input file unless an explicit import flag replaces it.
- Use slash flags for operations: `/FLAG`, `/FLAG:value`, or `/FLAG=value`.
- Use `-o <file>` for the output path.
- Use `--` before an absolute Unix path if it would otherwise look like an option.
- Expect numeric values to accept decimal, `0x` hex, trailing `h` hex, `0b` or trailing `b` binary, and `_` or `.` separators.
- Expect only one output format flag in a command.

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
16. Apply checksum operations with `/CS`, `/CSR`, `/CSM`, `/CSMR`.
17. Apply supported signing with `/DP`.
18. Apply supported signature verification with `/SV`.
19. Export with `/X...` and `-o`.

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
- Accept HexView threshold flags for compatibility.
- Parse the values, but treat them as no-op tuning hints in `hexy`.

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
- Apply the shared S08 banked mapping rules.
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

## dsPIC transforms

`/CDSPX:range[,target]`
- Expand dsPIC words by inserting two zero bytes per two-byte word.
- Omit `target` to write back in place using the default mapping.

`/CDSPS:range[,target]`
- Shrink dsPIC data by keeping the lower two bytes from each four-byte group.
- Use it to convert expanded storage back to packed words.

`/CDSPG:range`
- Clear every fourth byte over the given range for dsPIC ghost-byte cleanup.
- Use multiple ranges with the normal HexView range syntax.

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

`/AR:'range1':'range2':...`
- Keep only the listed address ranges after earlier edits and merges.
- Use it late when you want upstream operations to see the full image first.

`/L:logfile`
- Replay HexView-style log commands from a file.
- Use it when a workflow is already captured as `FileOpen`, `FileClose`, or `FileNew` steps.

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
- Split large regions into chunks no larger than `maxblocksize`.
- Use it before export when downstream consumers require bounded block sizes.

`/SWAPWORD`
- Swap bytes within each 16-bit word.
- Apply it after structural edits, before checksum or export.

`/SWAPLONG`
- Swap bytes within each 32-bit word.
- Use it for DWORD-endian reshaping before final output.

## Checksums

`/CSx[:target]` and `/CSRx[:target]`
- Compute checksum method `x`; `/CSR` flips the output endianness from the algorithm's native format.
- Omit `:target` to default to `@append`.

`/CSMx[:target]` and `/CSMRx[:target]`
- Run multi-checksum mode and allow repeated checksum flags in order.
- Do not combine any `/CS*` form with any `/CSM*` form in one command.

`target`
- Use `@append`, `@begin`, `@upfront`, `@end`, `@0xADDR`, or a file path.
- File targets write checksum bytes out-of-band instead of modifying the image.

`range modifiers`
- Add `;range` to limit the checksum region.
- Add `;!forced_range[#fill]` to force bytes to exist over a range before calculating.
- Add `/exclude_range` after the limited range to subtract specific sub-ranges.

## Signing and verification

`/DPn[:@placement]:keyinfo[;outfilename]`
- Run the supported signing subset after checksum operations.
- Pass the signing key as `keyinfo`; HexView-style trailing metadata fields are not needed for normal `hexy` use.
- Supported methods are `/DP32`, `/DP33`, `/DP38`, `/DP39`, `/DP46`, `/DP47`, `/DP48`, `/DP49`.

`placement`
- Use the same placement targets as checksums except file targets are invalid for in-image placement.
- Use `;outfilename` to write the signature bytes to a separate file.

`/SVn:keyinfo!signatureinfo`
- Verify a signature after all prior transforms.
- Supported methods are `/SV4` through `/SV11`.

## Output and export

`-o output.ext`
- Write the chosen export to `output.ext`.
- Treat it as required for most practical commands.

`/XI[:reclinelen[:rectype]]`
- Export Intel HEX.
- Use `rectype` only when `reclinelen` is also present.

`/XS[:reclinelen[:rectype]]`
- Export Motorola S-Record.
- Use `rectype` only when `reclinelen` is also present.

`/XN`
- Export one raw binary stream by concatenating segments in ascending address order.
- Use `/FA` first if a single contiguous image matters.

`/XSB`
- Export one binary file per segment, with the base address added to the filename.
- Use it when segment boundaries matter downstream.

`/XA[:linelen[:separator]]`
- Export HEX ASCII.
- Set a separator when a consumer needs tokenized output instead of contiguous pairs.

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

- Treat `/PB`, `/expdat`, OEM containers, GM/VBF/FIAT-specific exports, and other proprietary HexView extensions as out of scope here.
- Output formats `/XG*` (GCC), `/XK` (Keil), `/XV`, `/XVBF`, and `/XB` are recognized by the parser but not yet implemented; using them produces an error.
- Treat this reference as the shared CLI surface that `hexy` implements for non-proprietary workflows.

---
name: hexy-compat
description: "Guide for hexy, a cleanroom slash-compatible CLI for non-proprietary firmware workflows. Use when working with hexy slash-style pipelines for Intel HEX, S-Record, HEX ASCII, or binary files — range edits, merges, checksums, supported data processing (signing, MACs, XOR, AES, RSA encryption, compression) and verification, remaps, and export, including C arrays and CCP/XCP flash kernels."
---

# hexy-compat

Use `hexy` as a pipeline tool. Load one input image, apply ordered operations, then export once.

Treat operation order as part of the interface. Do not reorder flags casually. `hexy` applies flags in its fixed execution pipeline, and each stage sees the result of earlier stages in that pipeline.

Use slash-style compatibility syntax in examples and commands. Keep examples in installed-binary form such as `hexy input.hex /CR:'0x1000-0x1FFF' /CS0 /XI -o output.hex`.

Keep CLI parsing rules in mind:

- Use `-o <file>` for the output path; without it the export overwrites or creates the input name with the format's extension, and without an `/X...` flag nothing is exported. Most other options use `/FLAG:value` or `/FLAG=value`.
- Use `--` before an absolute Unix path if it might be mistaken for a slash option.
- Expect the first positional argument to be the input file; without one the last `/IN`, `/IA` or `/II2` import loads the image. Options HexView does not know are reported and skipped, as in HexView, and warnings go to the `/E` file.
- Expect numeric arguments to accept common compatibility forms such as `0x1234`, `1234h`, `0b1010`, and separators like `_` or `.`.
- Expect `/DP` and `/SV` to resolve relative key, signature and output paths against the input file's folder, and `/DP` signatures and MACs without `;outfile` to write HexView's default output file, such as `SignD_SHA256.RSA`. For AES methods, including LZSS with AES-CBC (`/DP34`, `/DP35`, `/DP59`, `/DP60`), param4 is the padding, not a file; RSA encryption ignores it. LZSS (`/DP26`, `/DP27`, `/DP57`, `/DP58`) and ARLE (`/DP36`, `/DP37`) compression replace block data; `/DP57`-`/DP60` take `#LZSS=window,length`.

Read [cli-reference.md](references/cli-reference.md) for the actual interface. Scan the execution-order section first, then jump to the specific stage you need.

Use the reference to answer questions like:

- which flag to use for a given transformation
- which order to place fill, cut, merge, checksum, and export flags
- which import or export format matches the current file
- which checksum or data processing subset is available in `hexy`
- which external compatibility-target features are intentionally out of scope here

Treat this skill as CLI-only. The external compatibility target also supports additional proprietary or OEM-specific formats and DLL-backed features that are not covered here.

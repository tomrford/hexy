# TODO

Post-API-simplification active issues.

Public core model is `HexFile`, `Segment`, `AddressRange`. No public CLI layer, no pipeline/flag surface, no in-memory CLI execution path.

Current compatibility gaps / divergences are tracked in [known-divergences.md](known-divergences.md).

## Compatibility Follow-ups

These are contract questions, not just implementation bugs.

### `/XN` ordering

Question: should binary export preserve raw insertion order or sorted address order?

Current state:
- `HexFile` documents raw segment operations as preserving insertion order
- [`write_binary`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/io/binary.rs) sorts by address before concatenation

Need:
- verify behavior externally when it matters
- then either document current behavior as correct or change it

### `/L` `FileOpen` path base

Question: should paths in log files resolve relative to cwd or relative to the log file location?

Current state:
- [`parse_log_commands`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/ops/log.rs) preserves the literal path
- [`execute_log_commands`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/ops/log.rs) later resolves through the caller/load closure, which currently makes CLI behavior cwd-relative

Need:
- verify behavior externally when it matters
- then either keep cwd-relative resolution or make log-file-relative resolution explicit

## Needs Design / More Consideration

These are real issues, but the right fix is less mechanical.

### Ambiguous key / signature source parsing

[`crates/hexy-core/src/signature.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/signature.rs)

`SignatureKeySource::Auto` and `SignatureBytesSource::Auto` still use `path.exists()` to choose between filesystem input and inline material.

Problem:
- cwd files can shadow intended inline input
- missing file-looking strings can be accepted as inline bytes or literal key material

Needs a decision on explicit source syntax or stricter rejection rules.

### `/DP` placement plus `/SV` hashes different images

[`crates/hexy-compat/src/args/signature.rs`](/Users/tomford/code/projects/hexy/crates/hexy-compat/src/args/signature.rs)
[`crates/hexy-compat/src/args/execute.rs`](/Users/tomford/code/projects/hexy/crates/hexy-compat/src/args/execute.rs)

`/DP` signs pre-placement bytes, then mutates the image by placing the signature. `/SV` verifies against the post-placement image.

Current repro:
- same-invocation placed signing plus verification fails, for example `/DP32:@append:...` with `/SV4:...`

Needs a decision:
- reject same-invocation placed `/DP` + `/SV`
- or define and implement exclusion rules for the placed signature range

### `normalized()` performance

[`crates/hexy-core/src/hexfile.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/hexfile.rs)

Two separate costs:

1. **Redundant normalization** — a single CLI run may normalize multiple times (align, checksum, output) even when nothing changed between calls. A dirty-flag on `HexFile` (cleared on mutation, checked in `normalized()`) would skip re-work when the file is already flat.

2. **Quadratic overlap resolution** — when overlaps exist, `overlay_segment()` walks all existing segments per new segment (O(n²) in segment count, each step clones). Only fires when `has_overlap` is true; the common fast path (sort + merge adjacent) is O(n log n). Fixing this properly requires an interval-tree or byte-level merge buffer.

Likely not a problem for real firmware hex files (<100 non-overlapping segments). Revisit if profiling shows otherwise.

### Full-span `AddressRange` support

[`crates/hexy-core/src/range.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/range.rs)
[`crates/hexy-core/src/ops/filter.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/ops/filter.rs)
[`crates/hexy-core/src/ops/checksum.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/ops/checksum.rs)
[`crates/hexy-core/src/ops/transform.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/ops/transform.rs)
[`crates/hexy-compat/src/args/execute.rs`](/Users/tomford/code/projects/hexy/crates/hexy-compat/src/args/execute.rs)

`AddressRange` currently rejects `0x00000000..=0xFFFFFFFF` because the type contract assumes `length() -> u32`. That keeps range math simple, but leaks into edge cases like `merge_ranges()`, where two adjacent valid ranges cannot be coalesced into the full span.

Follow-up redesign if/when this matters:
- decide whether the public contract should support the full span explicitly
- if yes, widen range length semantics (`u64`, `Option<u32>`, or a half-open representation)
- audit all materialization/allocation call sites that currently cast `range.length()` to `usize`

Do not treat this as just a constructor tweak; it is a small API redesign plus an allocation-behavior audit.

### Full-span materialization in sparse images

[`crates/hexy-core/src/ops/filter.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/ops/filter.rs)
[`crates/hexy-core/src/hexfile.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/hexfile.rs)
[`crates/hexy-core/src/io/binary.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/io/binary.rs)
[`crates/hexy-compat/src/args/io.rs`](/Users/tomford/code/projects/hexy/crates/hexy-compat/src/args/io.rs)

`fill_gaps`, `as_contiguous`, gap-filled binary output, and Porsche output still allocate the whole `min..=max` span.

Needs:
- explicit bounds / error behavior
- or streaming output paths for sparse images

### Forced-range checksum builds full synthetic data first

[`crates/hexy-core/src/ops/checksum.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/ops/checksum.rs)

Forced-range checksum still constructs a whole pattern-backed segment before exclusions are applied.

Needs a more careful checksum-collection refactor.

### Refine signature API in library

[`crates/hexy-core/src/signature.rs`](/Users/tomford/code/projects/hexy/crates/hexy-core/src/signature.rs)
[`crates/hexy-compat/src/args/signature.rs`](/Users/tomford/code/projects/hexy/crates/hexy-compat/src/args/signature.rs)

Signing, verification, placement, and source resolution now live in the library. The compat CLI should stay as a thin HexView-argument adapter.

Follow-ups worth considering:
- decide whether the library should grow a higher-level typed request layer for the HexView signature modes
- keep the CLI as a thin adapter over the library API, not a second crypto implementation

### CLI architecture: clap + HexView compat mode

The CLI is entirely hand-rolled to match HexView's `/`-prefix syntax. This is correct for drop-in compat, but means no `--help`, no shell completions, no discoverable native args.

Future direction under consideration: `hexy --hexview "/AR:'...' /CS1:@append" input.hex -o output.hex` — clap manages the outer shell (input, output, `--hexview`, `--help`, `--version`, future native flags), the existing hand-rolled parser handles the HexView string verbatim.

Open questions:
- should bare `/`-flags continue to work without `--hexview` for backward compat, or require the explicit mode switch?
- what native features (if any) warrant clap args beyond `--hexview`?

Deferred until more real-world usage clarifies the need.

## API Ergonomics

Keep the canonical public model as `HexFile` + `Segment` + `AddressRange`.

Possible thin ergonomic additions without introducing a second public data model:
- `HexFile::from_bytes(base, data)`
- `HexFile::extend_segments(iter)`
- `impl From<(u32, Vec<u8>)> for Segment`
- examples for parse -> mutate -> write
- examples for single-blob callers and sparse-patch callers

# hexy-py

Python bindings for the `hexy-core` Rust crate.

`HexFile.from_file(path)` reads a file and auto-detects Intel HEX, S-Record, or
raw binary with the same content sniffing used by the compat CLI. Use
`HexFile.from_file_bytes(data)` for the same auto-detection against in-memory
file bytes. Explicit parsers such as `HexFile.from_intel_hex(data)` remain
available when the format is known.

File writers mirror the in-memory serializers:
`write_intel_hex(path)`, `write_srec(path)`, `write_binary(path)`, and
`write_hex_ascii(path)`.

`Pipeline` is the reusable operation recipe API over `hexy_core::Pipeline`. It
applies stages in the same order as the compat CLI, not in the order methods are
called, and `apply` returns the processed `hexfile` with the `checksums` in stage
order and the `data_processing` output (the signature from `sign`). For ad-hoc
custom ordering, call methods directly on `HexFile`.

`sign` and `verify_signature` take a key file's content (bytes) or key text (str)
and read it as HexView does; see `docs/signatures.md` for the key formats.

Range-taking Python APIs use one range string for single-range operations and a
list of range strings for operations that accept multiple ranges. Each string
uses the same range syntax as the compat CLI.

Sparse files stay sparse for inspection and in-memory operations. Dense exports
such as `to_bytes()` and `to_binary(fill_gaps=...)` allocate across the covered
address span, so sparse inputs with far-apart segments can intentionally produce
large byte strings.

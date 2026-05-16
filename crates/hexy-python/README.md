# hexy-hexfile

Python bindings for the `hexy-core` Rust crate.

`HexFile.from_file(path)` reads a file and auto-detects Intel HEX, S-Record, or
raw binary with the same content sniffing used by the compat CLI. Use
`HexFile.from_file_bytes(data)` for the same auto-detection against in-memory
file bytes. Explicit parsers such as `HexFile.from_intel_hex(data)` remain
available when the format is known.

File writers mirror the in-memory serializers:
`write_intel_hex(path)`, `write_srec(path)`, `write_binary(path)`, and
`write_hex_ascii(path)`.

`Pipeline` is the reusable operation recipe API. It applies operations in hexy
CLI compatibility order, not in the order methods are called. For ad-hoc custom
ordering, call methods directly on `HexFile`.

Range-taking Python APIs use one range string for single-range operations and a
list of range strings for operations that accept multiple ranges. Each string
uses the same range syntax as the compat CLI.

Sparse files stay sparse for inspection and in-memory operations. Dense exports
such as `to_bytes()` and `to_binary(fill_gaps=...)` allocate across the covered
address span, so sparse inputs with far-apart segments can intentionally produce
large byte strings.

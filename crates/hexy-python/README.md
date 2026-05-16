# hexy-hexfile

Python bindings for the `hexy-core` Rust crate.

`Pipeline` is the reusable operation recipe API. It applies operations in hexy
CLI compatibility order, not in the order methods are called. For ad-hoc custom
ordering, call methods directly on `HexFile`.

Sparse files stay sparse for inspection and in-memory operations. Dense exports
such as `to_bytes()` and `to_binary(fill_gaps=...)` allocate across the covered
address span, so sparse inputs with far-apart segments can intentionally produce
large byte strings.

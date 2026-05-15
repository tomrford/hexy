# hexy-hexfile

Python bindings for the `hexy-core` Rust crate.

`Pipeline` is the reusable operation recipe API. It applies operations in hexy
CLI compatibility order, not in the order methods are called. For ad-hoc custom
ordering, call methods directly on `HexFile`.

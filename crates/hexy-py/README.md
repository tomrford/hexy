# hexy-py

Python bindings for the `hexy-core` Rust crate. `python/hexy/__init__.pyi` documents
every class and method.

- `HexFile` holds an image as segments and has a method for every core operation,
  named as the `Pipeline` stage it configures: `fill`, `cut`, `merge`, `filter`,
  `align`, `checksum`, `process_data`, `verify`, `validation_structure` and so on.
  Operations change the image in place; `copy()` and `normalized()` return new ones.
- `Pipeline` runs the configured stages in HexView's order, whatever order they were
  set in, and `apply` returns a `PipelineResult` with the image, the checksums, the
  data processing output and the validation structures.
- `DataProcessing.sign`, `.mac`, `.xor`, `.encrypt`, `.decrypt`, `.compress` and
  `.decompress` build the `/DP` operations that `process_data` runs.
- `from_file` and `from_file_bytes` detect Intel HEX, S-Record or raw binary as the CLI
  does; `from_intel_hex`, `from_srec` and the others read a known format. `to_*`
  methods return file contents and `write_*` methods write them.

Conventions:

- A range is an `AddressRange` or range text as HexView reads it (`0x1000-0x10FF` or
  `0x1000,0x100`); methods that take several ranges take a list.
- Checksum methods are HexView `/CS` indices. Other selectors are lower-case names,
  such as `"preserve"`, `"rsa-pss-sha256"` or `"overwrite-end"`.
- Asymmetric keys are a key file's content (bytes) or key text (str). Symmetric keys
  are the raw key (bytes) or key text (str), read as HexView reads a key file; see
  `docs/data-processing.md` for the key formats.
- Errors from the data are `hexy.HexyError` subclasses: `RangeError`, `ParseError`,
  `OperationError`, `ProcessingError` and its `VerificationError`. Unknown selector
  names raise `ValueError`, and file errors `OSError`.

Sparse files stay sparse. `to_binary(fill_gaps=...)` and `fill_gaps()` allocate across
the covered address span, so far-apart segments can produce large byte strings.

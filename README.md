# hexy

Hexy is a reusable binary file modification library based on a cleanroom implementation of Vector HexView.

## Which surface?

| Surface | Install | Use when |
|---------|---------|----------|
| `hexy-core` | `cargo add hexy-core` | Building Rust tools that need parsers, memory ops, checksums, or signatures |
| `hexy-compat` | `cargo install hexy-compat` | Running HexView-style slash-flag workflows from the shell (installs the `hexy` command) |
| `hexy-py` | `pip install hexy-py` | Scripting in Python with in-memory hex editing and `Pipeline` recipes |

`hexy-compat` is the HexView-compatible CLI built on `hexy-core`. `hexy-py` wraps a subset of the core API for Python. Coverage differs between surfaces — see [known divergences](docs/known-divergences.md) for what each crate exposes and where HexView parity is still incomplete.

For the full slash-flag reference, see [cli-reference.md](skill/hexy-compat/references/cli-reference.md).

## Install

```bash
cargo add hexy-core          # library
cargo install hexy-compat    # installs the `hexy` CLI binary
pip install hexy-py
```

## Quick examples

```bash
# Filter a range and export Intel HEX
hexy input.hex /AR:'0x1000-0x1FFF' /XI -o output.hex

# Fill, cut, checksum, then export S-Record
hexy app.hex /FR:'0x0-0xFFF' /FP:FF /CR:'0x800-0x8FF' /CS0 /XS -o app.s19

# Merge a calibration overlay and export binary
hexy base.hex /MO:cal.hex /XN -o combined.bin

# Export one binary per segment (writes segments_<addr>.bin alongside -o path)
hexy multi.hex /XSB -o segments.bin
# -> segments_1000.bin, segments_2000.bin, ...
```

## Workspace commands

Local development uses rustup (`cargo`) and `uv`. CI installs the same tools directly.

```bash
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run -p hexy-compat -- /XI input.hex -o output.hex
uv run --directory crates/hexy-py --group dev maturin develop
uv run --directory crates/hexy-py --group dev pytest tests
```

## Operation order

Compat flags execute in a fixed pipeline order, not in argument order. Steps 2-11 are the stages of `hexy_core::Pipeline`, which the CLI builds from its flags:

1. Input: the positional file, or the last of `/IN`, `/IA` and `/II2`
2. Address mapping (`/S08MAP`, `/S12MAP`, `/S12XMAP`, `/REMAP`)
3. dsPIC transforms (`/CDSPX`, `/CDSPS`, `/CDSPG`)
4. Fill (`/FR`; `/FP` sets the pattern, random fill when omitted)
5. Cut (`/CR`)
6. Merge (`/MT` or `/MO`)
7. Address range filter (`/AR`)
8. Collapse (`/FA`), align (`/AD`, `/AL`, `/AF`), split (`/SB`), swap (`/SWAPWORD`, `/SWAPLONG`), remove small blocks (`/RB`)
9. Checksum (`/CS`, `/CSR`, `/CSM`, `/CSMR`)
10. Data processing (`/DP`: signing, MACs, XOR, AES and RSA encryption, LZSS and ARLE compression) and verification (`/SV`)
11. Validation structures (`/vs`, then `/vshsm`)
12. Export (`/XI`, `/XS`, `/XN`, `/XSB`, `/XA`, `/XC`, `/XK`, `/XGACSWIL`, `/XF`, `/XP`) to `-o`, or to the input name with the format's extension; without an export flag nothing is written

The pipeline keeps the image as HexView keeps its blocks: adjacent data forms one block after every stage that changes data, while `/SB` pieces stay separate blocks until a checksum or data processing output is placed. `/RB`, `/XSB` and `/DP` work on these blocks (`HexFile::blocks`).

See [cli-reference.md](skill/hexy-compat/references/cli-reference.md) for flag syntax and examples.

## Library

```rust
use hexy_core::{AddressRange, IntelHexWriteOptions, parse_intel_hex, write_intel_hex};

let mut hf = parse_intel_hex(data)?;
hf.cut(AddressRange::from_start_end(0x800, 0x8FF)?);
let out = write_intel_hex(&hf, &IntelHexWriteOptions::default());
```

`Pipeline` reproduces a CLI run: set the stages its flags configure, in any order, and `run` applies them in HexView order. It returns the checksum and data processing bytes for the caller to write.

```rust
use hexy_core::{AlignOptions, ChecksumAlgorithm, ChecksumOptions, ChecksumStage, Pipeline};

// /AD:0x10 /AL /CS9
let pipeline = Pipeline {
    align: Some(AlignOptions {
        address_alignment: 0x10,
        length_alignment: 0x10,
        fill_byte: 0xFF,
    }),
    checksums: vec![ChecksumStage {
        options: ChecksumOptions { algorithm: ChecksumAlgorithm::Crc32, ..Default::default() },
        placement: None,
    }],
    ..Default::default()
};
let output = pipeline.run(&mut hf)?;
```

See [data processing](docs/data-processing.md) for the typed signing, MAC, XOR, AES, RSA
encryption, compression and verification API, the key formats, and the mapping from compat `/DP` and `/SV` methods.

## Scope

`hexy-compat` targets non-proprietary cleanroom-compatible slash workflows. Proprietary or DLL-backed features such as `/PB`, `/expdat`, and OEM container formats remain out of scope.

The repo is structured so additional frontends can consume `hexy-core` without forcing their release surface or UX into the compat CLI.

## Python bindings

The Python package mirrors `hexy-core`: `HexFile` with the parsers, writers and every
operation, `DataProcessing` values for the `/DP` operations, `ValidationStructure`, and
`Pipeline`. A CLI run is reproduced by configuring the `Pipeline` stages of its flags;
`tests/test_cli_equivalence.py` in `crates/hexy-py` checks that both give the same bytes.

```python
import hexy
from hexy import DataProcessing

source = hexy.HexFile.from_file("app.hex").normalized()  # HexView joins data on load
calibration = hexy.HexFile.from_file("calibration.hex")

# /MO:calibration.hex /FR:0x1000,0x100 /FP:FF /AR:0x0-0x1FFF /AD:0x10 /AL /CS9:@append
# /DP33:@append:key.txt
pipeline = hexy.Pipeline()
pipeline.merge(calibration, mode="overwrite")
pipeline.fill(["0x1000,0x100"], pattern=b"\xff")
pipeline.filter(["0x0-0x1FFF"])
pipeline.align(0x10, length=0x10)
pipeline.checksum(9, placement="append")
key = open("key.txt").read()
pipeline.process_data(
    DataProcessing.sign("rsa-pkcs1v15-sha256", key, metadata=True), placement="append"
)

result = pipeline.apply(source)
result.hexfile.write_intel_hex("patched.hex")
print(result.checksums[0].hex(), result.data_processing.hex())
```

See [hexy-py](crates/hexy-py/README.md) for the conventions of the Python API.

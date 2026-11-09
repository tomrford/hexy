# Known divergences

What each hexy crate exposes, and where hexy's behaviour differs from Vector HexView
1.15.2.

## Crate surfaces

- `hexy-core` is the Rust library. It owns the data model (`HexFile`, `Segment`,
  `AddressRange`), the parsers and writers, every image operation, checksums, data
  processing and verification with typed key readers, the validation structures, and
  `Pipeline`, HexView's stage order with typed parameters per stage.
- `hexy-compat` is the HexView-style CLI. It reads slash flags and INI files into a
  `Pipeline`, runs it, and writes the export and the checksum and data processing
  output files. It also owns what HexView does outside the core operations: the `/L`
  log commands and the `/XP` and `/XSB` file layouts. `/CSM*` and `/CSMR*`, which run
  several checksums in order, are a hexy extension that HexView ignores.
- `hexy-py` exposes every `hexy-core` operation, parser, writer and `Pipeline` stage
  to Python with the same parameters, so a CLI run is reproduced by configuring the
  `Pipeline` stages of its flags. The compat-only steps above compose from
  `to_binary`, `checksum` and `blocks`.

HexView options for OEM containers, GM headers, VBF files and external DLLs (`/XG*`,
`/XGAC`, `/XGMFBL`, `/XV`, `/XVBF`, `/XVBFSUBST`, `/MVBF`, `/XB`, `/xfca_sign`, `/PB`,
`/expdat`) are out of scope: hexy rejects them. See
[the CLI reference](../skill/hexy-compat/references/cli-reference.md).

## HexView compatibility limits

Do not claim these areas as drop-in compatible with HexView. Resolved parity findings
are not listed.

### Reporting

- Warning and error texts differ from HexView's, though each goes to the `/E` file on
  its own line as in HexView; `/V` writes `hexy V<version>`.
- Every failure exits with status 1; HexView returns a code per failure kind, such as
  2 for a merge range or 11 for a checksum.

### Input and ranges

- An import or merge file that does not exist: HexView warns and exports without it;
  hexy fails, so that a mistyped name cannot silently drop data. A wildcard name that
  matches nothing merges nothing in both.
- Input files with overlapping records: HexView fails to read them and writes nothing;
  hexy keeps the last record's bytes.
- `/IN` or `/IA` data that would reach past `0xFFFFFFFF`: HexView wraps it around to
  address 0; hexy fails.
- Numbers above 32 bits in range text crash HexView; hexy reads such a range as
  unreadable.
- A negative range length such as `/CR:8,-4`: HexView leaves overlapping blocks; hexy
  skips the range.
- `/L` lines `FileOpen<name>` without a blank, such as `FileOpenx`: HexView fails for
  some names; hexy empties the image like any other `FileOpen` with a name.

### Checksums

- A zero-length forced checksum range (`;!0x1000,0`) changes HexView's result in a way
  not yet understood; hexy ignores the range.
- `/CS16` `HexDataString` values with characters other than hex digits: HexView's
  parse is irregular; hexy rejects them.

### Data processing parameters and keys

- Key formats HexView rejects but hexy reads: RSA public keys as SPKI PEM, binary DER
  or X.509 certificates; RSA private keys as binary PKCS #1 DER; ECC keys with the
  standard `id-Ed25519` OID or a PEM label other than `PRIVATE KEY` and
  `EC PRIVATE KEY`; ECC public keys as SPKI or from certificates; P-256 public keys
  inside PKCS #8 keys (see [data processing](data-processing.md)).
- Hex key files of 2999 bytes or more: HexView fails to read them; hexy reads them.
- Key text with stray characters, such as `12x34`: HexView reads some of them as zero
  bytes; hexy rejects the text.
- Option values that are not valid, such as `#IV=00;sig.txt`: HexView ignores options
  a method does not use; hexy rejects them. Options a method does not use (`#IV`,
  `#AUTH`, `#TAG`, `#LZSS`, `#SALT`) are ignored by both, and hexy also warns.
- `/DP` with more than one `;`, or `@placement` without a following `:`: HexView fails
  the stage and still exports; hexy rejects the command.

### Data processing results

- Ciphers and compression that grow a block into the next block, such as `/SB` pieces
  or LZSS of random data: HexView keeps both blocks and exports the overlapping bytes
  twice; hexy keeps the later block's bytes.
- `/DP36` ARLE compression of some data with zero bytes, such as
  `00 00 00 00 02 00 02`: HexView reads past the block and picks other runs; hexy's
  output decompresses to the same data. Zero bytes that end a block, and data without
  zero bytes, compress as in HexView.
- `/DP19` to `/DP25` and `/DP29` (Vector-specific LZ compression, alone or with
  RIPEMD-160 signatures and MACs): hexy rejects them. The manual names only their
  window and length sizes; the coding is proprietary and undocumented, and it is not
  LZSS.
- `/DP55` without `#IV`: HexView takes the IV from the data but drops 16 bytes of
  ciphertext; hexy rejects the command.
- `/DP55` and `/DP56` with `#AUTH=@address,length`: HexView leaves that data
  unencrypted but also out of the tag; hexy rejects the command.
- `/DP56` with a `#TAG` file: HexView never reads it, so the check always fails; hexy
  rejects the command.
- `/DP56` with an image `#TAG` in the middle of a block: HexView decrypts part of the
  data before it fails; hexy fails without changing the data.
- `/DP38`, `/DP39` without `#SALT`: HexView's salt is 32 bytes of the C runtime's
  `rand()` seeded with the time in seconds, so it changes every second; hexy uses a
  random salt. With `#SALT` the signatures match; without it each tool verifies the
  other's.
- `/DP50`, `/DP51`: HexView signs with the same nonce for every key and message, which
  reveals the private key to anyone holding two of its signatures; hexy uses
  deterministic nonces (RFC 6979). Each tool verifies the other's signatures.
- `/DP17`, `/DP40`, `/DP42`: HexView's padding comes from the C runtime's `rand()`
  with a fixed seed, so its output is the same on every run; hexy pads with random
  bytes. Each tool decrypts the other's output.
- RSA encryption and decryption of more than one padded block: HexView handles only
  the first. It writes later `/DP17`, `/DP40` and `/DP42` blocks padded but
  unencrypted, leaves the padding on later `/DP18` blocks, fails later `/DP41` and
  `/DP43` blocks, and fails a padded `/DP17` block after a block of whole key lengths;
  hexy processes every block.
- `/DP17` blocks that are longer than one padded key length but not a whole number of
  key lengths, and `/DP18` blocks that are not a whole number of key lengths: HexView
  writes unusable data; hexy fails.
- `/DP52` on more than one block: both fail, but HexView first writes the signature of
  the first block to the output file; hexy writes no output file.

### Exports

- Without `-o`, an export from a `/IN`, `/IA` or `/II2` import is named after the
  import file, such as `firmware.s19` for `/IN:firmware.bin /XS`, and the export INI
  file defaults to the import file with `.ini`. HexView writes a file named only the
  suffix, such as `.s19` or `_f.hex`, and reads no INI file.
- An export without any input file, such as `/MO:merge.hex /XI`, needs `-o` in hexy;
  HexView writes `.hex`.
- Forced S1 or S2 records (`/XS:len:0`, `/XS:len:1`) for addresses that do not fit:
  HexView truncates the addresses; hexy rejects the export.
- `/XI` and `/XS` record lengths above 255, `/XC` `WordSize` values other than 0-2 and
  `/XK` on an empty image crash HexView; hexy rejects them.
- `/XF` with `FLASH ERASE SECTORS` in the INI file: HexView sometimes writes the block
  list instead, depending on the value and on `FLASH INDICATOR` and `DOWNLOAD FORMAT`
  (for example a `:start,length` list with `FLASH INDICATOR=1`); hexy always writes
  the INI text.

### Validation structures

- `/vs` with a checksum method that fails on the data, such as method 5 on an odd
  length: HexView still writes its C files; hexy fails the stage without them.
- `/vs` C files: hexy writes valid C where HexView's does not compile. The inserted
  structure and the `.h` file are the same. In the `.c` file:
  - the `WriteALFI` identifier: HexView writes no comma before it; hexy writes
    `,0x22`
  - checksums of other than 1, 2 or 4 bytes, such as SHA-1 digests or a 3-byte
    `/CS16` constant: HexView writes one literal, such as `0x0A0B0C`; hexy writes
    each byte, as in `0x0A, 0x0B, 0x0C`
  - tags of other than 1, 2 or 4 bytes: HexView writes C's reading of the tag text
    as one number, such as `0x1234u`; hexy writes a byte array of the tag's length
    holding that number
  - block checksums of a method HexView does not know or a `/CS16` constant it cannot
    read: HexView writes a bare `0x`; hexy leaves them out
  - without blocks: HexView writes a comma before the field after the begin tag, such
    as the file checksum; hexy does not

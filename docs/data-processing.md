# Data processing

`hexy-core` provides HexView's data processing (`/DP`) and signature verification
(`/SV`) as typed operations. `hexy-compat` translates the slash flags into them.

## Core API

A `DataProcessing` operation runs over the image's blocks (`HexFile::blocks`):

| Operation | Effect | Output |
|-----------|--------|--------|
| `Sign { method, key, salt }` | none | the signature |
| `Mac { method, key }` | none | the MAC |
| `Xor { key }` | XORs the data | none |
| `Encrypt` / `Decrypt { key, mode, padding }` | AES ECB, CBC or CTR, block by block | none |
| `EncryptGcm(AesGcm)` | AES-GCM over all blocks as one stream | the tag |
| `DecryptGcm { gcm, tag }` | AES-GCM decryption, then the tag check | none |
| `RsaEncrypt` / `RsaDecrypt { key, padding }` | RSA, block by block | none |
| `Compress` / `Decompress(Compression)` | LZSS or ARLE, block by block | none |
| `CompressEncrypt` / `DecryptDecompress(LzssAes)` | LZSS and AES-CBC, block by block | none |

`process_data` returns the output and, with a `Placement`, also writes it into the
image. `verify_signature` does not modify the image.

```rust
use hexy_core::{
    DataProcessing, HexFile, ProcessingError, SignatureMethod, SignatureScheme,
};

fn sign_and_verify(
    hexfile: &mut HexFile,
    private_key_file: &[u8],
    public_key_file: &[u8],
) -> Result<(), ProcessingError> {
    let method = SignatureMethod {
        scheme: SignatureScheme::RsaPkcs1v15Sha256,
        with_metadata: false,
    };
    let key = method.scheme.signing_key(private_key_file)?;
    let sign = DataProcessing::Sign {
        method,
        key,
        salt: None,
    };
    let signature = hexfile
        .process_data(&sign, None)?
        .unwrap_or_default();

    let key = method.scheme.verifying_key(public_key_file)?;
    hexfile.verify_signature(method, &key, &signature)
}
```

In a `Pipeline`, the `data_processing` stage runs after the checksum stages and the
`verify` stage after it, so verification sees placed output and replaced data.

### Signatures and MACs

The payload is the data of each block, concatenated in address order without gap
bytes. With `with_metadata`, each block's data is preceded by its start address and
length as two big-endian `u32` values, as HexView 1.15.2 hashes them.

| `SignatureScheme` | Algorithm |
|-------------------|-----------|
| `RsaPkcs1v15Md5`, `RsaPkcs1v15Sha1`, `RsaPkcs1v15Ripemd160`, `RsaPkcs1v15Sha256` | RSA PKCS #1 v1.5 over MD5, SHA-1, RIPEMD-160 or SHA-256 |
| `RsaPssSha256` | RSA-PSS over SHA-256 |
| `EcdsaP256Sha256` | ECDSA over P-256 and SHA-256 |
| `Ed25519` | Ed25519 (no pre-hash) over a single block |
| `Ed25519Ph` | Ed25519ph (SHA-512 pre-hash, empty context) |
| `Ed25519PhSha512` | Ed25519ph over the SHA-512 digest of the payload |

- RSA keys of 3072 and 4096 bits are supported.
- RSA-PSS signs with `salt`, or with a random 32-byte salt, and verifies signatures
  with any salt length, as HexView does. No other scheme takes a salt.
- ECDSA signatures are r and s as 32-byte big-endian values. hexy signs with
  deterministic nonces (RFC 6979), so its signatures differ from HexView's but verify
  the same way.
- `Ed25519` fails on an image of more than one block, `/SB` pieces included.

`MacAlgorithm` is `HmacMd5`, `HmacSha1`, `HmacRipemd160`, `HmacSha256` or
`CmacAes128`. HMAC uses at most the first 64 bytes of the key, as HexView does; CMAC
takes only 16-byte keys.

### Ciphers

Ciphers replace each block's data from the block's start address, in block order, so
data that grows overwrites what follows it. A block given no output keeps its data.
When a cipher fails, the blocks before the failing one stay replaced, as in HexView.

- `Xor`: the key repeats across the blocks, continuing from one block to the next. An
  empty key inverts the data.
- `Encrypt` and `Decrypt`: each block is encrypted on its own; AES-128, AES-192 or
  AES-256 follows the key length. `AesPadding` (`Pkcs7`, `AnsiX923`, `Rfc1321`) pads
  each block, adding a whole block to aligned data; without padding each block must be
  a multiple of 16 bytes. Decryption checks and removes the padding as HexView does:
  a last byte of zero is PKCS #7 or ANSI X.923 padding of no bytes, RFC 1321 padding
  must end in a zero byte, and padding may not make up the whole block. CTR decryption
  does not remove padding.
- `AesMode::Cbc` and `AesMode::Ctr` with `iv: None` take the first 16 bytes of the
  first block as the IV; those bytes stay in place, and every block uses that IV. CTR
  counts with a 128-bit big-endian counter that continues from all ones at one.
- `AesGcm` encrypts the data of all blocks as one stream, with a nonce of any length
  and optional additional data. Each block takes the output completed by the end of
  its data in 16-byte units, and the rest follows the last block; a block that takes
  no output keeps its data, as in HexView. `GcmTag::Image` reads the tag from image
  bytes at the start or end of a block, which are not decrypted and stay in place. A
  tag mismatch fails after the data is decrypted.
- `RsaEncrypt` and `RsaDecrypt`: each block is encrypted on its own, with random
  padding. `RsaPadding::Pkcs1v15` encrypts a block of a whole number of key lengths
  without padding, one key length at a time; any other block must fit one padded key
  length. Decrypting a block of one key length removes PKCS #1 v1.5 padding, or
  decrypts it without padding when the padding is not valid; longer blocks are
  decrypted without padding. `OaepSha1` and `OaepSha256` (OAEP without a label)
  encrypt blocks that fit one padded key length and decrypt blocks of one key length.

### Compression

Compression replaces each block's data from its start address, like a cipher; a block
that grows overwrites what follows it. hexy's compressed output is byte for byte
HexView's, so other tools that decompress HexView's output read hexy's.

`Lzss` holds the window and length field sizes in bits, 10 and 4 by default (Ford
SWDL005), with `0 < length < window < 16`. The stream is MSB-first bits:

- `1` and a byte is a literal
- `0`, a window position and a length code copies `code + break_even + 1` bytes from
  that absolute position, where `break_even` is `(1 + window + length) / 9`
- `0` and position 0 ends the stream, with no length; the last byte is padded with zero
  bits

The window starts as zero bytes and is written from position 1, wrapping past the end.
The compressor finds the longest match in a binary search tree of the window's strings
and takes it greedily, which fixes its choice among equal matches. HexView holds match
lengths in a byte, so with 8 or more length bits it compresses to literals only, and
decompression wraps longer lengths. Decompression reads past the end of the data as
zero bits, which end the stream, and ignores data after the end; a block that
decompresses to nothing keeps its data, as in HexView.

ARLE tokens are a header byte `KKCCCCCC` and data: kind 0 is `C` plain bytes, kinds 1,
2 and 3 a byte, word or long word repeated `C` times. The compressor takes the run that
covers the most bytes, with HexView's lookahead rules for overlapping runs; see the
`arle` module for them. Decompression fails on an incomplete token or empty output.

`LzssAes` compresses each block and then encrypts it with AES-CBC from `iv`, adding
`padding`; decryption removes the padding and then decompresses.

## Key material

Key types have `from_key_file` readers that take a key file's content, or key text,
as HexView reads it. Hex text is hex digit pairs, each optionally prefixed with `0x`,
with CR, LF, spaces and commas ignored; a trailing single digit makes the last byte
(`decode_hex_text`). Any other content is PEM, or binary DER.

`signing_key` and `verifying_key` read signature keys for a scheme. RSA private keys:

- hex text: a HIS key (`FF49` or `FF4B`, an ASN.1 length, then tag 0x81 modulus, 0x82
  public exponent and 0x91 private exponent, in any order), or a PKCS #1 key in DER
- PEM: PKCS #8 or PKCS #1
- binary: PKCS #8 DER; PKCS #1 DER is a hexy extension

A HIS key without a public exponent is taken to use 65537.

RSA public keys:

- hex text: a HIS key (`7F49`, `7F4B`, or the private forms), a PKCS #1 or SPKI public
  key in DER, or a PKCS #1 private key in DER
- PEM: a PKCS #1 public key, or a PKCS #8 or PKCS #1 private key
- hexy extensions: SPKI PEM, any of these in binary DER, and X.509 certificates in PEM
  or DER

Ed25519 and P-256 keys share one ECC key reader, as in HexView, so either reads the
other's key files. ECC private keys:

- DER in PEM, binary or hex text:
  - SEC1: `SEQUENCE { 1, OCTET STRING key [, [0] { OID prime256v1 }] [, [1] { BIT
    STRING public key }] }`
  - `SEQUENCE { 0, SEQUENCE { OID [, parameters] }, OCTET STRING { OCTET STRING key |
    SEC1 key } [, OCTET STRING { OCTET STRING public key }] }`, with `ecPublicKey`
    (1.2.840.10045.2.1) or `id-EdDSA25519-ph` (1.3.101.114); this includes PKCS #8
- hex text that is not one of these: the raw key, an Ed25519 seed or a big-endian
  P-256 scalar
- shorter keys are padded with zero bytes at the end, and longer keys are cut after 32
  bytes
- hexy extension: the standard `id-Ed25519` OID (1.3.101.112)

ECC public keys:

- a private key in the forms above that includes the public key; a P-256 public key is
  `04`, X and Y
- Ed25519: also the raw 32-byte key in hex text, padded or cut like a seed
- hexy extensions: SPKI and X.509 certificates in PEM or DER, and the public key inside
  a PKCS #8 P-256 key

HexView rejects the hexy extensions; none of them is read differently by HexView.

Symmetric keys are hex text only; HexView rejects binary key files for them.

- `MacKey`: a HIS key (`FF59` or `FF5B`, an ASN.1 length, then tag `D3`, an ASN.1
  length and the key), or any other hex text as the key bytes. Text that starts with a
  HIS header but whose length runs past the end is a plain key; a whole HIS item with
  any other content fails.
- `AesKey`: 16, 24 or 32 bytes.

## Compat mapping

The compat CLI owns the method numbers and the `/DP` parameter grammar.

| `/DP` | Operation | Default output file |
|-------|-----------|---------------------|
| `/DP0` | none | |
| `/DP1` | `Xor` | |
| `/DP2`, `/DP3` | `Encrypt`, `Decrypt` with `AesMode::Ecb` | |
| `/DP4`, `/DP5` | `Mac` `HmacSha1` | `SignD_SHA1.txt`, `SignDAL_SHA1.txt` |
| `/DP6`, `/DP7` | `Mac` `HmacRipemd160` | `SignD_Rmd160.txt`, `SignDAL_Rmd160.txt` |
| `/DP8`, `/DP10` | `Sign` `RsaPkcs1v15Sha1` | `SignD_SHA1.RSA`, `SignDAL_SHA1.RSA` |
| `/DP28`, `/DP9` | `Sign` `RsaPkcs1v15Ripemd160` | `SignD_RMD160.RSA`, `SignDAL_RMD160.RSA` |
| `/DP11`, `/DP12` | `Encrypt`, `Decrypt` with `AesMode::Cbc` | |
| `/DP13`, `/DP14` | `Mac` `HmacMd5` | `SignD_MD5.txt`, `SignDAL_MD5.txt` |
| `/DP15`, `/DP16` | `Sign` `RsaPkcs1v15Md5` | `SignD_MD5.RSA`, `SignDAL_MD5.RSA` |
| `/DP17`, `/DP18` | `RsaEncrypt`, `RsaDecrypt` with `RsaPadding::Pkcs1v15` | |
| `/DP30`, `/DP31` | `Mac` `HmacSha256` | `SignD_SHA256.txt`, `SignDAL_SHA256.txt` |
| `/DP32`, `/DP33` | `Sign` `RsaPkcs1v15Sha256` | `SignD_SHA256.RSA`, `SignDAL_SHA256.RSA` |
| `/DP38`, `/DP39` | `Sign` `RsaPssSha256` | `SignD_PSS_SHA256.RSA`, `SignDAL_PSS_SHA256.RSA` |
| `/DP40`, `/DP41` | `RsaEncrypt`, `RsaDecrypt` with `RsaPadding::OaepSha1` | |
| `/DP42`, `/DP43` | `RsaEncrypt`, `RsaDecrypt` with `RsaPadding::OaepSha256` | |
| `/DP44`, `/DP45` | `Mac` `CmacAes128` | `SignD_CmacAes.txt`, `SignDAL_CmacAes.txt` |
| `/DP46`, `/DP47` | `Sign` `Ed25519Ph` | `SignD_ED25519.ECC`, `SignDAL_ED25519.ECC` |
| `/DP48`, `/DP49` | `Sign` `Ed25519PhSha512` | `SignD_SHA512_ED25519PH.ECC`, `SignDAL_SHA512_ED25519PH.ECC` |
| `/DP50`, `/DP51` | `Sign` `EcdsaP256Sha256` | `SignD_SHA256_ANSIP256.ECC`, `SignDAL_SHA256_ANSIP256.ECC` |
| `/DP52` | `Sign` `Ed25519` | `SignD_ED25519.ECC` |
| `/DP53`, `/DP54` | `Encrypt`, `Decrypt` with `AesMode::Ctr` | |
| `/DP55`, `/DP56` | `EncryptGcm`, `DecryptGcm` | |
| `/DP26`, `/DP27` | `Compress`, `Decompress` with the default `Lzss` | |
| `/DP57`, `/DP58` | `Compress`, `Decompress` with `#LZSS` bits | |
| `/DP34`, `/DP35` | `CompressEncrypt`, `DecryptDecompress` with the default `Lzss` | |
| `/DP59`, `/DP60` | `CompressEncrypt`, `DecryptDecompress` with `#LZSS` bits | |
| `/DP36`, `/DP37` | `Compress`, `Decompress` with `Compression::Arle` | |

HexView's Vector-specific LZ methods `/DP19` to `/DP25` and `/DP29` are not
implemented: the manual names only their window and length sizes, and their coding is
undocumented and not standard LZSS.

The second signature or MAC method of each pair includes metadata. The RSA encryption
methods read a public key (or the public part of a private key), and decryption a
private key.

| `/SV` | Verifies |
|-------|----------|
| `/SV0` to `/SV3` | `/DP28`, `/DP9`, `/DP8`, `/DP10` |
| `/SV4` to `/SV7` | `/DP32`, `/DP33`, `/DP38`, `/DP39` |
| `/SV8` to `/SV11` | `/DP46` to `/DP49` |
| `/SV12` to `/SV14` | `/DP50` to `/DP52` |

HexView 1.15.2 implements `/SV12` to `/SV14`, which its manual does not list.

`/DPn[:@placement]:[param1][,param2,param3][;param4][#NAME=value]...`:

- param1 that is hex text is inline key text; `file,section,key` reads the key text from
  the INI file; any other param1 is a key file
- param4 is the output file of signatures and MACs; without it, the output goes to the
  default file above. HMAC-SHA-1 and HMAC-RIPEMD-160 output text ends with CRLF
- for AES and LZSS with AES-CBC, param4 is the padding, read from its first four letters ignoring case:
  `PKCS` (PKCS #7), `ANSI` (ANSI X.923) or `RFC1` (RFC 1321); anything else is no padding.
  RSA encryption ignores param4
- everything after the first `#` is options: `#SALT=`, `#IV=`, `#AUTH=`, `#TAG=` and
  `#LZSS=` (or `#LZSSa,b`), case-sensitive; HexView ignores unknown options
- `#SALT` is the `/DP38` and `/DP39` salt. HexView reads its first 255 characters, so
  the 128th byte of a longer salt is a single digit. An empty `#SALT=` is no salt
- `#IV` is the CBC and CTR IV, padded with zero bytes or cut to 16 bytes; an empty
  `#IV=` is no IV. For GCM it is the nonce, cut to 16 bytes. LZSS with AES-CBC uses zero
  bytes without it, not the data
- `#LZSS=window,length` is read as C's `scanf("%d,%d")`: `#LZSS= +12, 05x` is 12,5.
  `/DP57` and `/DP58` fail on bits outside the limits and on any parameter text without
  `#LZSS=`, such as `#LZSS12,5`; `/DP59` and `/DP60` use the default bits instead
- GCM `#AUTH` is hex text or a binary file (one with a byte from 0x80); HexView ignores
  text files and missing files. `/DP55` writes the tag to a `#TAG` file and to the
  placement; `/DP56` reads `#TAG` as hex text or `@address,length` in the image
- file references, including the output file, resolve against the input file's folder,
  or the working directory without a positional input file

`/SVn:keyinfo!signatureinfo` reads `keyinfo` with the same param1 forms. The signature
is inline hex text or a file of hex text, such as a `/DP` output file, which `/SV` can
read in the same command.

A failed `/DP` or `/SV` is reported, and hexy still runs the remaining stages and
exports, as HexView does. Consumers reproducing a compat workflow apply the table and
the grammar at their input boundary, then use the same typed core operations.

See the [CLI reference](../skill/hexy-compat/references/cli-reference.md) for
slash-flag syntax and placement forms.

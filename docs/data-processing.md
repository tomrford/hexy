# Data processing

`hexy-core` provides HexView's data processing (`/DP`) and signature verification
(`/SV`) as typed operations. `hexy-compat` translates the slash flags into them.

## Core API

A `DataProcessing` operation runs over the image's blocks (`HexFile::blocks`):

| Operation | Effect | Output |
|-----------|--------|--------|
| `Sign { method, key }` | none | the signature |
| `Mac { method, key }` | none | the MAC |
| `Xor { key }` | XORs the data | none |
| `Encrypt` / `Decrypt { key, mode, padding }` | AES ECB, CBC or CTR, block by block | none |
| `EncryptGcm(AesGcm)` | AES-GCM over all blocks as one stream | the tag |
| `DecryptGcm { gcm, tag }` | AES-GCM decryption, then the tag check | none |

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
    let signature = hexfile
        .process_data(&DataProcessing::Sign { method, key }, None)?
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
| `RsaPkcs1v15Sha256` | RSA PKCS #1 v1.5 over SHA-256 |
| `RsaPssSha256` | RSA-PSS over SHA-256 with a random 32-byte salt |
| `Ed25519Ph` | Ed25519ph (SHA-512 pre-hash, empty context) |
| `Ed25519Sha512` | Ed25519 over the SHA-512 digest of the payload |

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

Ed25519 private keys:

- hex text: the raw 32-byte seed; shorter text is padded with zero bytes at the end and
  longer text is cut after 32 bytes
- PEM: `SEQUENCE { INTEGER, SEQUENCE { OID 1.3.101.114 }, OCTET STRING { OCTET STRING
  seed } [, OCTET STRING { OCTET STRING public key }] }`
- hexy extensions: the standard `id-Ed25519` OID (1.3.101.112), and binary DER

Ed25519 public keys:

- hex text: the raw 32-byte key, padded or cut like a seed
- PEM: a private key in the form above that includes the public key
- hexy extensions: SPKI in PEM or DER, binary DER, and X.509 certificates

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
| `/DP11`, `/DP12` | `Encrypt`, `Decrypt` with `AesMode::Cbc` | |
| `/DP13`, `/DP14` | `Mac` `HmacMd5` | `SignD_MD5.txt`, `SignDAL_MD5.txt` |
| `/DP30`, `/DP31` | `Mac` `HmacSha256` | `SignD_SHA256.txt`, `SignDAL_SHA256.txt` |
| `/DP32`, `/DP33` | `Sign` `RsaPkcs1v15Sha256` | `SignD_SHA256.RSA`, `SignDAL_SHA256.RSA` |
| `/DP38`, `/DP39` | `Sign` `RsaPssSha256` | `SignD_PSS_SHA256.RSA`, `SignDAL_PSS_SHA256.RSA` |
| `/DP44`, `/DP45` | `Mac` `CmacAes128` | `SignD_CmacAes.txt`, `SignDAL_CmacAes.txt` |
| `/DP46`, `/DP47` | `Sign` `Ed25519Ph` | `SignD_ED25519.ECC`, `SignDAL_ED25519.ECC` |
| `/DP48`, `/DP49` | `Sign` `Ed25519Sha512` | `SignD_SHA512_ED25519PH.ECC`, `SignDAL_SHA512_ED25519PH.ECC` |
| `/DP53`, `/DP54` | `Encrypt`, `Decrypt` with `AesMode::Ctr` | |
| `/DP55`, `/DP56` | `EncryptGcm`, `DecryptGcm` | |

The second method of each pair includes metadata. `/SV4` to `/SV11` verify `/DP32`,
`/DP33`, `/DP38`, `/DP39` and `/DP46` to `/DP49`.

`/DPn[:@placement]:[param1][,param2,param3][;param4][#NAME=value]...`:

- param1 that is hex text is inline key text; `file,section,key` reads the key text from
  the INI file; any other param1 is a key file
- param4 is the output file of signatures and MACs; without it, the output goes to the
  default file above. HMAC-SHA-1 and HMAC-RIPEMD-160 output text ends with CRLF
- for AES, param4 is the padding, read from its first four letters ignoring case:
  `PKCS` (PKCS #7), `ANSI` (ANSI X.923) or `RFC1` (RFC 1321); anything else is no padding
- everything after the first `#` is options: `#SALT=`, `#IV=`, `#AUTH=`, `#TAG=` and
  `#LZSS=` (or `#LZSSa,b`), case-sensitive; HexView ignores unknown options
- `#IV` is the CBC and CTR IV, padded with zero bytes or cut to 16 bytes; an empty
  `#IV=` is no IV. For GCM it is the nonce, cut to 16 bytes
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

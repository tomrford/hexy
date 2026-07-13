# Signatures

`hexy-core` provides typed signing and verification operations. `hexy-compat`
translates HexView-style `/DP` and `/SV` arguments into those operations.

## Core API

Library consumers choose the algorithm, key source, signature source, and
placement explicitly:

```rust
use std::path::Path;

use hexy_core::{
    HexFile, SignatureBytesSource, SignatureError, SignatureKeySource,
    SignatureMethod, SignatureSignOptions, SignatureVerifyOptions,
};

fn sign_and_verify(hexfile: &mut HexFile) -> Result<(), SignatureError> {
    let method = SignatureMethod::RsaPkcs1v15Sha256 {
        with_metadata: false,
    };
    let signature = hexfile.sign(&SignatureSignOptions {
        method,
        key_source: SignatureKeySource::File(Path::new("private.pem")),
        placement: None,
    })?;

    hexfile.verify_signature(&SignatureVerifyOptions {
        method,
        key_source: SignatureKeySource::File(Path::new("public.pem")),
        signature_source: SignatureBytesSource::Bytes(&signature),
    })
}
```

`HexFile::sign` returns the signature bytes. With `placement: None`, it leaves
the image unchanged. A `SignaturePlacement` writes the signature into the image
as part of the same operation. `HexFile::verify_signature` does not modify the
image.

`SignatureKeySource` accepts a file, text such as an inline PEM key, or bytes.
`SignatureBytesSource` accepts a file or bytes. Core does not infer a source
type from a string.

RSA private keys may use PKCS #8 or PKCS #1 PEM or DER; RSA public keys may use
SPKI or PKCS #1 PEM or DER. Ed25519 private keys use PKCS #8 PEM or DER, and
Ed25519 public keys use SPKI PEM or DER. Public keys may also come from PEM or
DER X.509 certificates.

The signature payload is the data from normalized segments, concatenated in
address order without gap bytes. When `with_metadata` is `true`, the payload is
prefixed with the minimum address and data length as two big-endian `u32`
values.

## Compat mapping

The compat CLI owns slash-flag parsing, numeric method mapping, and source
classification. The supported mappings are:

| Sign | Verify | `SignatureMethod` | `with_metadata` |
|------|--------|-------------------|-----------------|
| `/DP32` | `/SV4` | `RsaPkcs1v15Sha256` | `false` |
| `/DP33` | `/SV5` | `RsaPkcs1v15Sha256` | `true` |
| `/DP38` | `/SV6` | `RsaPssSha256` | `false` |
| `/DP39` | `/SV7` | `RsaPssSha256` | `true` |
| `/DP46` | `/SV8` | `Ed25519Ph` | `false` |
| `/DP47` | `/SV9` | `Ed25519Ph` | `true` |
| `/DP48` | `/SV10` | `Ed25519Sha512Data` | `false` |
| `/DP49` | `/SV11` | `Ed25519Sha512Data` | `true` |

Compat classifies key input as follows:

- text beginning with `-----BEGIN `, or containing a newline, is inline text
- an even-length hexadecimal value beginning, case-insensitively, with `FF49`,
  `FF4B`, `FF59`, or `FF5B` is inline ASN.1 key bytes
- any other value is a file path

Compat classifies signature input as inline bytes when it is an even-length
hexadecimal value prefixed with `0x`, or when removing byte separators (space,
tab, `:`, `-`, or `_`) leaves an even-length hexadecimal value. Any other value
is a file path, including an unprefixed value such as `deadbeef`.

After classification, compat constructs `SignatureSignOptions` or
`SignatureVerifyOptions` and calls the core operation. Consumers reproducing a
compat workflow can apply the table and classification rules at their input
boundary, then use the same typed core requests. Core does not expose the `/DP`
or `/SV` numbers.

See the [CLI reference](../skill/hexy-compat/references/cli-reference.md) for
slash-flag syntax and placement forms.

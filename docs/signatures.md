# Data processing and signatures

`hexy-core` provides HexView's data processing (`/DP`) and signature verification
(`/SV`) as typed operations. `hexy-compat` translates the slash flags into them.

## Core API

A `DataProcessing` operation runs over the image's blocks (`HexFile::blocks`) and may
produce output, such as a signature, which can also be placed into the image:

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

`process_data` returns the operation's output and, with a `Placement`, also writes it
into the image. `verify_signature` does not modify the image. In a `Pipeline`, the
`data_processing` stage runs after the checksum stages and the `verify` stage after it,
so verification sees a placed signature.

The signature payload is the data of each block, concatenated in address order without
gap bytes. With `with_metadata`, each block's data is preceded by its start address and
length as two big-endian `u32` values, as HexView 1.15.2 hashes them.

`SignatureScheme` values:

| Scheme | Algorithm |
|--------|-----------|
| `RsaPkcs1v15Sha256` | RSA PKCS #1 v1.5 over SHA-256 |
| `RsaPssSha256` | RSA-PSS over SHA-256 with a random 32-byte salt |
| `Ed25519Ph` | Ed25519ph (SHA-512 pre-hash, empty context) |
| `Ed25519Sha512` | Ed25519 over the SHA-512 digest of the payload |

## Key material

`signing_key` and `verifying_key` read a key file's content, or key text, as HexView
does. The key types (`RsaPrivateKey`, `RsaPublicKey`, `Ed25519PrivateKey`,
`Ed25519PublicKey`) have the same `from_key_file` readers, and RSA keys also
`from_his_bytes`.

Hex text is hex digit pairs, each optionally prefixed with `0x`, with CR, LF, spaces and
commas ignored; a trailing single digit makes the last byte (`decode_hex_text`). Any
other content is PEM, or binary DER.

RSA private keys:

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

## Compat mapping

The compat CLI owns the method numbers and the `/DP` parameter grammar:

| Sign | Verify | `SignatureScheme` | `with_metadata` | Default output file |
|------|--------|-------------------|-----------------|---------------------|
| `/DP32` | `/SV4` | `RsaPkcs1v15Sha256` | `false` | `SignD_SHA256.RSA` |
| `/DP33` | `/SV5` | `RsaPkcs1v15Sha256` | `true` | `SignDAL_SHA256.RSA` |
| `/DP38` | `/SV6` | `RsaPssSha256` | `false` | `SignD_PSS_SHA256.RSA` |
| `/DP39` | `/SV7` | `RsaPssSha256` | `true` | `SignDAL_PSS_SHA256.RSA` |
| `/DP46` | `/SV8` | `Ed25519Ph` | `false` | `SignD_ED25519.ECC` |
| `/DP47` | `/SV9` | `Ed25519Ph` | `true` | `SignDAL_ED25519.ECC` |
| `/DP48` | `/SV10` | `Ed25519Sha512` | `false` | `SignD_SHA512_ED25519PH.ECC` |
| `/DP49` | `/SV11` | `Ed25519Sha512` | `true` | `SignDAL_SHA512_ED25519PH.ECC` |

`/DPn[:@placement]:[param1][,param2,param3][;param4][#NAME=value]...`:

- param1 that is hex text is inline key text; `file,section,key` reads the key text from
  the INI file; any other param1 is a key file
- param4 is the output file; without it, the output goes to the default file above
- everything after the first `#` is options: `#SALT=`, `#IV=`, `#AUTH=`, `#TAG=` and
  `#LZSS=` (or `#LZSSa,b`), case-sensitive; HexView ignores unknown options
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

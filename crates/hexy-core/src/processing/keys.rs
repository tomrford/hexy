//! Key material as HexView's data processing reads it.
//!
//! Each key type has `from_key_file`, which takes the content of a key file or key
//! text: hex text (see [`decode_hex_text`]), PEM, or binary DER. Some DER forms are
//! accepted here that HexView rejects; `docs/signatures.md` lists them.

use base64ct::{Base64, Encoding};
use ed25519_dalek::{SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use rsa::BigUint;
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use x509_cert::Certificate;
use x509_cert::der::{Decode, Encode};

use super::ProcessingError;

/// Bytes of HexView hex text: digit pairs, each optionally prefixed with `0x`, with
/// CR, LF, spaces and commas ignored; a trailing single digit makes the last byte.
/// `None` when the text holds anything else.
pub fn decode_hex_text(text: &[u8]) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'\r' | b'\n' | b' ' | b','))
        .collect();
    let mut bytes = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2).filter(|pair| *pair != b"0x") {
        let mut byte = 0;
        for &digit in pair {
            byte = byte << 4 | char::from(digit).to_digit(16)? as u8;
        }
        bytes.push(byte);
    }
    Some(bytes)
}

/// The content of a key file or key text.
enum KeyContent {
    /// Bytes of hex text.
    Hex(Vec<u8>),
    /// DER from PEM, or binary content.
    Der(Vec<u8>),
}

impl KeyContent {
    fn read(content: &[u8]) -> Self {
        if let Some(der) = pem_der(content) {
            return Self::Der(der);
        }
        match decode_hex_text(content) {
            Some(bytes) => Self::Hex(bytes),
            None => Self::Der(content.to_vec()),
        }
    }
}

/// The DER inside PEM text, with base64 lines of any length.
fn pem_der(content: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(content).ok()?;
    let (_, rest) = text.split_once("-----BEGIN ")?;
    let (_label, body) = rest.split_once("-----")?;
    let (body, _) = body.split_once("-----END ")?;
    let base64: String = body.split_ascii_whitespace().collect();
    Base64::decode_vec(&base64).ok()
}

/// One tag-length-value item with an ASN.1 definite length (short form, or one or
/// two length bytes): the tag, the value and the bytes after it.
fn read_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (len, rest) = match first {
        0x00..=0x7F => (usize::from(first), rest),
        0x81 => {
            let (&len, rest) = rest.split_first()?;
            (usize::from(len), rest)
        }
        0x82 => {
            let (len, rest) = rest.split_at_checked(2)?;
            (usize::from(u16::from_be_bytes([len[0], len[1]])), rest)
        }
        _ => return None,
    };
    let (value, rest) = rest.split_at_checked(len)?;
    Some((tag, value, rest))
}

/// The items of a DER `SEQUENCE`.
fn sequence(der: &[u8]) -> Option<Vec<(u8, &[u8])>> {
    let (0x30, mut body, _) = read_tlv(der)? else {
        return None;
    };
    let mut items = Vec::new();
    while !body.is_empty() {
        let (tag, value, rest) = read_tlv(body)?;
        items.push((tag, value));
        body = rest;
    }
    Some(items)
}

/// Values of a HIS RSA key: `FF49`/`FF4B` (private) or `7F49`/`7F4B` (public), an
/// ASN.1 length, then tagged values in any order: 0x81 modulus, 0x82 public exponent,
/// 0x91 private exponent. Other tags and bytes after the key are ignored.
struct HisRsaKey {
    private: bool,
    modulus: BigUint,
    public_exponent: BigUint,
    private_exponent: Option<BigUint>,
}

/// HexView reads HIS keys without a public exponent; they are taken to use 65537.
const DEFAULT_PUBLIC_EXPONENT: u32 = 65537;

impl HisRsaKey {
    fn parse(bytes: &[u8]) -> Option<Self> {
        let (&header, rest) = bytes.split_first()?;
        let (tag, mut body, _) = read_tlv(rest)?;
        if !matches!(header, 0xFF | 0x7F) || !matches!(tag, 0x49 | 0x4B) {
            return None;
        }
        let (mut modulus, mut public_exponent, mut private_exponent) = (None, None, None);
        while !body.is_empty() {
            let (tag, value, rest) = read_tlv(body)?;
            let value = Some(BigUint::from_bytes_be(value));
            match tag {
                0x81 => modulus = value,
                0x82 => public_exponent = value,
                0x91 => private_exponent = value,
                _ => {}
            }
            body = rest;
        }
        Some(Self {
            private: header == 0xFF,
            modulus: modulus?,
            public_exponent: public_exponent
                .unwrap_or_else(|| BigUint::from(DEFAULT_PUBLIC_EXPONENT)),
            private_exponent,
        })
    }
}

fn invalid_key(kind: &str) -> ProcessingError {
    ProcessingError::InvalidKey(format!("unable to read {kind}"))
}

#[derive(Debug, Clone)]
pub struct RsaPrivateKey(pub(super) rsa::RsaPrivateKey);

impl RsaPrivateKey {
    /// A HIS private key (`FF49` or `FF4B`) with modulus and private exponent.
    pub fn from_his_bytes(bytes: &[u8]) -> Result<Self, ProcessingError> {
        let key = HisRsaKey::parse(bytes)
            .filter(|key| key.private)
            .ok_or_else(|| invalid_key("HIS RSA private key"))?;
        let private_exponent = key
            .private_exponent
            .ok_or_else(|| invalid_key("HIS RSA private exponent"))?;
        if private_exponent.bits() == 0 {
            return Err(ProcessingError::InvalidKey(
                "HIS RSA private exponent must be nonzero".to_owned(),
            ));
        }
        // Prime recovery runs before the RSA crate validates these components.
        rsa::RsaPublicKey::new_with_max_size(
            key.modulus.clone(),
            key.public_exponent.clone(),
            usize::MAX,
        )
        .map_err(|e| ProcessingError::InvalidKey(e.to_string()))?;
        rsa::RsaPrivateKey::from_components(
            key.modulus,
            key.public_exponent,
            private_exponent,
            Vec::new(),
        )
        .map(Self)
        .map_err(|e| ProcessingError::InvalidKey(e.to_string()))
    }

    /// A HIS or PKCS #1 key in hex text, or a PKCS #8 or PKCS #1 key in DER or PEM.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        match KeyContent::read(content) {
            KeyContent::Hex(bytes) => Self::from_his_bytes(&bytes)
                .ok()
                .or_else(|| Self::from_pkcs1_der(&bytes)),
            KeyContent::Der(der) => Self::from_der(&der),
        }
        .ok_or_else(|| invalid_key("RSA private key"))
    }

    fn from_pkcs1_der(der: &[u8]) -> Option<Self> {
        rsa::RsaPrivateKey::from_pkcs1_der(der).ok().map(Self)
    }

    fn from_der(der: &[u8]) -> Option<Self> {
        rsa::RsaPrivateKey::from_pkcs8_der(der)
            .ok()
            .map(Self)
            .or_else(|| Self::from_pkcs1_der(der))
    }
}

#[derive(Debug, Clone)]
pub struct RsaPublicKey(pub(super) rsa::RsaPublicKey);

impl RsaPublicKey {
    /// The modulus and public exponent of any HIS key (`7F49`, `7F4B`, `FF49`, `FF4B`).
    pub fn from_his_bytes(bytes: &[u8]) -> Result<Self, ProcessingError> {
        let key = HisRsaKey::parse(bytes).ok_or_else(|| invalid_key("HIS RSA key"))?;
        rsa::RsaPublicKey::new(key.modulus, key.public_exponent)
            .map(Self)
            .map_err(|e| ProcessingError::InvalidKey(e.to_string()))
    }

    /// A HIS key or a PKCS #1 or SPKI key in hex text; or a PKCS #1 or SPKI public key,
    /// a private key, or an X.509 certificate, in DER or PEM. A private key gives its
    /// public part.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        let public = |key: RsaPrivateKey| Self(key.0.to_public_key());
        match KeyContent::read(content) {
            KeyContent::Hex(bytes) => Self::from_his_bytes(&bytes)
                .ok()
                .or_else(|| Self::from_der(&bytes))
                .or_else(|| RsaPrivateKey::from_pkcs1_der(&bytes).map(public)),
            KeyContent::Der(der) => Self::from_der(&der)
                .or_else(|| RsaPrivateKey::from_der(&der).map(public))
                .or_else(|| Self::from_der(&certificate_spki(&der)?)),
        }
        .ok_or_else(|| invalid_key("RSA public key"))
    }

    /// A PKCS #1 or SPKI public key.
    fn from_der(der: &[u8]) -> Option<Self> {
        rsa::RsaPublicKey::from_pkcs1_der(der)
            .or_else(|_| rsa::RsaPublicKey::from_public_key_der(der))
            .ok()
            .map(Self)
    }
}

fn certificate_spki(der: &[u8]) -> Option<Vec<u8>> {
    let certificate = Certificate::from_der(der).ok()?;
    certificate
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .ok()
}

/// `id-Ed25519` (1.3.101.112) and the `id-EdDSA25519-ph` (1.3.101.114) HexView uses.
fn is_ed25519_oid(algorithm: &[u8]) -> bool {
    matches!(
        read_tlv(algorithm),
        Some((0x06, [0x2B, 0x65, 0x70 | 0x72], _))
    )
}

/// Seed and, if present, public key of an Ed25519 private key in DER: `SEQUENCE {
/// version, SEQUENCE { OID }, OCTET STRING { OCTET STRING seed } [, OCTET STRING {
/// OCTET STRING public } | [1] public] }`.
fn ed25519_private_der(der: &[u8]) -> Option<([u8; 32], Option<[u8; 32]>)> {
    let items = sequence(der)?;
    let [(0x02, _), (0x30, algorithm), (0x04, private), rest @ ..] = items.as_slice() else {
        return None;
    };
    if !is_ed25519_oid(algorithm) {
        return None;
    }
    let inner = |octets: &[u8]| -> Option<[u8; 32]> {
        let (0x04, value, _) = read_tlv(octets)? else {
            return None;
        };
        value.try_into().ok()
    };
    let public = match rest.first() {
        Some((0x04, public)) => Some(inner(public)?),
        // PKCS #8 v2: `[1] IMPLICIT BIT STRING`.
        Some((0x81, [0x00, public @ ..])) => Some((*public).try_into().ok()?),
        _ => None,
    };
    Some((inner(private)?, public))
}

/// Public key of an Ed25519 `SubjectPublicKeyInfo` in DER.
fn ed25519_spki_der(der: &[u8]) -> Option<[u8; 32]> {
    let items = sequence(der)?;
    let [(0x30, algorithm), (0x03, [0x00, public @ ..])] = items.as_slice() else {
        return None;
    };
    is_ed25519_oid(algorithm)
        .then(|| public.try_into().ok())
        .flatten()
}

/// HexView reads hex text as a raw 32-byte key: shorter text is padded with zero bytes
/// at the end, and longer text is cut after 32 bytes.
fn raw_ed25519(bytes: &[u8]) -> [u8; 32] {
    let mut key = [0; 32];
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

#[derive(Debug, Clone)]
pub struct Ed25519PrivateKey(pub(super) EdSigningKey);

impl Ed25519PrivateKey {
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self(EdSigningKey::from_bytes(seed))
    }

    /// A raw seed in hex text, or a PKCS #8 key in PEM or DER.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        match KeyContent::read(content) {
            KeyContent::Hex(raw) if !raw.is_empty() => Ok(Self::from_bytes(&raw_ed25519(&raw))),
            KeyContent::Hex(_) => Err(invalid_key("empty Ed25519 private key")),
            KeyContent::Der(der) => ed25519_private_der(&der)
                .map(|(seed, _)| Self::from_bytes(&seed))
                .ok_or_else(|| invalid_key("Ed25519 private key")),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519PublicKey(pub(super) EdVerifyingKey);

impl Ed25519PublicKey {
    pub fn from_bytes(public: &[u8; 32]) -> Result<Self, ProcessingError> {
        EdVerifyingKey::from_bytes(public)
            .map(Self)
            .map_err(|e| ProcessingError::InvalidKey(e.to_string()))
    }

    /// A raw key in hex text, a private key in PEM or DER that carries its public key,
    /// an SPKI public key, or an X.509 certificate.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        let der = match KeyContent::read(content) {
            KeyContent::Hex(raw) if !raw.is_empty() => return Self::from_bytes(&raw_ed25519(&raw)),
            KeyContent::Hex(_) => return Err(invalid_key("empty Ed25519 public key")),
            KeyContent::Der(der) => der,
        };
        ed25519_private_der(&der)
            .and_then(|(_, public)| public)
            .or_else(|| ed25519_spki_der(&der))
            .or_else(|| ed25519_spki_der(&certificate_spki(&der)?))
            .ok_or_else(|| invalid_key("Ed25519 public key"))
            .and_then(|public| Self::from_bytes(&public))
    }
}

#[cfg(test)]
mod tests {
    use super::{RsaPrivateKey, decode_hex_text};

    /// HexView reads PEM with base64 lines of any length (probed with 76 columns).
    #[test]
    fn test_pem_accepts_any_line_length_and_ending() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/keys/rsa_pkcs8.pem"
        );
        let pem = std::fs::read_to_string(path).unwrap();
        let base64: String = pem.lines().filter(|l| !l.starts_with("-----")).collect();
        let lines: Vec<&str> = base64
            .as_bytes()
            .chunks(76)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect();
        let rewrapped = format!(
            "-----BEGIN PRIVATE KEY-----\r{}\r-----END PRIVATE KEY-----\r",
            lines.join("\r")
        );
        assert!(RsaPrivateKey::from_key_file(rewrapped.as_bytes()).is_ok());
    }

    /// HexView decodes key text this way (probed with `/DP1` XOR keys and RSA keys).
    #[test]
    fn test_decode_hex_text_matches_hexview() {
        assert_eq!(
            decode_hex_text(b"1234ABcd"),
            Some(vec![0x12, 0x34, 0xAB, 0xCD])
        );
        assert_eq!(decode_hex_text(b"0x1234"), Some(vec![0x12, 0x34]));
        assert_eq!(decode_hex_text(b"123"), Some(vec![0x12, 0x03]));
        assert_eq!(
            decode_hex_text(b"0x12,0x34 0xAB\r\n"),
            Some(vec![0x12, 0x34, 0xAB])
        );
        assert_eq!(decode_hex_text(b"120x34"), Some(vec![0x12, 0x34]));
        assert_eq!(decode_hex_text(b"12\t34"), None);
        assert_eq!(decode_hex_text(b"12X34"), None);
    }
}

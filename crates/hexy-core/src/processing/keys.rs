//! Key material as HexView's data processing reads it.
//!
//! Each key type has `from_key_file`, which takes the content of a key file or key
//! text: hex text (see [`decode_hex_text`]), PEM, or binary DER. Some DER forms are
//! accepted here that HexView rejects; `docs/data-processing.md` lists them.

use base64ct::{Base64, Encoding};
use ed25519_dalek::{SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use p256::ecdsa::{SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey};
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
pub struct RsaPrivateKey(pub(super) Box<rsa::RsaPrivateKey>);

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
        .map(|key| Self(Box::new(key)))
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
        rsa::RsaPrivateKey::from_pkcs1_der(der)
            .ok()
            .map(|key| Self(Box::new(key)))
    }

    fn from_der(der: &[u8]) -> Option<Self> {
        rsa::RsaPrivateKey::from_pkcs8_der(der)
            .ok()
            .map(|key| Self(Box::new(key)))
            .or_else(|| Self::from_pkcs1_der(der))
    }
}

#[derive(Debug, Clone)]
pub struct RsaPublicKey(pub(super) Box<rsa::RsaPublicKey>);

impl RsaPublicKey {
    /// The modulus and public exponent of any HIS key (`7F49`, `7F4B`, `FF49`, `FF4B`).
    pub fn from_his_bytes(bytes: &[u8]) -> Result<Self, ProcessingError> {
        let key = HisRsaKey::parse(bytes).ok_or_else(|| invalid_key("HIS RSA key"))?;
        rsa::RsaPublicKey::new(key.modulus, key.public_exponent)
            .map(|key| Self(Box::new(key)))
            .map_err(|e| ProcessingError::InvalidKey(e.to_string()))
    }

    /// A HIS key or a PKCS #1 or SPKI key in hex text; or a PKCS #1 or SPKI public key,
    /// a private key, or an X.509 certificate, in DER or PEM. A private key gives its
    /// public part.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        let public = |key: RsaPrivateKey| Self(Box::new(key.0.to_public_key()));
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
            .map(|key| Self(Box::new(key)))
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

/// `ecPublicKey` (1.2.840.10045.2.1).
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
/// `prime256v1` (1.2.840.10045.3.1.7).
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];

/// Whether an `AlgorithmIdentifier` names an ECC key: `ecPublicKey`, with any
/// parameters, or the `id-EdDSA25519-ph` (1.3.101.114) HexView uses for Ed25519; hexy
/// also reads `id-Ed25519` (1.3.101.112).
fn is_ecc_algorithm(algorithm: &[u8]) -> bool {
    matches!(
        read_tlv(algorithm),
        Some((0x06, oid, _)) if oid == OID_EC_PUBLIC_KEY || matches!(oid, [0x2B, 0x65, 0x70 | 0x72])
    )
}

/// The private key and, if present, the public key of an ECC private key in DER.
struct EccKeyDer<'a> {
    private: &'a [u8],
    public: Option<&'a [u8]>,
}

/// An ECC private key in the DER forms HexView reads for Ed25519 and P-256 alike:
///
/// - SEC1: `SEQUENCE { 1, OCTET STRING key [, [0] { prime256v1 }] [, [1] { BIT STRING
///   public key }] }`
/// - `SEQUENCE { 0, AlgorithmIdentifier, OCTET STRING { OCTET STRING key | SEC1 key }
///   [, OCTET STRING { OCTET STRING public key } | [1] public key] }`, which includes
///   PKCS #8
fn ecc_private_der(der: &[u8]) -> Option<EccKeyDer<'_>> {
    let items = sequence(der)?;
    match items.as_slice() {
        [(0x02, [1]), (0x04, private), rest @ ..] => {
            let mut key = EccKeyDer {
                private,
                public: None,
            };
            for (tag, value) in rest {
                match (tag, read_tlv(value)?) {
                    (0xA0, (0x06, OID_P256, [])) => {}
                    (0xA1, (0x03, [0, public @ ..], [])) => key.public = Some(public),
                    _ => return None,
                }
            }
            Some(key)
        }
        [(0x02, [0 | 1]), (0x30, algorithm), (0x04, inner), rest @ ..]
            if is_ecc_algorithm(algorithm) =>
        {
            let mut key = match read_tlv(inner)? {
                (0x04, private, []) => EccKeyDer {
                    private,
                    public: None,
                },
                (0x30, _, []) => ecc_private_der(inner)?,
                _ => return None,
            };
            match rest.first() {
                Some((0x04, public)) => {
                    let (0x04, public, []) = read_tlv(public)? else {
                        return None;
                    };
                    key.public = Some(public);
                }
                // PKCS #8 v2: `[1] IMPLICIT BIT STRING`.
                Some((0x81, [0x00, public @ ..])) => key.public = Some(public),
                _ => {}
            }
            Some(key)
        }
        _ => None,
    }
}

/// Public key of an ECC `SubjectPublicKeyInfo` in DER.
fn ecc_spki_der(der: &[u8]) -> Option<&[u8]> {
    let items = sequence(der)?;
    let [(0x30, algorithm), (0x03, [0x00, public @ ..])] = items.as_slice() else {
        return None;
    };
    is_ecc_algorithm(algorithm).then_some(public)
}

/// HexView reads raw ECC keys as 32 bytes: shorter keys are padded with zero bytes at
/// the end, and longer keys are cut after 32 bytes.
fn raw_ecc_key(bytes: &[u8]) -> [u8; 32] {
    let mut key = [0; 32];
    let len = bytes.len().min(32);
    key[..len].copy_from_slice(&bytes[..len]);
    key
}

/// The private key of an ECC key file: a key in DER, given in PEM, binary or hex text,
/// or else the raw key in hex text.
fn ecc_private_key(content: &[u8]) -> Option<[u8; 32]> {
    match KeyContent::read(content) {
        KeyContent::Hex(bytes) if bytes.is_empty() => None,
        KeyContent::Hex(bytes) => Some(raw_ecc_key(
            ecc_private_der(&bytes).map_or(bytes.as_slice(), |key| key.private),
        )),
        KeyContent::Der(der) => ecc_private_der(&der).map(|key| raw_ecc_key(key.private)),
    }
}

/// The public key in ECC key DER: from a private key that includes it, an SPKI public
/// key, or an X.509 certificate.
fn ecc_public_der(der: &[u8]) -> Option<Vec<u8>> {
    ecc_private_der(der)
        .and_then(|key| key.public)
        .or_else(|| ecc_spki_der(der))
        .map(<[u8]>::to_vec)
        .or_else(|| ecc_spki_der(&certificate_spki(der)?).map(<[u8]>::to_vec))
}

#[derive(Debug, Clone)]
pub struct Ed25519PrivateKey(pub(super) Box<EdSigningKey>);

impl Ed25519PrivateKey {
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Self(Box::new(EdSigningKey::from_bytes(seed)))
    }

    /// An ECC private key in PEM, DER or hex text, or a raw seed in hex text.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        ecc_private_key(content)
            .map(|seed| Self::from_bytes(&seed))
            .ok_or_else(|| invalid_key("Ed25519 private key"))
    }
}

#[derive(Debug, Clone)]
pub struct Ed25519PublicKey(pub(super) Box<EdVerifyingKey>);

impl Ed25519PublicKey {
    pub fn from_bytes(public: &[u8; 32]) -> Result<Self, ProcessingError> {
        EdVerifyingKey::from_bytes(public)
            .map(|key| Self(Box::new(key)))
            .map_err(|e| ProcessingError::InvalidKey(e.to_string()))
    }

    /// A private key that includes its public key, an SPKI public key, or an X.509
    /// certificate, in PEM, DER or hex text; or a raw key in hex text.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        let public = match KeyContent::read(content) {
            KeyContent::Hex(bytes) if bytes.is_empty() => return Err(invalid_key("empty Ed25519 public key")),
            KeyContent::Hex(bytes) => {
                ecc_public_der(&bytes).unwrap_or_else(|| raw_ecc_key(&bytes).to_vec())
            }
            KeyContent::Der(der) => ecc_public_der(&der).unwrap_or_default(),
        };
        let public = public
            .try_into()
            .map_err(|_| invalid_key("Ed25519 public key"))?;
        Self::from_bytes(&public)
    }
}

/// A P-256 private key.
#[derive(Debug, Clone)]
pub struct P256PrivateKey(pub(super) Box<P256SigningKey>);

impl P256PrivateKey {
    /// A big-endian scalar.
    pub fn from_bytes(scalar: &[u8; 32]) -> Result<Self, ProcessingError> {
        P256SigningKey::from_slice(scalar)
            .map(|key| Self(Box::new(key)))
            .map_err(|_| invalid_key("P-256 private key"))
    }

    /// An ECC private key in PEM, DER or hex text, or a raw scalar in hex text.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        let scalar = ecc_private_key(content).ok_or_else(|| invalid_key("P-256 private key"))?;
        Self::from_bytes(&scalar)
    }
}

#[derive(Debug, Clone)]
pub struct P256PublicKey(pub(super) Box<P256VerifyingKey>);

impl P256PublicKey {
    /// A SEC1 point: `04`, X and Y, or a compressed point.
    pub fn from_sec1_bytes(point: &[u8]) -> Result<Self, ProcessingError> {
        P256VerifyingKey::from_sec1_bytes(point)
            .map(|key| Self(Box::new(key)))
            .map_err(|_| invalid_key("P-256 public key"))
    }

    /// A private key that includes its public key, an SPKI public key, or an X.509
    /// certificate, in PEM, DER or hex text.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        let (KeyContent::Hex(der) | KeyContent::Der(der)) = KeyContent::read(content);
        let point = ecc_public_der(&der).ok_or_else(|| invalid_key("P-256 public key"))?;
        Self::from_sec1_bytes(&point)
    }
}

/// The bytes of hex text; HexView reads symmetric keys only from hex text.
fn hex_key(content: &[u8], kind: &str) -> Result<Vec<u8>, ProcessingError> {
    decode_hex_text(content)
        .filter(|key| !key.is_empty())
        .ok_or_else(|| invalid_key(kind))
}

/// A HIS MAC key: `FF59` or `FF5B`, an ASN.1 length, then tag `D3`, an ASN.1 length and
/// the key. `None` when the bytes do not start with a whole HIS item, so that they are
/// read as a plain key.
fn his_mac_key(bytes: &[u8]) -> Option<Result<Vec<u8>, ProcessingError>> {
    let Some((0xFF, rest)) = bytes.split_first() else {
        return None;
    };
    let (0x59 | 0x5B, value, rest) = read_tlv(rest)? else {
        return None;
    };
    Some(match read_tlv(value) {
        Some((0xD3, key, [])) if rest.is_empty() && !key.is_empty() => Ok(key.to_vec()),
        _ => Err(invalid_key("HIS MAC key")),
    })
}

/// A key for HMAC or CMAC.
#[derive(Debug, Clone)]
pub struct MacKey(pub(super) Vec<u8>);

impl MacKey {
    pub fn new(key: &[u8]) -> Result<Self, ProcessingError> {
        if key.is_empty() {
            return Err(invalid_key("empty MAC key"));
        }
        Ok(Self(key.to_vec()))
    }

    /// A HIS MAC key in hex text, or any other hex text as the key bytes.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        let bytes = hex_key(content, "MAC key")?;
        his_mac_key(&bytes).unwrap_or(Ok(bytes)).map(Self)
    }
}

/// An AES-128, AES-192 or AES-256 key.
#[derive(Debug, Clone)]
pub struct AesKey(pub(super) Vec<u8>);

impl AesKey {
    /// A 16, 24 or 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self, ProcessingError> {
        if !matches!(key.len(), 16 | 24 | 32) {
            return Err(ProcessingError::InvalidKey(format!(
                "AES key must be 16, 24 or 32 bytes, not {}",
                key.len()
            )));
        }
        Ok(Self(key.to_vec()))
    }

    /// The key in hex text.
    pub fn from_key_file(content: &[u8]) -> Result<Self, ProcessingError> {
        Self::new(&hex_key(content, "AES key")?)
    }
}

#[cfg(test)]
mod tests {
    use super::{MacKey, RsaPrivateKey, decode_hex_text};

    /// HexView 1.15.2 `/DP4` keys: a whole `FF59`/`FF5B` item is a HIS key, a longer
    /// length makes the text a plain key, and a malformed HIS item fails.
    #[test]
    fn test_mac_key_reads_his_keys() {
        let key = |text: &str| MacKey::from_key_file(text.as_bytes()).map(|key| key.0);
        let plain = "00112233445566778899aabbccddeeff";
        let bytes = decode_hex_text(plain.as_bytes()).unwrap();
        assert_eq!(key(&format!("FF5B12D310{plain}")).unwrap(), bytes);
        assert_eq!(key(&format!("FF5912D310{plain}")).unwrap(), bytes);
        let overlong = format!("FF5B13D310{plain}");
        assert_eq!(
            key(&overlong).unwrap(),
            decode_hex_text(overlong.as_bytes()).unwrap()
        );
        assert!(key(&format!("FF5B12D310{plain}AABB")).is_err());
        assert!(key(&format!("FF5B12D410{plain}")).is_err());
        assert!(key("").is_err());
    }

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

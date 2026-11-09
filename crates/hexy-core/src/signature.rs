use std::path::PathBuf;

use crate::{HexFile, OpsError, Placement};
use ed25519_dalek::pkcs8::{
    DecodePrivateKey as EdDecodePrivateKey, DecodePublicKey as EdDecodePublicKey,
};
use ed25519_dalek::{
    Signature as EdSignature, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use rsa::pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey};
use rsa::pkcs1v15::{
    Signature as RsaPkcs1v15Signature, SigningKey as RsaPkcs1v15SigningKey,
    VerifyingKey as RsaPkcs1v15VerifyingKey,
};
use rsa::pss::{
    Signature as RsaPssSignature, SigningKey as RsaPssSigningKey,
    VerifyingKey as RsaPssVerifyingKey,
};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256, Sha512};
use thiserror::Error;
use x509_cert::Certificate;
use x509_cert::der::{Decode, DecodePem, Encode};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMethod {
    RsaPkcs1v15Sha256 { with_metadata: bool },
    RsaPssSha256 { with_metadata: bool },
    Ed25519Ph { with_metadata: bool },
    Ed25519Sha512Data { with_metadata: bool },
}

impl SignatureMethod {
    fn with_metadata(self) -> bool {
        matches!(
            self,
            SignatureMethod::RsaPkcs1v15Sha256 {
                with_metadata: true
            } | SignatureMethod::RsaPssSha256 {
                with_metadata: true
            } | SignatureMethod::Ed25519Ph {
                with_metadata: true
            } | SignatureMethod::Ed25519Sha512Data {
                with_metadata: true
            }
        )
    }
}

#[derive(Debug, Clone)]
pub struct SignatureSignOptions {
    pub method: SignatureMethod,
    pub key_source: SignatureKeySource,
    pub placement: Option<Placement>,
}

#[derive(Debug, Clone)]
pub struct SignatureVerifyOptions {
    pub method: SignatureMethod,
    pub key_source: SignatureKeySource,
    pub signature_source: SignatureBytesSource,
}

#[derive(Debug, Clone)]
pub enum SignatureKeySource {
    Bytes(Vec<u8>),
    File(PathBuf),
    Text(String),
}

#[derive(Debug, Clone)]
pub enum SignatureBytesSource {
    Bytes(Vec<u8>),
    File(PathBuf),
}

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("signature payload length exceeds u32")]
    PayloadLengthOverflow,

    #[error("signature placement: {0}")]
    Placement(#[from] OpsError),

    #[error("{0}")]
    InvalidKeyMaterial(String),

    #[error("{0}")]
    InvalidSignatureBytes(String),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("{0}")]
    Crypto(String),
}

impl HexFile {
    pub fn sign(&mut self, options: &SignatureSignOptions) -> Result<Vec<u8>, SignatureError> {
        let payload = signature_payload(self, options.method.with_metadata())?;
        let key_material = resolve_key_material(&options.key_source)?;
        let signature = sign_payload(options.method, &payload, &key_material)?;
        if let Some(placement) = options.placement
            && let Some(target) = self.placement_range(placement, signature.len())?
        {
            self.write_bytes(target.start(), &signature)?;
        }
        Ok(signature)
    }

    pub fn verify_signature(&self, options: &SignatureVerifyOptions) -> Result<(), SignatureError> {
        let payload = signature_payload(self, options.method.with_metadata())?;
        let key_material = resolve_key_material(&options.key_source)?;
        let signature = resolve_signature_bytes(&options.signature_source)?;
        verify_payload(options.method, &payload, &key_material, &signature)
    }
}

/// The block data in address order; with metadata, each block is preceded by its start
/// address and length as big-endian `u32`s.
fn signature_payload(hexfile: &HexFile, with_metadata: bool) -> Result<Vec<u8>, SignatureError> {
    let mut payload = Vec::new();
    for block in hexfile.blocks() {
        if with_metadata {
            let len =
                u32::try_from(block.len()).map_err(|_| SignatureError::PayloadLengthOverflow)?;
            payload.extend_from_slice(&block.start_address.to_be_bytes());
            payload.extend_from_slice(&len.to_be_bytes());
        }
        payload.extend_from_slice(&block.data);
    }
    Ok(payload)
}

fn resolve_key_material(source: &SignatureKeySource) -> Result<Vec<u8>, SignatureError> {
    match source {
        SignatureKeySource::Bytes(bytes) => Ok(bytes.clone()),
        SignatureKeySource::File(path) => {
            std::fs::read(path).map_err(|e| SignatureError::InvalidKeyMaterial(e.to_string()))
        }
        SignatureKeySource::Text(text) => Ok(text.as_bytes().to_vec()),
    }
}

fn resolve_signature_bytes(source: &SignatureBytesSource) -> Result<Vec<u8>, SignatureError> {
    match source {
        SignatureBytesSource::Bytes(bytes) => Ok(bytes.clone()),
        SignatureBytesSource::File(path) => {
            let content = std::fs::read(path)
                .map_err(|e| SignatureError::InvalidSignatureBytes(e.to_string()))?;
            Ok(decode_signature_text(&content).unwrap_or(content))
        }
    }
}

/// Bytes of `/DP` outfile text (`0xAA ,0xBB`), or `None` for any other content.
pub fn decode_signature_text(content: &[u8]) -> Option<Vec<u8>> {
    std::str::from_utf8(content)
        .ok()?
        .split(',')
        .map(|item| {
            let hex = item.trim().strip_prefix("0x")?;
            (hex.len() == 2).then(|| u8::from_str_radix(hex, 16).ok())?
        })
        .collect()
}

fn sign_payload(
    method: SignatureMethod,
    payload: &[u8],
    key_material: &[u8],
) -> Result<Vec<u8>, SignatureError> {
    match method {
        SignatureMethod::RsaPkcs1v15Sha256 { .. } => {
            let key = load_rsa_private_key(key_material)?;
            let signer = RsaPkcs1v15SigningKey::<Sha256>::new(key);
            Ok(signer.sign(payload).to_vec())
        }
        SignatureMethod::RsaPssSha256 { .. } => {
            let key = load_rsa_private_key(key_material)?;
            let signer = RsaPssSigningKey::<Sha256>::new(key);
            Ok(signer.sign(payload).to_vec())
        }
        SignatureMethod::Ed25519Ph { .. } => {
            let key = load_ed25519_private_key(key_material)?;
            let prehashed = Sha512::new_with_prefix(payload);
            let signature = key
                .sign_prehashed(prehashed, None)
                .map_err(|e| SignatureError::Crypto(e.to_string()))?;
            Ok(signature.to_bytes().to_vec())
        }
        SignatureMethod::Ed25519Sha512Data { .. } => {
            let key = load_ed25519_private_key(key_material)?;
            let digest = Sha512::digest(payload);
            Ok(key.sign(&digest).to_bytes().to_vec())
        }
    }
}

fn verify_payload(
    method: SignatureMethod,
    payload: &[u8],
    key_material: &[u8],
    signature_bytes: &[u8],
) -> Result<(), SignatureError> {
    match method {
        SignatureMethod::RsaPkcs1v15Sha256 { .. } => {
            let key = load_rsa_public_key(key_material)?;
            let signature = RsaPkcs1v15Signature::try_from(signature_bytes).map_err(|_| {
                SignatureError::InvalidSignatureBytes(
                    "invalid RSA PKCS1 signature bytes".to_owned(),
                )
            })?;
            let verifier = RsaPkcs1v15VerifyingKey::<Sha256>::new(key);
            verifier
                .verify(payload, &signature)
                .map_err(|_| SignatureError::VerificationFailed)
        }
        SignatureMethod::RsaPssSha256 { .. } => {
            let key = load_rsa_public_key(key_material)?;
            let signature = RsaPssSignature::try_from(signature_bytes).map_err(|_| {
                SignatureError::InvalidSignatureBytes("invalid RSA PSS signature bytes".to_owned())
            })?;
            let verifier = RsaPssVerifyingKey::<Sha256>::new(key);
            verifier
                .verify(payload, &signature)
                .map_err(|_| SignatureError::VerificationFailed)
        }
        SignatureMethod::Ed25519Ph { .. } => {
            let key = load_ed25519_public_key(key_material)?;
            let signature = EdSignature::from_slice(signature_bytes).map_err(|_| {
                SignatureError::InvalidSignatureBytes("invalid ed25519 signature bytes".to_owned())
            })?;
            let prehashed = Sha512::new_with_prefix(payload);
            key.verify_prehashed(prehashed, None, &signature)
                .map_err(|_| SignatureError::VerificationFailed)
        }
        SignatureMethod::Ed25519Sha512Data { .. } => {
            let key = load_ed25519_public_key(key_material)?;
            let signature = EdSignature::from_slice(signature_bytes).map_err(|_| {
                SignatureError::InvalidSignatureBytes("invalid ed25519 signature bytes".to_owned())
            })?;
            let digest = Sha512::digest(payload);
            key.verify(&digest, &signature)
                .map_err(|_| SignatureError::VerificationFailed)
        }
    }
}

fn load_rsa_private_key(key_material: &[u8]) -> Result<RsaPrivateKey, SignatureError> {
    if let Ok(text) = std::str::from_utf8(key_material) {
        let text = text.trim();
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(text) {
            return Ok(key);
        }
        if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(text) {
            return Ok(key);
        }
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs8_der(key_material) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_der(key_material) {
        return Ok(key);
    }
    Err(SignatureError::InvalidKeyMaterial(
        "unable to parse RSA private key".to_owned(),
    ))
}

fn load_rsa_public_key(key_material: &[u8]) -> Result<RsaPublicKey, SignatureError> {
    if let Ok(text) = std::str::from_utf8(key_material) {
        let text = text.trim();
        if let Ok(key) = RsaPublicKey::from_public_key_pem(text) {
            return Ok(key);
        }
        if let Ok(key) = RsaPublicKey::from_pkcs1_pem(text) {
            return Ok(key);
        }
    }
    if let Ok(key) = RsaPublicKey::from_public_key_der(key_material) {
        return Ok(key);
    }
    if let Ok(key) = RsaPublicKey::from_pkcs1_der(key_material) {
        return Ok(key);
    }
    if let Some(spki_der) = extract_spki_from_certificate(key_material)
        && let Ok(key) = RsaPublicKey::from_public_key_der(&spki_der)
    {
        return Ok(key);
    }
    Err(SignatureError::InvalidKeyMaterial(
        "unable to parse RSA public key or certificate".to_owned(),
    ))
}

fn load_ed25519_private_key(key_material: &[u8]) -> Result<EdSigningKey, SignatureError> {
    if let Ok(text) = std::str::from_utf8(key_material) {
        let text = text.trim();
        if let Ok(key) = EdSigningKey::from_pkcs8_pem(text) {
            return Ok(key);
        }
    }
    if let Ok(key) = EdSigningKey::from_pkcs8_der(key_material) {
        return Ok(key);
    }
    Err(SignatureError::InvalidKeyMaterial(
        "unable to parse ed25519 private key".to_owned(),
    ))
}

fn load_ed25519_public_key(key_material: &[u8]) -> Result<EdVerifyingKey, SignatureError> {
    if let Ok(text) = std::str::from_utf8(key_material) {
        let text = text.trim();
        if let Ok(key) = EdVerifyingKey::from_public_key_pem(text) {
            return Ok(key);
        }
    }
    if let Ok(key) = EdVerifyingKey::from_public_key_der(key_material) {
        return Ok(key);
    }
    if let Some(spki_der) = extract_spki_from_certificate(key_material)
        && let Ok(key) = EdVerifyingKey::from_public_key_der(&spki_der)
    {
        return Ok(key);
    }
    Err(SignatureError::InvalidKeyMaterial(
        "unable to parse ed25519 public key or certificate".to_owned(),
    ))
}

fn extract_spki_from_certificate(key_material: &[u8]) -> Option<Vec<u8>> {
    if let Ok(cert) = Certificate::from_pem(key_material) {
        return cert.tbs_certificate.subject_public_key_info.to_der().ok();
    }
    if let Ok(cert) = Certificate::from_der(key_material) {
        return cert.tbs_certificate.subject_public_key_info.to_der().ok();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    /// HexView 1.15.2 `/DP33` hashes each block as big-endian start, big-endian length
    /// and data; split pieces count as blocks (verified against its RSA signatures).
    #[test]
    fn test_metadata_payload_lists_each_block() {
        let mut file = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA; 0x180]).unwrap(),
            Segment::new(0x2000, vec![0xBB]).unwrap(),
        ]);
        file.split(0x100);
        let payload = signature_payload(&file, true).unwrap();
        let mut expected = Vec::new();
        for (start, data) in [
            (0x1000u32, [0xAA; 0x100].as_slice()),
            (0x1100, &[0xAA; 0x80]),
            (0x2000, &[0xBB]),
        ] {
            expected.extend_from_slice(&start.to_be_bytes());
            expected.extend_from_slice(&(data.len() as u32).to_be_bytes());
            expected.extend_from_slice(data);
        }
        assert_eq!(payload, expected);
    }
}

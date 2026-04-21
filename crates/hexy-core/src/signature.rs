use std::path::Path;

use crate::HexFile;
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
pub struct SignatureSignOptions<'a> {
    pub method: SignatureMethod,
    pub key_source: SignatureKeySource<'a>,
    pub placement: Option<SignaturePlacement>,
}

#[derive(Debug, Clone)]
pub struct SignatureVerifyOptions<'a> {
    pub method: SignatureMethod,
    pub key_source: SignatureKeySource<'a>,
    pub signature_source: SignatureBytesSource<'a>,
}

#[derive(Debug, Clone, Copy)]
pub enum SignatureKeySource<'a> {
    Bytes(&'a [u8]),
    File(&'a Path),
    Text(&'a str),
}

#[derive(Debug, Clone, Copy)]
pub enum SignatureBytesSource<'a> {
    Bytes(&'a [u8]),
    File(&'a Path),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignaturePlacement {
    Address(u32),
    Append,
    Begin,
    Prepend,
    OverwriteEnd,
}

#[derive(Debug, Error)]
pub enum SignatureError {
    #[error("signature payload length exceeds u32")]
    PayloadLengthOverflow,

    #[error("signature append overflows u32")]
    AppendOverflow,

    #[error("signature prepend underflows u32")]
    PrependUnderflow,

    #[error("signature overwrite underflows u32")]
    OverwriteUnderflow,

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
    pub fn sign(&mut self, options: &SignatureSignOptions<'_>) -> Result<Vec<u8>, SignatureError> {
        let payload = signature_payload(self, options.method.with_metadata())?;
        let key_material = resolve_key_material(options.key_source)?;
        let signature = sign_payload(options.method, &payload, &key_material)?;
        if let Some(target) = options.placement.as_ref() {
            self.place_signature(target, &signature)?;
        }
        Ok(signature)
    }

    pub fn verify_signature(
        &self,
        options: &SignatureVerifyOptions<'_>,
    ) -> Result<(), SignatureError> {
        let payload = signature_payload(self, options.method.with_metadata())?;
        let key_material = resolve_key_material(options.key_source)?;
        let signature = resolve_signature_bytes(options.signature_source)?;
        verify_payload(options.method, &payload, &key_material, &signature)
    }

    fn place_signature(
        &mut self,
        target: &SignaturePlacement,
        signature: &[u8],
    ) -> Result<(), SignatureError> {
        match target {
            SignaturePlacement::Address(addr) => {
                self.write_bytes(*addr, signature);
                Ok(())
            }
            SignaturePlacement::Append => {
                if let Some(end) = self.max_address() {
                    let addr = end.checked_add(1).ok_or(SignatureError::AppendOverflow)?;
                    self.write_bytes(addr, signature);
                }
                Ok(())
            }
            SignaturePlacement::Begin => {
                if let Some(start) = self.min_address() {
                    self.write_bytes(start, signature);
                } else {
                    self.place_signature(&SignaturePlacement::Append, signature)?;
                }
                Ok(())
            }
            SignaturePlacement::Prepend => {
                if let Some(start) = self.min_address() {
                    let new_start = start
                        .checked_sub(signature.len() as u32)
                        .ok_or(SignatureError::PrependUnderflow)?;
                    self.write_bytes(new_start, signature);
                }
                Ok(())
            }
            SignaturePlacement::OverwriteEnd => {
                if let Some(end) = self.max_address() {
                    let offset = (signature.len() as u32).saturating_sub(1);
                    let write_addr = end
                        .checked_sub(offset)
                        .ok_or(SignatureError::OverwriteUnderflow)?;
                    self.write_bytes(write_addr, signature);
                }
                Ok(())
            }
        }
    }
}

fn signature_payload(hexfile: &HexFile, with_metadata: bool) -> Result<Vec<u8>, SignatureError> {
    let normalized = hexfile.normalized();
    let mut data = Vec::new();
    for seg in normalized.segments() {
        data.extend_from_slice(&seg.data);
    }
    if !with_metadata {
        return Ok(data);
    }
    let start = normalized.min_address().unwrap_or(0);
    let len = u32::try_from(data.len()).map_err(|_| SignatureError::PayloadLengthOverflow)?;
    let mut out = Vec::with_capacity(8 + data.len());
    out.extend_from_slice(&start.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&data);
    Ok(out)
}

fn resolve_key_material(source: SignatureKeySource<'_>) -> Result<Vec<u8>, SignatureError> {
    match source {
        SignatureKeySource::Bytes(bytes) => Ok(bytes.to_vec()),
        SignatureKeySource::File(path) => {
            std::fs::read(path).map_err(|e| SignatureError::InvalidKeyMaterial(e.to_string()))
        }
        SignatureKeySource::Text(text) => Ok(text.as_bytes().to_vec()),
    }
}

fn resolve_signature_bytes(source: SignatureBytesSource<'_>) -> Result<Vec<u8>, SignatureError> {
    match source {
        SignatureBytesSource::Bytes(bytes) => Ok(bytes.to_vec()),
        SignatureBytesSource::File(path) => {
            std::fs::read(path).map_err(|e| SignatureError::InvalidSignatureBytes(e.to_string()))
        }
    }
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

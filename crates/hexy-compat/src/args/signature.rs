use std::path::Path;

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
use x509_cert::Certificate;
use x509_cert::der::{Decode, DecodePem, Encode};

use super::error::CliError;
use super::types::{ChecksumTarget, DataProcessingParams, SignatureVerifyParams};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SignatureMethod {
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

pub(super) fn is_supported_data_processing_method(method: u8) -> bool {
    matches!(method, 32 | 33 | 38 | 39 | 46 | 47 | 48 | 49)
}

pub(super) fn is_supported_signature_verify_method(method: u8) -> bool {
    matches!(method, 4..=11)
}

fn map_data_processing_method(method: u8) -> Option<SignatureMethod> {
    match method {
        32 => Some(SignatureMethod::RsaPkcs1v15Sha256 {
            with_metadata: false,
        }),
        33 => Some(SignatureMethod::RsaPkcs1v15Sha256 {
            with_metadata: true,
        }),
        38 => Some(SignatureMethod::RsaPssSha256 {
            with_metadata: false,
        }),
        39 => Some(SignatureMethod::RsaPssSha256 {
            with_metadata: true,
        }),
        46 => Some(SignatureMethod::Ed25519Ph {
            with_metadata: false,
        }),
        47 => Some(SignatureMethod::Ed25519Ph {
            with_metadata: true,
        }),
        48 => Some(SignatureMethod::Ed25519Sha512Data {
            with_metadata: false,
        }),
        49 => Some(SignatureMethod::Ed25519Sha512Data {
            with_metadata: true,
        }),
        _ => None,
    }
}

fn map_signature_verify_method(method: u8) -> Option<SignatureMethod> {
    match method {
        4 => Some(SignatureMethod::RsaPkcs1v15Sha256 {
            with_metadata: false,
        }),
        5 => Some(SignatureMethod::RsaPkcs1v15Sha256 {
            with_metadata: true,
        }),
        6 => Some(SignatureMethod::RsaPssSha256 {
            with_metadata: false,
        }),
        7 => Some(SignatureMethod::RsaPssSha256 {
            with_metadata: true,
        }),
        8 => Some(SignatureMethod::Ed25519Ph {
            with_metadata: false,
        }),
        9 => Some(SignatureMethod::Ed25519Ph {
            with_metadata: true,
        }),
        10 => Some(SignatureMethod::Ed25519Sha512Data {
            with_metadata: false,
        }),
        11 => Some(SignatureMethod::Ed25519Sha512Data {
            with_metadata: true,
        }),
        _ => None,
    }
}

pub(super) fn apply_data_processing(
    hexfile: &mut crate::HexFile,
    params: &DataProcessingParams,
) -> Result<Option<Vec<u8>>, CliError> {
    let Some(method) = map_data_processing_method(params.method) else {
        return Ok(None);
    };
    let payload = signature_payload(hexfile, method.with_metadata())?;
    let signature = sign_payload(method, &payload, &params.key_info)
        .map_err(|e| CliError::Other(format!("/DP{}: {e}", params.method)))?;
    if let Some(target) = params.placement.as_ref() {
        place_signature(hexfile, target, &signature)
            .map_err(|e| CliError::Other(format!("/DP{}: {e}", params.method)))?;
    }
    if let Some(path) = params.output_file.as_ref() {
        std::fs::write(path, &signature)
            .map_err(|e| CliError::Other(format!("/DP{}: {e}", params.method)))?;
    }
    Ok(Some(signature))
}

pub(super) fn apply_signature_verification(
    hexfile: &crate::HexFile,
    params: &SignatureVerifyParams,
) -> Result<(), CliError> {
    let Some(method) = map_signature_verify_method(params.method) else {
        return Ok(());
    };
    let payload = signature_payload(hexfile, method.with_metadata())?;
    let signature_bytes = load_signature_bytes(&params.signature_info)
        .map_err(|e| CliError::Other(format!("/SV{}: {e}", params.method)))?;
    verify_payload(method, &payload, &params.key_info, &signature_bytes)
        .map_err(|e| CliError::Other(format!("/SV{}: {e}", params.method)))?;
    Ok(())
}

fn signature_payload(hexfile: &crate::HexFile, with_metadata: bool) -> Result<Vec<u8>, CliError> {
    let normalized = hexfile.normalized();
    let mut data = Vec::new();
    for seg in normalized.segments() {
        data.extend_from_slice(&seg.data);
    }
    if !with_metadata {
        return Ok(data);
    }
    let start = normalized.min_address().unwrap_or(0);
    let len = u32::try_from(data.len())
        .map_err(|_| CliError::Other("signature payload length exceeds u32".to_string()))?;
    let mut out = Vec::with_capacity(8 + data.len());
    out.extend_from_slice(&start.to_be_bytes());
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&data);
    Ok(out)
}

fn place_signature(
    hexfile: &mut crate::HexFile,
    target: &ChecksumTarget,
    signature: &[u8],
) -> Result<(), String> {
    match target {
        ChecksumTarget::Address(addr) => {
            hexfile.write_bytes(*addr, signature);
            Ok(())
        }
        ChecksumTarget::Append => {
            if let Some(end) = hexfile.max_address() {
                let addr = end
                    .checked_add(1)
                    .ok_or_else(|| "signature append overflows u32".to_string())?;
                hexfile.write_bytes(addr, signature);
            }
            Ok(())
        }
        ChecksumTarget::Begin => {
            if let Some(start) = hexfile.min_address() {
                hexfile.write_bytes(start, signature);
            } else {
                return place_signature(hexfile, &ChecksumTarget::Append, signature);
            }
            Ok(())
        }
        ChecksumTarget::Prepend => {
            if let Some(start) = hexfile.min_address() {
                let new_start = start
                    .checked_sub(signature.len() as u32)
                    .ok_or_else(|| "signature prepend underflows u32".to_string())?;
                hexfile.write_bytes(new_start, signature);
            }
            Ok(())
        }
        ChecksumTarget::OverwriteEnd => {
            if let Some(end) = hexfile.max_address() {
                let offset = (signature.len() as u32).saturating_sub(1);
                let write_addr = end
                    .checked_sub(offset)
                    .ok_or_else(|| "signature overwrite underflows u32".to_string())?;
                hexfile.write_bytes(write_addr, signature);
            }
            Ok(())
        }
        ChecksumTarget::File(_) => Err("file target is not valid for /DP placement".to_string()),
    }
}

fn load_signature_bytes(signature_info: &str) -> Result<Vec<u8>, String> {
    let source = signature_info.trim();
    if source.is_empty() {
        return Err("signature info is empty".to_string());
    }
    let path = Path::new(source);
    if path.exists() {
        return std::fs::read(path).map_err(|e| e.to_string());
    }
    parse_hex_signature(source)
}

fn parse_hex_signature(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
    if cleaned.is_empty() {
        return Err("signature is neither an existing file path nor a hex string".to_string());
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err("signature hex string must have even length".to_string());
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        let byte = u8::from_str_radix(&cleaned[i..i + 2], 16)
            .map_err(|_| "invalid signature hex string".to_string())?;
        out.push(byte);
    }
    Ok(out)
}

fn sign_payload(
    method: SignatureMethod,
    payload: &[u8],
    key_info: &str,
) -> Result<Vec<u8>, String> {
    match method {
        SignatureMethod::RsaPkcs1v15Sha256 { .. } => {
            let key = load_rsa_private_key(key_info)?;
            let signer = RsaPkcs1v15SigningKey::<Sha256>::new(key);
            Ok(signer.sign(payload).to_vec())
        }
        SignatureMethod::RsaPssSha256 { .. } => {
            let key = load_rsa_private_key(key_info)?;
            let signer = RsaPssSigningKey::<Sha256>::new(key);
            Ok(signer.sign(payload).to_vec())
        }
        SignatureMethod::Ed25519Ph { .. } => {
            let key = load_ed25519_private_key(key_info)?;
            let prehashed = Sha512::new_with_prefix(payload);
            let signature = key
                .sign_prehashed(prehashed, None)
                .map_err(|e| e.to_string())?;
            Ok(signature.to_bytes().to_vec())
        }
        SignatureMethod::Ed25519Sha512Data { .. } => {
            let key = load_ed25519_private_key(key_info)?;
            let digest = Sha512::digest(payload);
            Ok(key.sign(&digest).to_bytes().to_vec())
        }
    }
}

fn verify_payload(
    method: SignatureMethod,
    payload: &[u8],
    key_info: &str,
    signature_bytes: &[u8],
) -> Result<(), String> {
    match method {
        SignatureMethod::RsaPkcs1v15Sha256 { .. } => {
            let key = load_rsa_public_key(key_info)?;
            let signature = RsaPkcs1v15Signature::try_from(signature_bytes)
                .map_err(|_| "invalid RSA PKCS1 signature bytes".to_string())?;
            let verifier = RsaPkcs1v15VerifyingKey::<Sha256>::new(key);
            verifier
                .verify(payload, &signature)
                .map_err(|_| "signature verification failed".to_string())
        }
        SignatureMethod::RsaPssSha256 { .. } => {
            let key = load_rsa_public_key(key_info)?;
            let signature = RsaPssSignature::try_from(signature_bytes)
                .map_err(|_| "invalid RSA PSS signature bytes".to_string())?;
            let verifier = RsaPssVerifyingKey::<Sha256>::new(key);
            verifier
                .verify(payload, &signature)
                .map_err(|_| "signature verification failed".to_string())
        }
        SignatureMethod::Ed25519Ph { .. } => {
            let key = load_ed25519_public_key(key_info)?;
            let signature = EdSignature::from_slice(signature_bytes)
                .map_err(|_| "invalid ed25519 signature bytes".to_string())?;
            let prehashed = Sha512::new_with_prefix(payload);
            key.verify_prehashed(prehashed, None, &signature)
                .map_err(|_| "signature verification failed".to_string())
        }
        SignatureMethod::Ed25519Sha512Data { .. } => {
            let key = load_ed25519_public_key(key_info)?;
            let signature = EdSignature::from_slice(signature_bytes)
                .map_err(|_| "invalid ed25519 signature bytes".to_string())?;
            let digest = Sha512::digest(payload);
            key.verify(&digest, &signature)
                .map_err(|_| "signature verification failed".to_string())
        }
    }
}

fn load_key_material(key_info: &str) -> Result<Vec<u8>, String> {
    let key_source = key_info
        .split(',')
        .next()
        .map(str::trim)
        .ok_or_else(|| "missing key info".to_string())?;
    if key_source.is_empty() {
        return Err("missing key info".to_string());
    }
    let path = Path::new(key_source);
    if path.exists() {
        return std::fs::read(path).map_err(|e| e.to_string());
    }
    Ok(key_source.as_bytes().to_vec())
}

fn load_rsa_private_key(key_info: &str) -> Result<RsaPrivateKey, String> {
    let material = load_key_material(key_info)?;
    if let Ok(text) = std::str::from_utf8(&material) {
        let text = text.trim();
        if let Ok(key) = RsaPrivateKey::from_pkcs8_pem(text) {
            return Ok(key);
        }
        if let Ok(key) = RsaPrivateKey::from_pkcs1_pem(text) {
            return Ok(key);
        }
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs8_der(&material) {
        return Ok(key);
    }
    if let Ok(key) = RsaPrivateKey::from_pkcs1_der(&material) {
        return Ok(key);
    }
    Err("unable to parse RSA private key".to_string())
}

fn load_rsa_public_key(key_info: &str) -> Result<RsaPublicKey, String> {
    let material = load_key_material(key_info)?;
    if let Ok(text) = std::str::from_utf8(&material) {
        let text = text.trim();
        if let Ok(key) = RsaPublicKey::from_public_key_pem(text) {
            return Ok(key);
        }
        if let Ok(key) = RsaPublicKey::from_pkcs1_pem(text) {
            return Ok(key);
        }
    }
    if let Ok(key) = RsaPublicKey::from_public_key_der(&material) {
        return Ok(key);
    }
    if let Ok(key) = RsaPublicKey::from_pkcs1_der(&material) {
        return Ok(key);
    }
    if let Some(spki_der) = extract_spki_from_certificate(&material)
        && let Ok(key) = RsaPublicKey::from_public_key_der(&spki_der)
    {
        return Ok(key);
    }
    Err("unable to parse RSA public key or certificate".to_string())
}

fn load_ed25519_private_key(key_info: &str) -> Result<EdSigningKey, String> {
    let material = load_key_material(key_info)?;
    if let Ok(text) = std::str::from_utf8(&material) {
        let text = text.trim();
        if let Ok(key) = EdSigningKey::from_pkcs8_pem(text) {
            return Ok(key);
        }
    }
    if let Ok(key) = EdSigningKey::from_pkcs8_der(&material) {
        return Ok(key);
    }
    Err("unable to parse ed25519 private key".to_string())
}

fn load_ed25519_public_key(key_info: &str) -> Result<EdVerifyingKey, String> {
    let material = load_key_material(key_info)?;
    if let Ok(text) = std::str::from_utf8(&material) {
        let text = text.trim();
        if let Ok(key) = EdVerifyingKey::from_public_key_pem(text) {
            return Ok(key);
        }
    }
    if let Ok(key) = EdVerifyingKey::from_public_key_der(&material) {
        return Ok(key);
    }
    if let Some(spki_der) = extract_spki_from_certificate(&material)
        && let Ok(key) = EdVerifyingKey::from_public_key_der(&spki_der)
    {
        return Ok(key);
    }
    Err("unable to parse ed25519 public key or certificate".to_string())
}

fn extract_spki_from_certificate(material: &[u8]) -> Option<Vec<u8>> {
    if let Ok(cert) = Certificate::from_pem(material) {
        return cert.tbs_certificate.subject_public_key_info.to_der().ok();
    }
    if let Ok(cert) = Certificate::from_der(material) {
        return cert.tbs_certificate.subject_public_key_info.to_der().ok();
    }
    None
}

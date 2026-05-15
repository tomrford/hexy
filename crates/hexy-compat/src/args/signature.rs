use super::error::CliError;
use super::types::{ChecksumTarget, DataProcessingParams, SignatureVerifyParams};
use hexy_core::{
    SignatureBytesSource, SignatureKeySource, SignatureMethod, SignaturePlacement,
    SignatureSignOptions, SignatureVerifyOptions,
};
use std::path::Path;

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

enum ResolvedKeySource<'a> {
    File(&'a Path),
    Text(&'a str),
    Bytes(Vec<u8>),
}

impl<'a> ResolvedKeySource<'a> {
    fn as_core(&'a self) -> SignatureKeySource<'a> {
        match self {
            Self::File(path) => SignatureKeySource::File(path),
            Self::Text(text) => SignatureKeySource::Text(text),
            Self::Bytes(bytes) => SignatureKeySource::Bytes(bytes),
        }
    }
}

enum ResolvedSignatureSource<'a> {
    File(&'a Path),
    Bytes(Vec<u8>),
}

impl<'a> ResolvedSignatureSource<'a> {
    fn as_core(&'a self) -> SignatureBytesSource<'a> {
        match self {
            Self::File(path) => SignatureBytesSource::File(path),
            Self::Bytes(bytes) => SignatureBytesSource::Bytes(bytes),
        }
    }
}

fn decode_hex_bytes(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) {
        return Err("hex string must have even length".to_owned());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte =
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "invalid hex string".to_owned())?;
        out.push(byte);
    }
    Ok(out)
}

fn parse_explicit_hex_bytes(raw: &str) -> Result<Option<Vec<u8>>, String> {
    let raw = raw.trim();
    if let Some(hex) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        if hex.is_empty() || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("invalid hex string".to_owned());
        }
        return decode_hex_bytes(hex).map(Some);
    }

    let has_separator = raw.contains([' ', '\t', ':', '-', '_']);
    if !has_separator {
        return Ok(None);
    }

    let cleaned: String = raw
        .chars()
        .filter(|c| !matches!(c, ' ' | '\t' | ':' | '-' | '_'))
        .collect();
    if cleaned.is_empty() || !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Ok(None);
    }
    decode_hex_bytes(&cleaned).map(Some)
}

fn looks_like_inline_pem(raw: &str) -> bool {
    let raw = raw.trim();
    raw.starts_with("-----BEGIN ") || raw.contains(['\n', '\r'])
}

fn looks_like_asn_key_bytes(raw: &str) -> bool {
    let raw = raw.trim();
    let upper = raw.to_ascii_uppercase();
    let known_prefix = ["FF49", "FF4B", "FF59", "FF5B"]
        .iter()
        .any(|prefix| upper.starts_with(prefix));
    known_prefix && raw.len().is_multiple_of(2) && raw.chars().all(|c| c.is_ascii_hexdigit())
}

fn resolve_key_source(raw: &str) -> Result<ResolvedKeySource<'_>, CliError> {
    if looks_like_inline_pem(raw) {
        return Ok(ResolvedKeySource::Text(raw));
    }
    if looks_like_asn_key_bytes(raw) {
        let bytes = decode_hex_bytes(raw.trim())
            .map_err(|e| CliError::Other(format!("signature key info: {e}")))?;
        return Ok(ResolvedKeySource::Bytes(bytes));
    }
    Ok(ResolvedKeySource::File(Path::new(raw)))
}

fn resolve_signature_source(raw: &str) -> Result<ResolvedSignatureSource<'_>, CliError> {
    if let Some(bytes) = parse_explicit_hex_bytes(raw)
        .map_err(|e| CliError::Other(format!("signature info: {e}")))?
    {
        return Ok(ResolvedSignatureSource::Bytes(bytes));
    }
    Ok(ResolvedSignatureSource::File(Path::new(raw)))
}

pub(super) fn apply_data_processing(
    hexfile: &mut crate::HexFile,
    params: &DataProcessingParams,
) -> Result<Option<Vec<u8>>, CliError> {
    let Some(method) = map_data_processing_method(params.method) else {
        return Ok(None);
    };
    let key_source = resolve_key_source(&params.key_info)
        .map_err(|e| CliError::Other(format!("/DP{}: {e}", params.method)))?;
    let options = SignatureSignOptions {
        method,
        key_source: key_source.as_core(),
        placement: params
            .placement
            .as_ref()
            .map(map_checksum_target)
            .transpose()
            .map_err(|e| CliError::Other(format!("/DP{}: {e}", params.method)))?,
    };
    let signature = hexfile
        .sign(&options)
        .map_err(|e| CliError::Other(format!("/DP{}: {e}", params.method)))?;
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
    let key_source = resolve_key_source(&params.key_info)
        .map_err(|e| CliError::Other(format!("/SV{}: {e}", params.method)))?;
    let signature_source = resolve_signature_source(&params.signature_info)
        .map_err(|e| CliError::Other(format!("/SV{}: {e}", params.method)))?;
    let options = SignatureVerifyOptions {
        method,
        key_source: key_source.as_core(),
        signature_source: signature_source.as_core(),
    };
    hexfile
        .verify_signature(&options)
        .map_err(|e| CliError::Other(format!("/SV{}: {e}", params.method)))?;
    Ok(())
}

fn map_checksum_target(target: &ChecksumTarget) -> Result<SignaturePlacement, String> {
    match target {
        ChecksumTarget::None => Err("missing /DP placement target".to_owned()),
        ChecksumTarget::Address(addr) => Ok(SignaturePlacement::Address(*addr)),
        ChecksumTarget::Append => Ok(SignaturePlacement::Append),
        ChecksumTarget::Begin => Ok(SignaturePlacement::Begin),
        ChecksumTarget::Prepend => Ok(SignaturePlacement::Prepend),
        ChecksumTarget::OverwriteEnd => Ok(SignaturePlacement::OverwriteEnd),
        ChecksumTarget::File(_) => Err("file target is not valid for /DP placement".to_owned()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ResolvedKeySource, ResolvedSignatureSource, parse_explicit_hex_bytes, resolve_key_source,
        resolve_signature_source,
    };

    #[test]
    fn test_resolve_key_source_defaults_bare_tokens_to_file() {
        let source = resolve_key_source("mykey").unwrap();
        assert!(
            matches!(source, ResolvedKeySource::File(path) if path == std::path::Path::new("mykey"))
        );
    }

    #[test]
    fn test_resolve_key_source_windows_absolute_path_is_file() {
        let source = resolve_key_source(r"C:\temp\key.pem").unwrap();
        assert!(
            matches!(source, ResolvedKeySource::File(path) if path == std::path::Path::new(r"C:\temp\key.pem"))
        );
    }

    #[test]
    fn test_resolve_key_source_pem_text_is_inline() {
        let source =
            resolve_key_source("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----")
                .unwrap();
        assert!(matches!(source, ResolvedKeySource::Text(_)));
    }

    #[test]
    fn test_resolve_key_source_compat_asn_bytes_are_inline() {
        let source = resolve_key_source("FF490001").unwrap();
        assert!(
            matches!(source, ResolvedKeySource::Bytes(bytes) if bytes == vec![0xFF, 0x49, 0x00, 0x01])
        );
    }

    #[test]
    fn test_parse_explicit_hex_bytes_accepts_prefixed_and_structured_forms() {
        assert_eq!(
            parse_explicit_hex_bytes("0xA1B2").unwrap(),
            Some(vec![0xA1, 0xB2])
        );
        assert_eq!(
            parse_explicit_hex_bytes("A1:B2 C3-D4").unwrap(),
            Some(vec![0xA1, 0xB2, 0xC3, 0xD4])
        );
    }

    #[test]
    fn test_resolve_signature_source_defaults_bare_tokens_to_file() {
        let source = resolve_signature_source("deadbeef").unwrap();
        assert!(
            matches!(source, ResolvedSignatureSource::File(path) if path == std::path::Path::new("deadbeef"))
        );
    }

    #[test]
    fn test_resolve_signature_source_windows_absolute_path_is_file() {
        let source = resolve_signature_source(r"D:\temp\sig.bin").unwrap();
        assert!(
            matches!(source, ResolvedSignatureSource::File(path) if path == std::path::Path::new(r"D:\temp\sig.bin"))
        );
    }

    #[test]
    fn test_resolve_signature_source_explicit_hex_is_inline() {
        let source = resolve_signature_source("0xA1B2").unwrap();
        assert!(
            matches!(source, ResolvedSignatureSource::Bytes(bytes) if bytes == vec![0xA1, 0xB2])
        );
    }
}

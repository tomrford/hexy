use super::error::CliError;
use super::types::{DataProcessingParams, SignatureVerifyParams};
use hexy_core::{
    SignatureBytesSource, SignatureKeySource, SignatureMethod, SignatureSignOptions,
    SignatureVerifyOptions,
};
use std::path::PathBuf;

/// `/SV4`..`/SV11`: odd methods include the address/length metadata.
fn verify_method(method: u8) -> Option<SignatureMethod> {
    let with_metadata = method % 2 == 1;
    Some(match method {
        4 | 5 => SignatureMethod::RsaPkcs1v15Sha256 { with_metadata },
        6 | 7 => SignatureMethod::RsaPssSha256 { with_metadata },
        8 | 9 => SignatureMethod::Ed25519Ph { with_metadata },
        10 | 11 => SignatureMethod::Ed25519Sha512Data { with_metadata },
        _ => return None,
    })
}

/// The `/DP` signing method; each pairs with one `/SV` verification method.
pub(super) fn data_processing_method(method: u8) -> Result<SignatureMethod, CliError> {
    let verify = match method {
        32 | 33 => method - 28,
        38 | 39 => method - 32,
        46..=49 => method - 38,
        _ => 0,
    };
    verify_method(verify).ok_or_else(|| {
        CliError::Unsupported(format!(
            "data processing (/DP{method}) is not supported yet"
        ))
    })
}

pub(super) fn signature_verify_method(method: u8) -> Result<SignatureMethod, CliError> {
    verify_method(method).ok_or_else(|| {
        CliError::Unsupported(format!(
            "signature verification (/SV{method}) is not supported yet"
        ))
    })
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

fn resolve_key_source(raw: &str) -> Result<SignatureKeySource, CliError> {
    if looks_like_inline_pem(raw) {
        return Ok(SignatureKeySource::Text(raw.to_owned()));
    }
    if looks_like_asn_key_bytes(raw) {
        let bytes = decode_hex_bytes(raw.trim())
            .map_err(|e| CliError::Other(format!("signature key info: {e}")))?;
        return Ok(SignatureKeySource::Bytes(bytes));
    }
    Ok(SignatureKeySource::File(PathBuf::from(raw)))
}

fn resolve_signature_source(raw: &str) -> Result<SignatureBytesSource, CliError> {
    if let Some(bytes) = parse_explicit_hex_bytes(raw)
        .map_err(|e| CliError::Other(format!("signature info: {e}")))?
    {
        return Ok(SignatureBytesSource::Bytes(bytes));
    }
    Ok(SignatureBytesSource::File(PathBuf::from(raw)))
}

/// Core signing options for a supported `/DP` method.
pub(super) fn sign_options(
    params: &DataProcessingParams,
) -> Result<SignatureSignOptions, CliError> {
    let flag_error = |e: String| CliError::Other(format!("/DP{}: {e}", params.method));
    Ok(SignatureSignOptions {
        method: data_processing_method(params.method)?,
        key_source: resolve_key_source(&params.key_info).map_err(|e| flag_error(e.to_string()))?,
        placement: params.placement,
    })
}

/// Core verification options for a supported `/SV` method.
pub(super) fn verify_options(
    params: &SignatureVerifyParams,
) -> Result<SignatureVerifyOptions, CliError> {
    let flag_error = |e: String| CliError::Other(format!("/SV{}: {e}", params.method));
    Ok(SignatureVerifyOptions {
        method: signature_verify_method(params.method)?,
        key_source: resolve_key_source(&params.key_info).map_err(|e| flag_error(e.to_string()))?,
        signature_source: resolve_signature_source(&params.signature_info)
            .map_err(|e| flag_error(e.to_string()))?,
    })
}

#[cfg(test)]
mod tests {
    use super::{parse_explicit_hex_bytes, resolve_key_source, resolve_signature_source};
    use hexy_core::{SignatureBytesSource, SignatureKeySource};

    #[test]
    fn test_resolve_key_source_defaults_bare_tokens_to_file() {
        let source = resolve_key_source("mykey").unwrap();
        assert!(
            matches!(source, SignatureKeySource::File(path) if path == std::path::Path::new("mykey"))
        );
    }

    #[test]
    fn test_resolve_key_source_windows_absolute_path_is_file() {
        let source = resolve_key_source(r"C:\temp\key.pem").unwrap();
        assert!(
            matches!(source, SignatureKeySource::File(path) if path == std::path::Path::new(r"C:\temp\key.pem"))
        );
    }

    #[test]
    fn test_resolve_key_source_pem_text_is_inline() {
        let source =
            resolve_key_source("-----BEGIN PUBLIC KEY-----\nabc\n-----END PUBLIC KEY-----")
                .unwrap();
        assert!(matches!(source, SignatureKeySource::Text(_)));
    }

    #[test]
    fn test_resolve_key_source_compat_asn_bytes_are_inline() {
        let source = resolve_key_source("FF490001").unwrap();
        assert!(
            matches!(source, SignatureKeySource::Bytes(bytes) if bytes == vec![0xFF, 0x49, 0x00, 0x01])
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
            matches!(source, SignatureBytesSource::File(path) if path == std::path::Path::new("deadbeef"))
        );
    }

    #[test]
    fn test_resolve_signature_source_windows_absolute_path_is_file() {
        let source = resolve_signature_source(r"D:\temp\sig.bin").unwrap();
        assert!(
            matches!(source, SignatureBytesSource::File(path) if path == std::path::Path::new(r"D:\temp\sig.bin"))
        );
    }

    #[test]
    fn test_resolve_signature_source_explicit_hex_is_inline() {
        let source = resolve_signature_source("0xA1B2").unwrap();
        assert!(matches!(source, SignatureBytesSource::Bytes(bytes) if bytes == vec![0xA1, 0xB2]));
    }
}

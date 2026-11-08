//! `/DP` and `/SV`: HexView's method numbers, and their parameters resolved into core
//! data processing and verification stages.
//!
//! File references resolve against the input file's folder, as HexView resolves them;
//! without an input file they resolve against the working directory.

mod params;

use std::path::{Path, PathBuf};

use crate::{
    DataProcessing, DataProcessingStage, SignatureMethod, SignatureScheme, VerifyStage,
    decode_hex_text,
};

use super::error::CliError;
use super::ini::load_ini;
use super::io::ReadProvider;

pub(super) use params::{
    DataProcessingParams, ParamSource, SignatureVerifyParams, parse_data_processing,
    parse_signature_verify,
};

/// HexView 1.15.2 numbers its `/DP` methods 0 to 60 and its `/SV` methods 0 to 11.
const DP_METHODS: u8 = 61;
/// The `/DP` method that creates the signature each `/SV` method verifies.
const SV_SIGNATURES: [u8; 12] = [28, 9, 8, 10, 32, 33, 38, 39, 46, 47, 48, 49];

/// A `/DP` method hexy implements, with the file HexView writes its output to when
/// param4 is absent.
fn dp_method(number: u8) -> Option<(SignatureMethod, &'static str)> {
    use SignatureScheme::{Ed25519Ph, Ed25519Sha512, RsaPkcs1v15Sha256, RsaPssSha256};
    let (scheme, with_metadata, default_output) = match number {
        32 => (RsaPkcs1v15Sha256, false, "SignD_SHA256.RSA"),
        33 => (RsaPkcs1v15Sha256, true, "SignDAL_SHA256.RSA"),
        38 => (RsaPssSha256, false, "SignD_PSS_SHA256.RSA"),
        39 => (RsaPssSha256, true, "SignDAL_PSS_SHA256.RSA"),
        46 => (Ed25519Ph, false, "SignD_ED25519.ECC"),
        47 => (Ed25519Ph, true, "SignDAL_ED25519.ECC"),
        48 => (Ed25519Sha512, false, "SignD_SHA512_ED25519PH.ECC"),
        49 => (Ed25519Sha512, true, "SignDAL_SHA512_ED25519PH.ECC"),
        _ => return None,
    };
    Some((
        SignatureMethod {
            scheme,
            with_metadata,
        },
        default_output,
    ))
}

fn sv_method(number: u8) -> Option<SignatureMethod> {
    let (method, _) = dp_method(*SV_SIGNATURES.get(usize::from(number))?)?;
    Some(method)
}

/// Upfront checks: HexView methods hexy does not implement are rejected before any
/// output is written. Unknown method numbers fail when their stage runs, as in HexView.
pub(super) fn validate_data_processing(
    params: &DataProcessingParams,
    silent: bool,
) -> Result<(), CliError> {
    let flag = format!("/DP{}", params.method);
    let Some((method, _)) = dp_method(params.method) else {
        if params.method < DP_METHODS {
            return Err(CliError::Unsupported(format!(
                "data processing ({flag}) is not supported yet"
            )));
        }
        return Ok(());
    };
    if method.scheme == SignatureScheme::RsaPssSha256 && params.options.salt.is_some() {
        return Err(CliError::Unsupported(format!(
            "{flag}: #SALT is not supported yet"
        )));
    }
    for name in params.options.names() {
        if !silent {
            eprintln!("Warning: {flag} ignores {name}");
        }
    }
    Ok(())
}

pub(super) fn validate_signature_verify(params: &SignatureVerifyParams) -> Result<(), CliError> {
    if sv_method(params.method).is_none() && usize::from(params.method) < SV_SIGNATURES.len() {
        return Err(CliError::Unsupported(format!(
            "signature verification (/SV{}) is not supported yet",
            params.method
        )));
    }
    Ok(())
}

/// The core stage for `/DP`, read when the stage runs.
pub(super) fn data_processing_stage(
    params: &DataProcessingParams,
    dir: &Path,
    provider: &impl ReadProvider,
) -> Result<DataProcessingStage, String> {
    let (method, _) = dp_method(params.method).ok_or("unknown data processing method")?;
    let key = method
        .scheme
        .signing_key(&param_content(&params.source, dir, provider)?)
        .map_err(|e| e.to_string())?;
    Ok(DataProcessingStage {
        operation: DataProcessing::Sign { method, key },
        placement: params.placement,
    })
}

/// The file `/DP` writes its output to: param4, or HexView's default name.
pub(super) fn data_processing_output(params: &DataProcessingParams, dir: &Path) -> Option<PathBuf> {
    let (_, default_output) = dp_method(params.method)?;
    Some(dir.join(params.param4.as_deref().unwrap_or(default_output)))
}

/// The core stage for `/SV`, read when the stage runs so that the signature can be the
/// output file of a `/DP` in the same command.
pub(super) fn verify_stage(
    params: &SignatureVerifyParams,
    dir: &Path,
    provider: &impl ReadProvider,
) -> Result<VerifyStage, String> {
    let method = sv_method(params.method).ok_or("unknown signature verification method")?;
    let key = method
        .scheme
        .verifying_key(&param_content(&params.key, dir, provider)?)
        .map_err(|e| e.to_string())?;
    let signature = params
        .signature
        .as_deref()
        .ok_or("missing !signatureinfo")?;
    Ok(VerifyStage {
        method,
        key,
        signature: signature_bytes(signature, dir, provider)?,
    })
}

/// The content of param1: inline text, an INI value, or a file's bytes.
fn param_content(
    source: &ParamSource,
    dir: &Path,
    provider: &impl ReadProvider,
) -> Result<Vec<u8>, String> {
    match source {
        ParamSource::Inline(text) => Ok(text.clone().into_bytes()),
        ParamSource::Ini { file, section, key } => {
            let path = dir.join(file);
            let ini = load_ini(&path, provider, Some(section))
                .map_err(|e| format!("{}: {e}", path.display()))?;
            ini.get(&key.to_ascii_lowercase())
                .map(|value| value.clone().into_bytes())
                .ok_or_else(|| format!("{}: no {key} in [{section}]", path.display()))
        }
        ParamSource::File(file) => {
            let path = dir.join(file);
            provider
                .read_bytes(&path)
                .map_err(|e| format!("{}: {e}", path.display()))
        }
    }
}

/// Signature bytes from inline hex text or a file of hex text, such as a `/DP` output
/// file.
fn signature_bytes(
    signature: &str,
    dir: &Path,
    provider: &impl ReadProvider,
) -> Result<Vec<u8>, String> {
    if let Some(bytes) = decode_hex_text(signature.as_bytes()) {
        return Ok(bytes);
    }
    let path = dir.join(signature);
    let content = provider
        .read_bytes(&path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    decode_hex_text(&content).ok_or_else(|| format!("{}: not hex text", path.display()))
}

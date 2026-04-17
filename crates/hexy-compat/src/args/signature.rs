use super::error::CliError;
use super::types::{ChecksumTarget, DataProcessingParams, SignatureVerifyParams};
use hexy_core::{
    SignatureBytesSource, SignatureKeySource, SignatureMethod, SignaturePlacement,
    SignatureSignOptions, SignatureVerifyOptions,
};

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
    let options = SignatureSignOptions {
        method,
        key_source: SignatureKeySource::Auto(&params.key_info),
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
    let options = SignatureVerifyOptions {
        method,
        key_source: SignatureKeySource::Auto(&params.key_info),
        signature_source: SignatureBytesSource::Auto(&params.signature_info),
    };
    hexfile
        .verify_signature(&options)
        .map_err(|e| CliError::Other(format!("/SV{}: {e}", params.method)))?;
    Ok(())
}

fn map_checksum_target(target: &ChecksumTarget) -> Result<SignaturePlacement, String> {
    match target {
        ChecksumTarget::Address(addr) => Ok(SignaturePlacement::Address(*addr)),
        ChecksumTarget::Append => Ok(SignaturePlacement::Append),
        ChecksumTarget::Begin => Ok(SignaturePlacement::Begin),
        ChecksumTarget::Prepend => Ok(SignaturePlacement::Prepend),
        ChecksumTarget::OverwriteEnd => Ok(SignaturePlacement::OverwriteEnd),
        ChecksumTarget::File(_) => Err("file target is not valid for /DP placement".to_string()),
    }
}

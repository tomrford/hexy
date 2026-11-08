//! `/DP` and `/SV`: HexView's method numbers, and their parameters resolved into core
//! data processing and verification stages.
//!
//! File references resolve against the input file's folder, as HexView resolves them;
//! without an input file they resolve against the working directory.

mod params;

use std::path::{Path, PathBuf};

use crate::{
    AesGcm, AesKey, AesMode, AesPadding, DataProcessing, DataProcessingStage, GcmTag, MacAlgorithm,
    MacKey, MacMethod, ProcessingError, SignatureMethod, SignatureScheme, VerifyStage,
    decode_hex_text,
};

use super::error::CliError;
use super::ini::load_ini;
use super::io::ReadProvider;

pub(super) use params::{
    DataInput, DataProcessingParams, ParamSource, SignatureVerifyParams, parse_data_processing,
    parse_signature_verify,
};

/// HexView 1.15.2 numbers its `/DP` methods 0 to 60 and its `/SV` methods 0 to 11.
const DP_METHODS: u8 = 61;
/// The `/DP` method that creates the signature each `/SV` method verifies.
const SV_SIGNATURES: [u8; 12] = [28, 9, 8, 10, 32, 33, 38, 39, 46, 47, 48, 49];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cipher {
    Ecb,
    Cbc,
    Ctr,
}

/// The file HexView writes a method's output to when param4 is absent, and whether the
/// text ends with CRLF.
#[derive(Debug, Clone, Copy)]
struct OutputFile {
    name: &'static str,
    crlf: bool,
}

/// A `/DP` method hexy implements.
#[derive(Debug, Clone, Copy)]
enum Method {
    /// `/DP0` does nothing.
    None,
    Xor,
    /// param4 is the padding and `#IV` the IV.
    Aes {
        cipher: Cipher,
        decrypt: bool,
    },
    /// `#IV` is the nonce, `#AUTH` the additional data and `#TAG` the tag: an output file
    /// when encrypting, and an input when decrypting.
    Gcm {
        decrypt: bool,
    },
    Mac(MacMethod, OutputFile),
    Sign(SignatureMethod, OutputFile),
}

fn dp_method(number: u8) -> Option<Method> {
    use MacAlgorithm::{CmacAes128, HmacMd5, HmacRipemd160, HmacSha1, HmacSha256};
    use SignatureScheme::{Ed25519Ph, Ed25519Sha512, RsaPkcs1v15Sha256, RsaPssSha256};
    let mac = |algorithm, with_metadata, name, crlf| {
        let method = MacMethod {
            algorithm,
            with_metadata,
        };
        Method::Mac(method, OutputFile { name, crlf })
    };
    let sign = |scheme, with_metadata, name| {
        let method = SignatureMethod {
            scheme,
            with_metadata,
        };
        Method::Sign(method, OutputFile { name, crlf: false })
    };
    let aes = |cipher, decrypt| Method::Aes { cipher, decrypt };
    Some(match number {
        0 => Method::None,
        1 => Method::Xor,
        2 => aes(Cipher::Ecb, false),
        3 => aes(Cipher::Ecb, true),
        4 => mac(HmacSha1, false, "SignD_SHA1.txt", true),
        5 => mac(HmacSha1, true, "SignDAL_SHA1.txt", true),
        6 => mac(HmacRipemd160, false, "SignD_Rmd160.txt", true),
        7 => mac(HmacRipemd160, true, "SignDAL_Rmd160.txt", true),
        11 => aes(Cipher::Cbc, false),
        12 => aes(Cipher::Cbc, true),
        13 => mac(HmacMd5, false, "SignD_MD5.txt", false),
        14 => mac(HmacMd5, true, "SignDAL_MD5.txt", false),
        30 => mac(HmacSha256, false, "SignD_SHA256.txt", false),
        31 => mac(HmacSha256, true, "SignDAL_SHA256.txt", false),
        32 => sign(RsaPkcs1v15Sha256, false, "SignD_SHA256.RSA"),
        33 => sign(RsaPkcs1v15Sha256, true, "SignDAL_SHA256.RSA"),
        38 => sign(RsaPssSha256, false, "SignD_PSS_SHA256.RSA"),
        39 => sign(RsaPssSha256, true, "SignDAL_PSS_SHA256.RSA"),
        44 => mac(CmacAes128, false, "SignD_CmacAes.txt", false),
        45 => mac(CmacAes128, true, "SignDAL_CmacAes.txt", false),
        46 => sign(Ed25519Ph, false, "SignD_ED25519.ECC"),
        47 => sign(Ed25519Ph, true, "SignDAL_ED25519.ECC"),
        48 => sign(Ed25519Sha512, false, "SignD_SHA512_ED25519PH.ECC"),
        49 => sign(Ed25519Sha512, true, "SignDAL_SHA512_ED25519PH.ECC"),
        53 => aes(Cipher::Ctr, false),
        54 => aes(Cipher::Ctr, true),
        55 => Method::Gcm { decrypt: false },
        56 => Method::Gcm { decrypt: true },
        _ => return None,
    })
}

fn sv_method(number: u8) -> Option<SignatureMethod> {
    match dp_method(*SV_SIGNATURES.get(usize::from(number))?)? {
        Method::Sign(method, _) => Some(method),
        _ => None,
    }
}

/// Upfront checks: HexView methods and options hexy does not implement are rejected
/// before any output is written, and options a method ignores are reported. Unknown
/// method numbers fail when their stage runs, as in HexView.
pub(super) fn validate_data_processing(
    params: &DataProcessingParams,
    silent: bool,
) -> Result<(), CliError> {
    let flag = format!("/DP{}", params.method);
    let unsupported = |what: &str| Err(CliError::Unsupported(format!("{flag}: {what}")));
    let options = &params.options;
    let Some(method) = dp_method(params.method) else {
        if params.method < DP_METHODS {
            return unsupported("this data processing method is not supported yet");
        }
        return Ok(());
    };
    let mut used = Vec::new();
    match method {
        Method::Sign(method, _) => {
            if method.scheme == SignatureScheme::RsaPssSha256 && options.salt.is_some() {
                return unsupported("#SALT is not supported yet");
            }
        }
        Method::Aes { cipher, .. } => {
            if cipher != Cipher::Ecb {
                used.push("#IV");
            }
        }
        Method::Gcm { decrypt } => {
            used.extend(["#IV", "#AUTH"]);
            if matches!(options.auth, Some(DataInput::Image(_))) {
                return unsupported(
                    "#AUTH=@ is not supported: HexView leaves that data out of the tag",
                );
            }
            let tag_file = matches!(options.tag, Some(DataInput::File(_)));
            if decrypt {
                if tag_file {
                    return unsupported("#TAG files are not supported: HexView does not read them");
                }
                used.push("#TAG");
            } else {
                if nonce(params).is_none() {
                    return unsupported(
                        "#IV is required: without it HexView drops 16 bytes of ciphertext",
                    );
                }
                if tag_file {
                    used.push("#TAG");
                }
            }
        }
        Method::None | Method::Xor | Method::Mac(..) => {}
    }
    for name in options.names().filter(|name| !used.contains(name)) {
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

/// The core stage for `/DP`, read when the stage runs; `/DP0` has none.
pub(super) fn data_processing_stage(
    params: &DataProcessingParams,
    dir: &Path,
    provider: &impl ReadProvider,
) -> Result<Option<DataProcessingStage>, String> {
    let method = dp_method(params.method).ok_or("unknown data processing method")?;
    let key = || param_content(&params.source, dir, provider);
    let error = |e: ProcessingError| e.to_string();
    let operation = match method {
        Method::None => return Ok(None),
        // HexView inverts the data when the key is missing or is not hex text.
        Method::Xor => DataProcessing::Xor {
            key: key()
                .ok()
                .and_then(|content| decode_hex_text(&content))
                .unwrap_or_default(),
        },
        Method::Aes { cipher, decrypt } => {
            let key = AesKey::from_key_file(&key()?).map_err(error)?;
            let iv = params
                .options
                .iv
                .as_deref()
                .filter(|iv| !iv.is_empty())
                .map(|iv| {
                    // HexView pads a short IV with zero bytes and cuts a long one.
                    let mut block = [0; 16];
                    let len = iv.len().min(16);
                    block[..len].copy_from_slice(&iv[..len]);
                    block
                });
            let mode = match cipher {
                Cipher::Ecb => AesMode::Ecb,
                Cipher::Cbc => AesMode::Cbc { iv },
                Cipher::Ctr => AesMode::Ctr { iv },
            };
            let padding = params.param4.as_deref().and_then(padding);
            if decrypt {
                DataProcessing::Decrypt { key, mode, padding }
            } else {
                DataProcessing::Encrypt { key, mode, padding }
            }
        }
        Method::Gcm { decrypt } => {
            let gcm = AesGcm {
                key: AesKey::from_key_file(&key()?).map_err(error)?,
                nonce: nonce(params).ok_or("#IV is required")?.to_vec(),
                aad: match &params.options.auth {
                    Some(DataInput::Hex(bytes)) => bytes.clone(),
                    Some(DataInput::File(file)) => binary_file(&dir.join(file), provider),
                    Some(DataInput::Image(_)) | None => Vec::new(),
                },
            };
            if decrypt {
                // Without a tag, HexView decrypts the data and then fails the check.
                let tag = match &params.options.tag {
                    Some(DataInput::Image(range)) => GcmTag::Image(*range),
                    Some(DataInput::Hex(bytes)) => GcmTag::Bytes(bytes.clone()),
                    Some(DataInput::File(_)) | None => GcmTag::Bytes(Vec::new()),
                };
                DataProcessing::DecryptGcm { gcm, tag }
            } else {
                DataProcessing::EncryptGcm(gcm)
            }
        }
        Method::Mac(method, _) => DataProcessing::Mac {
            method,
            key: MacKey::from_key_file(&key()?).map_err(error)?,
        },
        Method::Sign(method, _) => DataProcessing::Sign {
            method,
            key: method.scheme.signing_key(&key()?).map_err(error)?,
        },
    };
    Ok(Some(DataProcessingStage {
        operation,
        placement: params.placement,
    }))
}

/// The AES-GCM nonce: `#IV`, of which HexView uses at most 16 bytes.
fn nonce(params: &DataProcessingParams) -> Option<&[u8]> {
    let iv = params.options.iv.as_deref().filter(|iv| !iv.is_empty())?;
    Some(&iv[..iv.len().min(16)])
}

/// HexView reads the padding name from its first four letters, ignoring case; any
/// other param4 means no padding.
fn padding(name: &str) -> Option<AesPadding> {
    match name.get(..4)?.to_ascii_uppercase().as_str() {
        "PKCS" => Some(AesPadding::Pkcs7),
        "ANSI" => Some(AesPadding::AnsiX923),
        "RFC1" => Some(AesPadding::Rfc1321),
        _ => None,
    }
}

/// A file's bytes when they are binary (hold a byte from 0x80); HexView ignores
/// missing files and files of text as `#AUTH` data.
fn binary_file(path: &Path, provider: &impl ReadProvider) -> Vec<u8> {
    provider
        .read_bytes(path)
        .ok()
        .filter(|content| content.iter().any(|&b| b >= 0x80))
        .unwrap_or_default()
}

/// The file `/DP` writes its output to, and whether the text ends with CRLF: param4 or
/// HexView's default name for signatures and MACs, and the `#TAG` file for AES-GCM
/// encryption.
pub(super) fn data_processing_output(
    params: &DataProcessingParams,
    dir: &Path,
) -> Option<(PathBuf, bool)> {
    let (name, crlf) = match dp_method(params.method)? {
        Method::Mac(_, output) | Method::Sign(_, output) => (
            Path::new(params.param4.as_deref().unwrap_or(output.name)),
            output.crlf,
        ),
        Method::Gcm { decrypt: false } => match &params.options.tag {
            Some(DataInput::File(file)) => (file.as_path(), false),
            _ => return None,
        },
        _ => return None,
    };
    Some((dir.join(name), crlf))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// HexView 1.15.2 matches the first four letters of the padding name, ignoring case.
    #[test]
    fn test_padding_names() {
        assert_eq!(padding("PKCS5"), Some(AesPadding::Pkcs7));
        assert_eq!(padding("ansix923"), Some(AesPadding::AnsiX923));
        assert_eq!(padding("Rfc1"), Some(AesPadding::Rfc1321));
        assert_eq!(padding("RFC"), None);
        assert_eq!(padding("FOO"), None);
    }
}

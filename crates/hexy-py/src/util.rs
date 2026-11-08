use hexy_core::{
    AddressRange, AesGcm, AesKey, AesMode, AesPadding, Compression, DataProcessing, GcmTag,
    IntelHexMode, Lzss, LzssAes, MacAlgorithm, MacKey, MacMethod, MergeMode, Placement, RsaPadding,
    RsaPrivateKey, RsaPublicKey, SRecordType, SignatureMethod, SignatureScheme, SwapMode,
    parse_compat_ranges,
};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pub(crate) fn value_error(err: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(err.to_string())
}

pub(crate) fn parse_range_arg(obj: &Bound<'_, PyAny>) -> PyResult<AddressRange> {
    if let Ok(text) = obj.extract::<String>() {
        return parse_single_range_text(&text);
    }
    Err(PyTypeError::new_err("expected range string"))
}

pub(crate) fn parse_ranges_arg(obj: &Bound<'_, PyAny>) -> PyResult<Vec<AddressRange>> {
    if obj.extract::<String>().is_ok() {
        return Err(PyTypeError::new_err(
            "expected a list of range strings, not a single range string",
        ));
    }
    let items = obj
        .try_iter()
        .map_err(|_| PyTypeError::new_err("expected a list of range strings"))?;
    items
        .map(|item| {
            let item = item?;
            parse_range_arg(&item)
        })
        .collect()
}

fn parse_single_range_text(text: &str) -> PyResult<AddressRange> {
    let ranges = parse_compat_ranges(text).map_err(value_error)?;
    let count = ranges.len();
    if count == 1 {
        Ok(ranges[0])
    } else {
        Err(PyValueError::new_err(format!(
            "expected a single range, got {count} ranges"
        )))
    }
}

pub(crate) fn parse_fill_pattern(pattern: Option<&[u8]>) -> PyResult<Vec<u8>> {
    let pattern = pattern.unwrap_or(&[0xFF]);
    if pattern.is_empty() {
        return Err(PyValueError::new_err("fill pattern cannot be empty"));
    }
    Ok(pattern.to_vec())
}

pub(crate) fn parse_merge_mode(mode: Option<&str>) -> PyResult<MergeMode> {
    match mode.unwrap_or("overwrite").to_ascii_lowercase().as_str() {
        "overwrite" | "opaque" => Ok(MergeMode::Overwrite),
        "preserve" | "transparent" => Ok(MergeMode::Preserve),
        other => Err(PyValueError::new_err(format!(
            "unknown merge mode '{other}', expected 'overwrite' or 'preserve'"
        ))),
    }
}

pub(crate) fn parse_swap_mode(mode: &str) -> PyResult<SwapMode> {
    match mode.to_ascii_lowercase().as_str() {
        "word" | "swapword" => Ok(SwapMode::Word),
        "dword" | "long" | "swaplong" => Ok(SwapMode::DWord),
        other => Err(PyValueError::new_err(format!(
            "unknown swap mode '{other}', expected 'word' or 'dword'"
        ))),
    }
}

pub(crate) fn parse_intel_mode(mode: Option<&str>) -> PyResult<IntelHexMode> {
    match mode.unwrap_or("auto").to_ascii_lowercase().as_str() {
        "auto" => Ok(IntelHexMode::Auto),
        "linear" | "extended_linear" => Ok(IntelHexMode::ExtendedLinear),
        "segment" | "extended_segment" => Ok(IntelHexMode::ExtendedSegment),
        other => Err(PyValueError::new_err(format!(
            "unknown Intel HEX mode '{other}'"
        ))),
    }
}

pub(crate) fn parse_srec_type(record_type: Option<&str>) -> PyResult<Option<SRecordType>> {
    match record_type.map(|v| v.to_ascii_lowercase()) {
        None => Ok(None),
        Some(value) if value == "auto" => Ok(None),
        Some(value) if value == "s1" || value == "1" => Ok(Some(SRecordType::S1)),
        Some(value) if value == "s2" || value == "2" => Ok(Some(SRecordType::S2)),
        Some(value) if value == "s3" || value == "3" => Ok(Some(SRecordType::S3)),
        Some(other) => Err(PyValueError::new_err(format!(
            "unknown S-Record type '{other}'"
        ))),
    }
}

pub(crate) fn py_bytes(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, data).unbind()
}

/// A placement address, or `"append"`, `"begin"`, `"prepend"` or `"overwrite_end"`.
pub(crate) fn parse_placement(obj: &Bound<'_, PyAny>) -> PyResult<Placement> {
    if let Ok(address) = obj.extract::<u32>() {
        return Ok(Placement::Address(address));
    }
    let name: String = obj
        .extract()
        .map_err(|_| PyTypeError::new_err("expected an address or placement name"))?;
    match name.to_ascii_lowercase().as_str() {
        "append" => Ok(Placement::Append),
        "begin" => Ok(Placement::Begin),
        "prepend" => Ok(Placement::Prepend),
        "overwrite_end" => Ok(Placement::OverwriteEnd),
        other => Err(PyValueError::new_err(format!(
            "unknown placement '{other}', expected 'append', 'begin', 'prepend' or 'overwrite_end'"
        ))),
    }
}

/// A signature method from its Python name.
pub(crate) fn parse_signature_method(scheme: &str, metadata: bool) -> PyResult<SignatureMethod> {
    let scheme = match scheme.to_ascii_lowercase().as_str() {
        "rsa-pkcs1v15-md5" => SignatureScheme::RsaPkcs1v15Md5,
        "rsa-pkcs1v15-sha1" => SignatureScheme::RsaPkcs1v15Sha1,
        "rsa-pkcs1v15-ripemd160" => SignatureScheme::RsaPkcs1v15Ripemd160,
        "rsa-pkcs1v15-sha256" => SignatureScheme::RsaPkcs1v15Sha256,
        "rsa-pss-sha256" => SignatureScheme::RsaPssSha256,
        "ecdsa-p256-sha256" => SignatureScheme::EcdsaP256Sha256,
        "ed25519" => SignatureScheme::Ed25519,
        "ed25519ph" => SignatureScheme::Ed25519Ph,
        "ed25519ph-sha512" => SignatureScheme::Ed25519PhSha512,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown signature method '{other}'"
            )));
        }
    };
    Ok(SignatureMethod {
        scheme,
        with_metadata: metadata,
    })
}

/// Key file content as bytes, or key text as str.
pub(crate) fn key_content(obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(bytes) = obj.extract::<&[u8]>() {
        return Ok(bytes.to_vec());
    }
    obj.extract::<String>()
        .map(String::into_bytes)
        .map_err(|_| PyTypeError::new_err("expected key bytes or key text"))
}

/// A MAC operation from its Python name and raw key.
pub(crate) fn mac_operation(method: &str, key: &[u8], metadata: bool) -> PyResult<DataProcessing> {
    let algorithm = match method.to_ascii_lowercase().as_str() {
        "hmac-md5" => MacAlgorithm::HmacMd5,
        "hmac-sha1" => MacAlgorithm::HmacSha1,
        "hmac-ripemd160" => MacAlgorithm::HmacRipemd160,
        "hmac-sha256" => MacAlgorithm::HmacSha256,
        "cmac-aes128" => MacAlgorithm::CmacAes128,
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown MAC method '{other}'"
            )));
        }
    };
    Ok(DataProcessing::Mac {
        method: MacMethod {
            algorithm,
            with_metadata: metadata,
        },
        key: MacKey::new(key).map_err(value_error)?,
    })
}

/// The cipher arguments shared by `encrypt` and `decrypt`.
pub(crate) struct CipherArgs<'a, 'py> {
    pub mode: &'a str,
    pub key: &'a Bound<'py, PyAny>,
    pub iv: Option<&'a [u8]>,
    pub padding: Option<&'a str>,
    pub aad: &'a [u8],
}

/// An AES or RSA encryption or decryption. AES takes the raw key and GCM decryption
/// checks `tag`, bytes or a range of the image; RSA takes key file content or key text.
pub(crate) fn cipher_operation(
    args: CipherArgs<'_, '_>,
    decrypt: bool,
    tag: Option<&Bound<'_, PyAny>>,
) -> PyResult<DataProcessing> {
    let mode = args.mode.to_ascii_lowercase();
    let rsa_padding = match mode.as_str() {
        "rsa-pkcs1v15" => Some(RsaPadding::Pkcs1v15),
        "rsa-oaep-sha1" => Some(RsaPadding::OaepSha1),
        "rsa-oaep-sha256" => Some(RsaPadding::OaepSha256),
        _ => None,
    };
    if let Some(padding) = rsa_padding {
        if args.iv.is_some() || args.padding.is_some() || !args.aad.is_empty() || tag.is_some() {
            return Err(PyValueError::new_err(
                "RSA modes take no iv, padding, aad or tag",
            ));
        }
        let key = key_content(args.key)?;
        return Ok(if decrypt {
            DataProcessing::RsaDecrypt {
                key: RsaPrivateKey::from_key_file(&key).map_err(value_error)?,
                padding,
            }
        } else {
            DataProcessing::RsaEncrypt {
                key: RsaPublicKey::from_key_file(&key).map_err(value_error)?,
                padding,
            }
        });
    }
    let key = args
        .key
        .extract::<&[u8]>()
        .map_err(|_| PyTypeError::new_err("AES keys are bytes"))?;
    let key = AesKey::new(key).map_err(value_error)?;
    if mode == "gcm" {
        let gcm = AesGcm {
            key,
            nonce: args
                .iv
                .ok_or_else(|| PyValueError::new_err("gcm needs an iv"))?
                .to_vec(),
            aad: args.aad.to_vec(),
        };
        if !decrypt {
            return Ok(DataProcessing::EncryptGcm(gcm));
        }
        let tag = tag.ok_or_else(|| PyValueError::new_err("gcm decryption needs a tag"))?;
        let tag = match tag.extract::<Vec<u8>>() {
            Ok(bytes) => GcmTag::Bytes(bytes),
            Err(_) => GcmTag::Image(parse_range_arg(tag)?),
        };
        return Ok(DataProcessing::DecryptGcm { gcm, tag });
    }
    if tag.is_some() {
        return Err(PyValueError::new_err("only gcm takes a tag"));
    }
    let iv = args
        .iv
        .map(|iv| {
            <[u8; 16]>::try_from(iv).map_err(|_| PyValueError::new_err("iv must be 16 bytes"))
        })
        .transpose()?;
    let mode = match (mode.as_str(), iv) {
        ("ecb", None) => AesMode::Ecb,
        ("cbc", iv) => AesMode::Cbc { iv },
        ("ctr", iv) => AesMode::Ctr { iv },
        ("ecb", Some(_)) => return Err(PyValueError::new_err("ecb takes no iv")),
        (other, _) => {
            return Err(PyValueError::new_err(format!(
                "unknown mode '{other}', expected 'ecb', 'cbc', 'ctr', 'gcm', 'rsa-pkcs1v15',                  'rsa-oaep-sha1' or 'rsa-oaep-sha256'"
            )));
        }
    };
    let padding = parse_aes_padding(args.padding)?;
    Ok(if decrypt {
        DataProcessing::Decrypt { key, mode, padding }
    } else {
        DataProcessing::Encrypt { key, mode, padding }
    })
}

fn parse_aes_padding(padding: Option<&str>) -> PyResult<Option<AesPadding>> {
    Ok(match padding.map(str::to_ascii_lowercase).as_deref() {
        None => None,
        Some("pkcs7") => Some(AesPadding::Pkcs7),
        Some("ansix923") => Some(AesPadding::AnsiX923),
        Some("rfc1321") => Some(AesPadding::Rfc1321),
        Some(other) => {
            return Err(PyValueError::new_err(format!(
                "unknown padding '{other}', expected 'pkcs7', 'ansix923' or 'rfc1321'"
            )));
        }
    })
}

/// The arguments shared by `compress` and `decompress`.
pub(crate) struct CompressionArgs<'a> {
    pub method: &'a str,
    pub window_bits: Option<u8>,
    pub length_bits: Option<u8>,
    pub key: Option<&'a [u8]>,
    pub iv: Option<&'a [u8]>,
    pub padding: Option<&'a str>,
}

/// LZSS (with AES-CBC when given a key) or ARLE compression or decompression.
pub(crate) fn compression_operation(
    args: CompressionArgs<'_>,
    decompress: bool,
) -> PyResult<DataProcessing> {
    let lzss = match args.method.to_ascii_lowercase().as_str() {
        "lzss" => match (args.window_bits, args.length_bits) {
            (None, None) => Lzss::default(),
            (Some(window), Some(length)) => Lzss::new(window, length).map_err(value_error)?,
            _ => {
                return Err(PyValueError::new_err(
                    "window_bits and length_bits go together",
                ));
            }
        },
        "arle" => {
            if args.window_bits.is_some() || args.length_bits.is_some() || args.key.is_some() {
                return Err(PyValueError::new_err(
                    "arle takes no window_bits, length_bits or key",
                ));
            }
            let compression = Compression::Arle;
            return Ok(if decompress {
                DataProcessing::Decompress(compression)
            } else {
                DataProcessing::Compress(compression)
            });
        }
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown compression '{other}', expected 'lzss' or 'arle'"
            )));
        }
    };
    let Some(key) = args.key else {
        if args.iv.is_some() || args.padding.is_some() {
            return Err(PyValueError::new_err("iv and padding need a key"));
        }
        let compression = Compression::Lzss(lzss);
        return Ok(if decompress {
            DataProcessing::Decompress(compression)
        } else {
            DataProcessing::Compress(compression)
        });
    };
    let lzss_aes = LzssAes {
        lzss,
        key: AesKey::new(key).map_err(value_error)?,
        iv: match args.iv {
            Some(iv) => <[u8; 16]>::try_from(iv)
                .map_err(|_| PyValueError::new_err("iv must be 16 bytes"))?,
            None => [0; 16],
        },
        padding: parse_aes_padding(args.padding)?,
    };
    Ok(if decompress {
        DataProcessing::DecryptDecompress(lzss_aes)
    } else {
        DataProcessing::CompressEncrypt(lzss_aes)
    })
}

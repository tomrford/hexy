//! `DataProcessing`: HexView's `/DP` operations as values that `HexFile.process_data`
//! and the `Pipeline` stages run.

use hexy_core::{
    AesGcm, AesKey, AesMode, AesPadding, Compression, DataProcessing, GcmTag, Lzss, LzssAes,
    MacAlgorithm, MacKey, MacMethod, RsaPadding, RsaPrivateKey, RsaPublicKey, SignatureMethod,
    SignatureScheme, decode_hex_text,
};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;

use crate::args::{SymmetricKey, choice, key_file, range};
use crate::errors::py_err;

#[pyclass(name = "DataProcessing", module = "hexy", frozen, from_py_object)]
#[derive(Clone)]
pub(crate) struct PyDataProcessing {
    pub(crate) inner: DataProcessing,
}

impl From<DataProcessing> for PyDataProcessing {
    fn from(inner: DataProcessing) -> Self {
        Self { inner }
    }
}

#[pymethods]
impl PyDataProcessing {
    #[staticmethod]
    #[pyo3(signature = (method, key, *, metadata=false, salt=None))]
    fn sign(
        method: &str,
        key: &Bound<'_, PyAny>,
        metadata: bool,
        salt: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let method = signature_method(method, metadata)?;
        let key = method.scheme.signing_key(&key_file(key)?).map_err(py_err)?;
        Ok(DataProcessing::Sign { method, key, salt }.into())
    }

    #[staticmethod]
    #[pyo3(signature = (method, key, *, metadata=false))]
    fn mac(method: &str, key: &Bound<'_, PyAny>, metadata: bool) -> PyResult<Self> {
        let algorithm = choice(
            "MAC method",
            method,
            &[
                ("hmac-md5", MacAlgorithm::HmacMd5),
                ("hmac-sha1", MacAlgorithm::HmacSha1),
                ("hmac-ripemd160", MacAlgorithm::HmacRipemd160),
                ("hmac-sha256", MacAlgorithm::HmacSha256),
                ("cmac-aes128", MacAlgorithm::CmacAes128),
            ],
        )?;
        let key = match SymmetricKey::extract(key)? {
            SymmetricKey::Raw(key) => MacKey::new(&key),
            SymmetricKey::Text(text) => MacKey::from_key_file(text.as_bytes()),
        }
        .map_err(py_err)?;
        let method = MacMethod {
            algorithm,
            with_metadata: metadata,
        };
        Ok(DataProcessing::Mac { method, key }.into())
    }

    #[staticmethod]
    #[pyo3(signature = (key=None))]
    fn xor(key: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let key = match key.map(SymmetricKey::extract).transpose()? {
            None => Vec::new(),
            Some(SymmetricKey::Raw(key)) => key,
            Some(SymmetricKey::Text(text)) => decode_hex_text(text.as_bytes())
                .ok_or_else(|| PyValueError::new_err("the XOR key text is not hex"))?,
        };
        Ok(DataProcessing::Xor { key }.into())
    }

    #[staticmethod]
    #[pyo3(signature = (mode, key, *, iv=None, padding=None, aad=None))]
    fn encrypt(
        mode: &str,
        key: &Bound<'_, PyAny>,
        iv: Option<Vec<u8>>,
        padding: Option<&str>,
        aad: Option<Vec<u8>>,
    ) -> PyResult<Self> {
        let args = CipherArgs {
            mode,
            key,
            iv,
            padding,
            aad,
            tag: None,
        };
        cipher(args, false).map(Into::into)
    }

    #[staticmethod]
    #[pyo3(signature = (mode, key, *, iv=None, padding=None, aad=None, tag=None))]
    fn decrypt(
        mode: &str,
        key: &Bound<'_, PyAny>,
        iv: Option<Vec<u8>>,
        padding: Option<&str>,
        aad: Option<Vec<u8>>,
        tag: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Self> {
        let args = CipherArgs {
            mode,
            key,
            iv,
            padding,
            aad,
            tag,
        };
        cipher(args, true).map(Into::into)
    }

    #[staticmethod]
    #[pyo3(signature = (method="lzss", *, window_bits=None, length_bits=None, key=None, iv=None, padding=None))]
    fn compress(
        method: &str,
        window_bits: Option<u8>,
        length_bits: Option<u8>,
        key: Option<&Bound<'_, PyAny>>,
        iv: Option<Vec<u8>>,
        padding: Option<&str>,
    ) -> PyResult<Self> {
        let args = CompressionArgs {
            method,
            window_bits,
            length_bits,
            key,
            iv,
            padding,
        };
        compression(args, false).map(Into::into)
    }

    #[staticmethod]
    #[pyo3(signature = (method="lzss", *, window_bits=None, length_bits=None, key=None, iv=None, padding=None))]
    fn decompress(
        method: &str,
        window_bits: Option<u8>,
        length_bits: Option<u8>,
        key: Option<&Bound<'_, PyAny>>,
        iv: Option<Vec<u8>>,
        padding: Option<&str>,
    ) -> PyResult<Self> {
        let args = CompressionArgs {
            method,
            window_bits,
            length_bits,
            key,
            iv,
            padding,
        };
        compression(args, true).map(Into::into)
    }
}

pub(crate) fn signature_method(name: &str, metadata: bool) -> PyResult<SignatureMethod> {
    let scheme = choice(
        "signature method",
        name,
        &[
            ("rsa-pkcs1v15-md5", SignatureScheme::RsaPkcs1v15Md5),
            ("rsa-pkcs1v15-sha1", SignatureScheme::RsaPkcs1v15Sha1),
            (
                "rsa-pkcs1v15-ripemd160",
                SignatureScheme::RsaPkcs1v15Ripemd160,
            ),
            ("rsa-pkcs1v15-sha256", SignatureScheme::RsaPkcs1v15Sha256),
            ("rsa-pss-sha256", SignatureScheme::RsaPssSha256),
            ("ecdsa-p256-sha256", SignatureScheme::EcdsaP256Sha256),
            ("ed25519", SignatureScheme::Ed25519),
            ("ed25519ph", SignatureScheme::Ed25519Ph),
            ("ed25519ph-sha512", SignatureScheme::Ed25519PhSha512),
        ],
    )?;
    Ok(SignatureMethod {
        scheme,
        with_metadata: metadata,
    })
}

fn aes_key(key: &Bound<'_, PyAny>) -> PyResult<AesKey> {
    match SymmetricKey::extract(key)? {
        SymmetricKey::Raw(key) => AesKey::new(&key),
        SymmetricKey::Text(text) => AesKey::from_key_file(text.as_bytes()),
    }
    .map_err(py_err)
}

fn iv16(iv: Vec<u8>) -> PyResult<[u8; 16]> {
    <[u8; 16]>::try_from(iv).map_err(|_| PyValueError::new_err("the IV must be 16 bytes"))
}

fn aes_padding(padding: Option<&str>) -> PyResult<Option<AesPadding>> {
    padding
        .map(|name| {
            choice(
                "padding",
                name,
                &[
                    ("pkcs7", AesPadding::Pkcs7),
                    ("ansix923", AesPadding::AnsiX923),
                    ("rfc1321", AesPadding::Rfc1321),
                ],
            )
        })
        .transpose()
}

#[derive(Clone, Copy)]
enum Mode {
    Ecb,
    Cbc,
    Ctr,
    Gcm,
    Rsa(RsaPadding),
}

struct CipherArgs<'a, 'py> {
    mode: &'a str,
    key: &'a Bound<'py, PyAny>,
    iv: Option<Vec<u8>>,
    padding: Option<&'a str>,
    aad: Option<Vec<u8>>,
    /// The GCM tag to check: bytes or a range of the image.
    tag: Option<&'a Bound<'py, PyAny>>,
}

/// An AES or RSA encryption or decryption.
fn cipher(args: CipherArgs<'_, '_>, decrypt: bool) -> PyResult<DataProcessing> {
    let mode = choice(
        "cipher mode",
        args.mode,
        &[
            ("ecb", Mode::Ecb),
            ("cbc", Mode::Cbc),
            ("ctr", Mode::Ctr),
            ("gcm", Mode::Gcm),
            ("rsa-pkcs1v15", Mode::Rsa(RsaPadding::Pkcs1v15)),
            ("rsa-oaep-sha1", Mode::Rsa(RsaPadding::OaepSha1)),
            ("rsa-oaep-sha256", Mode::Rsa(RsaPadding::OaepSha256)),
        ],
    )?;
    let gcm = matches!(mode, Mode::Gcm);
    if !gcm && (args.tag.is_some() || args.aad.is_some()) {
        return Err(PyValueError::new_err("only gcm takes aad or a tag"));
    }
    if args.padding.is_some() && matches!(mode, Mode::Gcm | Mode::Rsa(_)) {
        return Err(PyValueError::new_err(
            "only ecb, cbc and ctr take a padding",
        ));
    }
    let padding = aes_padding(args.padding)?;
    let mode = match mode {
        Mode::Rsa(padding) => {
            if args.iv.is_some() {
                return Err(PyValueError::new_err("RSA takes no iv"));
            }
            let key = key_file(args.key)?;
            return Ok(if decrypt {
                DataProcessing::RsaDecrypt {
                    key: RsaPrivateKey::from_key_file(&key).map_err(py_err)?,
                    padding,
                }
            } else {
                DataProcessing::RsaEncrypt {
                    key: RsaPublicKey::from_key_file(&key).map_err(py_err)?,
                    padding,
                }
            });
        }
        Mode::Gcm => {
            let gcm = AesGcm {
                key: aes_key(args.key)?,
                nonce: args
                    .iv
                    .ok_or_else(|| PyValueError::new_err("gcm needs an iv"))?,
                aad: args.aad.unwrap_or_default(),
            };
            if !decrypt {
                return Ok(DataProcessing::EncryptGcm(gcm));
            }
            let tag = args
                .tag
                .ok_or_else(|| PyValueError::new_err("gcm decryption needs a tag"))?;
            let tag = match tag.extract::<Vec<u8>>() {
                Ok(bytes) => GcmTag::Bytes(bytes),
                Err(_) => GcmTag::Image(range(tag)?),
            };
            return Ok(DataProcessing::DecryptGcm { gcm, tag });
        }
        Mode::Ecb if args.iv.is_some() => {
            return Err(PyValueError::new_err("ecb takes no iv"));
        }
        Mode::Ecb => AesMode::Ecb,
        Mode::Cbc => AesMode::Cbc {
            iv: args.iv.map(iv16).transpose()?,
        },
        Mode::Ctr => AesMode::Ctr {
            iv: args.iv.map(iv16).transpose()?,
        },
    };
    let key = aes_key(args.key)?;
    Ok(if decrypt {
        DataProcessing::Decrypt { key, mode, padding }
    } else {
        DataProcessing::Encrypt { key, mode, padding }
    })
}

struct CompressionArgs<'a, 'py> {
    method: &'a str,
    window_bits: Option<u8>,
    length_bits: Option<u8>,
    key: Option<&'a Bound<'py, PyAny>>,
    iv: Option<Vec<u8>>,
    padding: Option<&'a str>,
}

/// LZSS (with AES-CBC when given a key) or ARLE compression or decompression.
fn compression(args: CompressionArgs<'_, '_>, decompress: bool) -> PyResult<DataProcessing> {
    let wrap = |compression| {
        if decompress {
            DataProcessing::Decompress(compression)
        } else {
            DataProcessing::Compress(compression)
        }
    };
    let lzss = choice(
        "compression",
        args.method,
        &[("lzss", true), ("arle", false)],
    )?;
    if !lzss {
        if args.window_bits.is_some() || args.length_bits.is_some() || args.key.is_some() {
            return Err(PyValueError::new_err(
                "arle takes no window_bits, length_bits or key",
            ));
        }
        return Ok(wrap(Compression::Arle));
    }
    let lzss = match (args.window_bits, args.length_bits) {
        (None, None) => Lzss::default(),
        (Some(window), Some(length)) => Lzss::new(window, length).map_err(py_err)?,
        _ => {
            return Err(PyTypeError::new_err(
                "window_bits and length_bits go together",
            ));
        }
    };
    let Some(key) = args.key else {
        if args.iv.is_some() || args.padding.is_some() {
            return Err(PyValueError::new_err("iv and padding need a key"));
        }
        return Ok(wrap(Compression::Lzss(lzss)));
    };
    let lzss_aes = LzssAes {
        lzss,
        key: aes_key(key)?,
        iv: args.iv.map(iv16).transpose()?.unwrap_or_default(),
        padding: aes_padding(args.padding)?,
    };
    Ok(if decompress {
        DataProcessing::DecryptDecompress(lzss_aes)
    } else {
        DataProcessing::CompressEncrypt(lzss_aes)
    })
}

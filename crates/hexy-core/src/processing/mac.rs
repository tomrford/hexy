use aes::Aes128;
use cmac::Cmac;
use hmac::digest::KeyInit;
use hmac::{Hmac, Mac};
use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::Sha256;

use super::ProcessingError;
use super::keys::MacKey;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacAlgorithm {
    HmacMd5,
    HmacSha1,
    HmacRipemd160,
    HmacSha256,
    /// CMAC with AES-128; it takes only 16-byte keys.
    CmacAes128,
}

/// A MAC algorithm and the payload it covers, as for [`super::SignatureMethod`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacMethod {
    pub algorithm: MacAlgorithm,
    pub with_metadata: bool,
}

/// HexView uses at most the first 64 bytes of an HMAC key.
const HMAC_KEY_LIMIT: usize = 64;

fn hmac<M: Mac + KeyInit>(key: &[u8], payload: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    let key = &key[..key.len().min(HMAC_KEY_LIMIT)];
    let mut mac =
        <M as KeyInit>::new_from_slice(key).map_err(|e| ProcessingError::Crypto(e.to_string()))?;
    mac.update(payload);
    Ok(mac.finalize().into_bytes().to_vec())
}

impl MacAlgorithm {
    pub(super) fn compute(self, key: &MacKey, payload: &[u8]) -> Result<Vec<u8>, ProcessingError> {
        let key = key.0.as_slice();
        match self {
            Self::HmacMd5 => hmac::<Hmac<Md5>>(key, payload),
            Self::HmacSha1 => hmac::<Hmac<Sha1>>(key, payload),
            Self::HmacRipemd160 => hmac::<Hmac<Ripemd160>>(key, payload),
            Self::HmacSha256 => hmac::<Hmac<Sha256>>(key, payload),
            Self::CmacAes128 => {
                let mut mac = <Cmac<Aes128> as KeyInit>::new_from_slice(key).map_err(|_| {
                    ProcessingError::InvalidKey(format!(
                        "CMAC needs a 16-byte key, not {}",
                        key.len()
                    ))
                })?;
                mac.update(payload);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }
}

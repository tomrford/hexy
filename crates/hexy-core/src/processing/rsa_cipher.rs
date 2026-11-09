use rsa::hazmat::{rsa_decrypt_and_check, rsa_encrypt};
use rsa::rand_core::OsRng;
use rsa::traits::PublicKeyParts;
use rsa::{BigUint, Oaep, Pkcs1v15Encrypt};
use sha1::Sha1;
use sha2::Sha256;

use super::ProcessingError;
use super::keys::{RsaPrivateKey, RsaPublicKey};

/// The padding of RSA encryption, which encrypts or decrypts each block on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsaPadding {
    /// PKCS #1 v1.5. Data of a multiple of the key length is encrypted without padding,
    /// one key length at a time; other data must fit one padded block. Decrypting one
    /// key length removes the padding when it is valid; longer data is decrypted
    /// without padding.
    Pkcs1v15,
    /// OAEP with SHA-1 and no label; the data must fit one padded block.
    OaepSha1,
    /// OAEP with SHA-256 and no label; the data must fit one padded block.
    OaepSha256,
}

impl RsaPadding {
    pub(super) fn encrypt(
        self,
        key: &RsaPublicKey,
        data: &[u8],
    ) -> Result<Vec<u8>, ProcessingError> {
        let key = key.0.as_ref();
        let size = key.size();
        let encrypted = match self {
            Self::Pkcs1v15 if data.len().is_multiple_of(size) => {
                return data
                    .chunks(size)
                    .map(|chunk| {
                        let message = BigUint::from_bytes_be(chunk);
                        if &message >= key.n() {
                            return Err(ProcessingError::Crypto(
                                "data block is not below the RSA modulus".to_owned(),
                            ));
                        }
                        rsa_encrypt(key, &message)
                            .map(|cipher| be_bytes(&cipher, size))
                            .map_err(crypto)
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(|chunks| chunks.concat());
            }
            Self::Pkcs1v15 => key.encrypt(&mut OsRng, Pkcs1v15Encrypt, data),
            Self::OaepSha1 => key.encrypt(&mut OsRng, Oaep::new::<Sha1>(), data),
            Self::OaepSha256 => key.encrypt(&mut OsRng, Oaep::new::<Sha256>(), data),
        };
        encrypted.map_err(crypto)
    }

    pub(super) fn decrypt(
        self,
        key: &RsaPrivateKey,
        data: &[u8],
    ) -> Result<Vec<u8>, ProcessingError> {
        let key = key.0.as_ref();
        let size = key.size();
        let raw = |chunk: &[u8]| {
            rsa_decrypt_and_check(key, Some(&mut OsRng), &BigUint::from_bytes_be(chunk))
                .map(|message| be_bytes(&message, size))
                .map_err(crypto)
        };
        let single = data.len() == size;
        match self {
            Self::Pkcs1v15 if single => key.decrypt(Pkcs1v15Encrypt, data).or_else(|_| raw(data)),
            Self::Pkcs1v15 if data.len().is_multiple_of(size) => data
                .chunks(size)
                .map(raw)
                .collect::<Result<Vec<Vec<u8>>, _>>()
                .map(|chunks| chunks.concat()),
            Self::OaepSha1 if single => key.decrypt(Oaep::new::<Sha1>(), data).map_err(crypto),
            Self::OaepSha256 if single => key.decrypt(Oaep::new::<Sha256>(), data).map_err(crypto),
            _ => Err(ProcessingError::RsaDataLength(size)),
        }
    }
}

fn crypto(e: rsa::Error) -> ProcessingError {
    ProcessingError::Crypto(e.to_string())
}

/// `value` as `size` big-endian bytes.
fn be_bytes(value: &BigUint, size: usize) -> Vec<u8> {
    let bytes = value.to_bytes_be();
    let mut out = vec![0; size.saturating_sub(bytes.len())];
    out.extend_from_slice(&bytes);
    out
}

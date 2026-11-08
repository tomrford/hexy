use ed25519_dalek::Signature as EdSignature;
use md5::Md5;
use p256::ecdsa::Signature as P256Signature;
use ripemd::Ripemd160;
use rsa::BigUint;
use rsa::hazmat::rsa_encrypt;
use rsa::pkcs1v15::{
    Signature as RsaPkcs1v15Signature, SigningKey as RsaPkcs1v15SigningKey,
    VerifyingKey as RsaPkcs1v15VerifyingKey,
};
use rsa::pkcs8::AssociatedOid;
use rsa::pss::{
    Signature as RsaPssSignature, SigningKey as RsaPssSigningKey,
    VerifyingKey as RsaPssVerifyingKey,
};
use rsa::rand_core::{CryptoRng, RngCore, impls};
use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer, Verifier};
use rsa::traits::PublicKeyParts;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use super::ProcessingError;
use super::keys::{
    Ed25519PrivateKey, Ed25519PublicKey, P256PrivateKey, P256PublicKey, RsaPrivateKey, RsaPublicKey,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// RSA PKCS #1 v1.5 over MD5.
    RsaPkcs1v15Md5,
    /// RSA PKCS #1 v1.5 over SHA-1.
    RsaPkcs1v15Sha1,
    /// RSA PKCS #1 v1.5 over RIPEMD-160.
    RsaPkcs1v15Ripemd160,
    /// RSA PKCS #1 v1.5 over SHA-256.
    RsaPkcs1v15Sha256,
    /// RSA-PSS over SHA-256. Signing takes a salt, or a random 32-byte salt;
    /// verification accepts any salt length, as HexView's does.
    RsaPssSha256,
    /// ECDSA over P-256 and SHA-256 with deterministic nonces (RFC 6979). The signature
    /// is r and s as 32-byte big-endian values.
    EcdsaP256Sha256,
    /// Ed25519 over the payload; the image must be a single block.
    Ed25519,
    /// Ed25519ph (SHA-512 pre-hash, empty context) over the payload.
    Ed25519Ph,
    /// Ed25519ph over the SHA-512 digest of the payload.
    Ed25519PhSha512,
}

/// A signature scheme and the payload it covers: the data of each block, in address
/// order; with metadata, each block's data is preceded by its start address and length
/// as big-endian `u32`s.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignatureMethod {
    pub scheme: SignatureScheme,
    pub with_metadata: bool,
}

#[derive(Debug, Clone)]
pub enum SigningKey {
    Rsa(RsaPrivateKey),
    Ed25519(Ed25519PrivateKey),
    P256(P256PrivateKey),
}

#[derive(Debug, Clone)]
pub enum VerifyingKey {
    Rsa(RsaPublicKey),
    Ed25519(Ed25519PublicKey),
    P256(P256PublicKey),
}

impl SignatureScheme {
    /// The private key for this scheme from a key file or key text.
    pub fn signing_key(self, key_file: &[u8]) -> Result<SigningKey, ProcessingError> {
        Ok(match self {
            Self::EcdsaP256Sha256 => SigningKey::P256(P256PrivateKey::from_key_file(key_file)?),
            Self::Ed25519 | Self::Ed25519Ph | Self::Ed25519PhSha512 => {
                SigningKey::Ed25519(Ed25519PrivateKey::from_key_file(key_file)?)
            }
            Self::RsaPkcs1v15Md5
            | Self::RsaPkcs1v15Sha1
            | Self::RsaPkcs1v15Ripemd160
            | Self::RsaPkcs1v15Sha256
            | Self::RsaPssSha256 => SigningKey::Rsa(RsaPrivateKey::from_key_file(key_file)?),
        })
    }

    /// The public key for this scheme from a key file or key text.
    pub fn verifying_key(self, key_file: &[u8]) -> Result<VerifyingKey, ProcessingError> {
        Ok(match self {
            Self::EcdsaP256Sha256 => VerifyingKey::P256(P256PublicKey::from_key_file(key_file)?),
            Self::Ed25519 | Self::Ed25519Ph | Self::Ed25519PhSha512 => {
                VerifyingKey::Ed25519(Ed25519PublicKey::from_key_file(key_file)?)
            }
            Self::RsaPkcs1v15Md5
            | Self::RsaPkcs1v15Sha1
            | Self::RsaPkcs1v15Ripemd160
            | Self::RsaPkcs1v15Sha256
            | Self::RsaPssSha256 => VerifyingKey::Rsa(RsaPublicKey::from_key_file(key_file)?),
        })
    }

    pub(super) fn sign(
        self,
        key: &SigningKey,
        payload: &[u8],
        salt: Option<&[u8]>,
    ) -> Result<Vec<u8>, ProcessingError> {
        if salt.is_some() && self != Self::RsaPssSha256 {
            return Err(ProcessingError::UnusedSalt(self));
        }
        let crypto = |e: rsa::signature::Error| ProcessingError::Crypto(e.to_string());
        match (self, key) {
            (Self::RsaPkcs1v15Md5, SigningKey::Rsa(key)) => Ok(sign_pkcs1v15::<Md5>(key, payload)),
            (Self::RsaPkcs1v15Sha1, SigningKey::Rsa(key)) => {
                Ok(sign_pkcs1v15::<Sha1>(key, payload))
            }
            (Self::RsaPkcs1v15Ripemd160, SigningKey::Rsa(key)) => {
                Ok(sign_pkcs1v15::<Ripemd160>(key, payload))
            }
            (Self::RsaPkcs1v15Sha256, SigningKey::Rsa(key)) => {
                Ok(sign_pkcs1v15::<Sha256>(key, payload))
            }
            (Self::RsaPssSha256, SigningKey::Rsa(key)) => {
                let key = key.0.as_ref().clone();
                match salt {
                    Some(salt) => RsaPssSigningKey::<Sha256>::new_with_salt_len(key, salt.len())
                        .try_sign_with_rng(&mut FixedSalt(salt), payload),
                    None => RsaPssSigningKey::<Sha256>::new(key).try_sign(payload),
                }
                .map(|signature| signature.to_vec())
                .map_err(crypto)
            }
            (Self::EcdsaP256Sha256, SigningKey::P256(key)) => {
                let signature: P256Signature = key.0.sign(payload);
                Ok(signature.to_bytes().to_vec())
            }
            (Self::Ed25519, SigningKey::Ed25519(key)) => {
                Ok(key.0.sign(payload).to_bytes().to_vec())
            }
            (Self::Ed25519Ph, SigningKey::Ed25519(key)) => sign_ed25519ph(key, payload),
            (Self::Ed25519PhSha512, SigningKey::Ed25519(key)) => {
                sign_ed25519ph(key, &Sha512::digest(payload))
            }
            _ => Err(ProcessingError::KeyMismatch(self)),
        }
    }

    pub(super) fn verify(
        self,
        key: &VerifyingKey,
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), ProcessingError> {
        let invalid = || ProcessingError::InvalidSignature(signature.len());
        let verified = match (self, key) {
            (Self::RsaPkcs1v15Md5, VerifyingKey::Rsa(key)) => {
                return verify_pkcs1v15::<Md5>(key, payload, signature);
            }
            (Self::RsaPkcs1v15Sha1, VerifyingKey::Rsa(key)) => {
                return verify_pkcs1v15::<Sha1>(key, payload, signature);
            }
            (Self::RsaPkcs1v15Ripemd160, VerifyingKey::Rsa(key)) => {
                return verify_pkcs1v15::<Ripemd160>(key, payload, signature);
            }
            (Self::RsaPkcs1v15Sha256, VerifyingKey::Rsa(key)) => {
                return verify_pkcs1v15::<Sha256>(key, payload, signature);
            }
            (Self::RsaPssSha256, VerifyingKey::Rsa(key)) => {
                let signature = RsaPssSignature::try_from(signature).map_err(|_| invalid())?;
                // HexView verifies any salt length, so it is read from the signature.
                let salt_len = pss_salt_len(&key.0, &signature.to_bytes())
                    .ok_or(ProcessingError::VerificationFailed)?;
                RsaPssVerifyingKey::<Sha256>::new_with_salt_len(key.0.as_ref().clone(), salt_len)
                    .verify(payload, &signature)
            }
            (Self::EcdsaP256Sha256, VerifyingKey::P256(key)) => {
                let signature = P256Signature::from_slice(signature).map_err(|_| invalid())?;
                key.0.verify(payload, &signature)
            }
            (Self::Ed25519, VerifyingKey::Ed25519(key)) => {
                let signature = EdSignature::from_slice(signature).map_err(|_| invalid())?;
                key.0.verify(payload, &signature)
            }
            (Self::Ed25519Ph | Self::Ed25519PhSha512, VerifyingKey::Ed25519(key)) => {
                let signature = EdSignature::from_slice(signature).map_err(|_| invalid())?;
                let prehash = match self {
                    Self::Ed25519PhSha512 => Sha512::new_with_prefix(Sha512::digest(payload)),
                    _ => Sha512::new_with_prefix(payload),
                };
                key.0.verify_prehashed(prehash, None, &signature)
            }
            _ => return Err(ProcessingError::KeyMismatch(self)),
        };
        verified.map_err(|_| ProcessingError::VerificationFailed)
    }
}

fn sign_pkcs1v15<D: Digest + AssociatedOid>(key: &RsaPrivateKey, payload: &[u8]) -> Vec<u8> {
    RsaPkcs1v15SigningKey::<D>::new(key.0.as_ref().clone())
        .sign(payload)
        .to_vec()
}

fn verify_pkcs1v15<D: Digest + AssociatedOid>(
    key: &RsaPublicKey,
    payload: &[u8],
    signature: &[u8],
) -> Result<(), ProcessingError> {
    let signature = RsaPkcs1v15Signature::try_from(signature)
        .map_err(|_| ProcessingError::InvalidSignature(signature.len()))?;
    RsaPkcs1v15VerifyingKey::<D>::new(key.0.as_ref().clone())
        .verify(payload, &signature)
        .map_err(|_| ProcessingError::VerificationFailed)
}

/// The salt length of an RSA-PSS SHA-256 signature: the length of the data block
/// after the zero padding and its `01` separator, once unmasked (RFC 8017 9.1.2).
fn pss_salt_len(key: &rsa::RsaPublicKey, signature: &[u8]) -> Option<usize> {
    let hash_len = Sha256::output_size();
    let em_bits = key.n().bits() - 1;
    let em_len = em_bits.div_ceil(8);
    let message = rsa_encrypt(key, &BigUint::from_bytes_be(signature)).ok()?;
    let mut em = message.to_bytes_be();
    em.splice(0..0, vec![0; em_len.checked_sub(em.len())?]);
    let db_len = em_len.checked_sub(hash_len + 1)?;
    let hash = &em[db_len..em_len - 1];
    let mut db = Vec::with_capacity(db_len);
    for counter in 0u32.. {
        if db.len() >= db_len {
            break;
        }
        db.extend(
            Sha256::new()
                .chain_update(hash)
                .chain_update(counter.to_be_bytes())
                .finalize(),
        );
    }
    db.truncate(db_len);
    db.iter_mut()
        .zip(&em)
        .for_each(|(mask, masked)| *mask ^= masked);
    db[0] &= 0xFF >> (8 * em_len - em_bits);
    let separator = db.iter().position(|&b| b != 0)?;
    Some(db_len - separator - 1)
}

fn sign_ed25519ph(key: &Ed25519PrivateKey, message: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    key.0
        .sign_prehashed(Sha512::new_with_prefix(message), None)
        .map(|signature| signature.to_bytes().to_vec())
        .map_err(|e| ProcessingError::Crypto(e.to_string()))
}

/// The RNG an RSA-PSS signer takes its salt from, giving the salt bytes.
struct FixedSalt<'a>(&'a [u8]);

impl RngCore for FixedSalt<'_> {
    fn next_u32(&mut self) -> u32 {
        impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let (salt, rest) = self.0.split_at(dest.len().min(self.0.len()));
        dest[..salt.len()].copy_from_slice(salt);
        self.0 = rest;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rsa::rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for FixedSalt<'_> {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode_hex_text;

    /// HexView pads a short raw P-256 scalar with zero bytes at the end: its `/DP50`
    /// signature with key text `0102...10` verifies with the key hexy reads from it.
    #[test]
    fn test_short_p256_scalar_matches_hexview() {
        let private = P256PrivateKey::from_key_file(b"0102030405060708090a0b0c0d0e0f10").unwrap();
        let public = VerifyingKey::P256(P256PublicKey(Box::new(*private.0.verifying_key())));
        let payload: Vec<u8> = [(0x30, 1u8), (0x10, 2)]
            .into_iter()
            .flat_map(|(len, seed)| (0..len).map(move |i| seed.wrapping_add((i * 7) as u8)))
            .collect();
        let signature = decode_hex_text(b"c912e18658b5e0501952f3ee09c5fd1ca282085b04924ab0b6f67e011bcf3d0715b5f2cfc5a0b4fda9bd2e9cb852148332b77fc37f0bc41e4f71c35acca3dce8").unwrap();
        SignatureScheme::EcdsaP256Sha256
            .verify(&public, &payload, &signature)
            .unwrap();
    }
}

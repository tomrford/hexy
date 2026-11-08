use ed25519_dalek::Signature as EdSignature;
use rsa::pkcs1v15::{
    Signature as RsaPkcs1v15Signature, SigningKey as RsaPkcs1v15SigningKey,
    VerifyingKey as RsaPkcs1v15VerifyingKey,
};
use rsa::pss::{
    Signature as RsaPssSignature, SigningKey as RsaPssSigningKey,
    VerifyingKey as RsaPssVerifyingKey,
};
use rsa::signature::{SignatureEncoding, Signer, Verifier};
use sha2::{Digest, Sha256, Sha512};

use super::ProcessingError;
use super::keys::{Ed25519PrivateKey, Ed25519PublicKey, RsaPrivateKey, RsaPublicKey};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureScheme {
    /// RSA PKCS #1 v1.5 over SHA-256.
    RsaPkcs1v15Sha256,
    /// RSA-PSS over SHA-256 with a random 32-byte salt.
    RsaPssSha256,
    /// Ed25519ph (SHA-512 pre-hash, empty context).
    Ed25519Ph,
    /// Ed25519 over the SHA-512 digest of the payload.
    Ed25519Sha512,
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
}

#[derive(Debug, Clone)]
pub enum VerifyingKey {
    Rsa(RsaPublicKey),
    Ed25519(Ed25519PublicKey),
}

impl SignatureScheme {
    fn is_rsa(self) -> bool {
        matches!(self, Self::RsaPkcs1v15Sha256 | Self::RsaPssSha256)
    }

    /// The private key for this scheme from a key file or key text.
    pub fn signing_key(self, key_file: &[u8]) -> Result<SigningKey, ProcessingError> {
        Ok(if self.is_rsa() {
            SigningKey::Rsa(RsaPrivateKey::from_key_file(key_file)?)
        } else {
            SigningKey::Ed25519(Ed25519PrivateKey::from_key_file(key_file)?)
        })
    }

    /// The public key for this scheme from a key file or key text.
    pub fn verifying_key(self, key_file: &[u8]) -> Result<VerifyingKey, ProcessingError> {
        Ok(if self.is_rsa() {
            VerifyingKey::Rsa(RsaPublicKey::from_key_file(key_file)?)
        } else {
            VerifyingKey::Ed25519(Ed25519PublicKey::from_key_file(key_file)?)
        })
    }

    pub(super) fn sign(self, key: &SigningKey, payload: &[u8]) -> Result<Vec<u8>, ProcessingError> {
        match (self, key) {
            (Self::RsaPkcs1v15Sha256, SigningKey::Rsa(key)) => {
                let signer = RsaPkcs1v15SigningKey::<Sha256>::new(key.0.clone());
                Ok(signer.sign(payload).to_vec())
            }
            (Self::RsaPssSha256, SigningKey::Rsa(key)) => {
                let signer = RsaPssSigningKey::<Sha256>::new(key.0.clone());
                Ok(signer.sign(payload).to_vec())
            }
            (Self::Ed25519Ph, SigningKey::Ed25519(key)) => key
                .0
                .sign_prehashed(Sha512::new_with_prefix(payload), None)
                .map(|signature| signature.to_bytes().to_vec())
                .map_err(|e| ProcessingError::Crypto(e.to_string())),
            (Self::Ed25519Sha512, SigningKey::Ed25519(key)) => {
                Ok(key.0.sign(&Sha512::digest(payload)).to_bytes().to_vec())
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
            (Self::RsaPkcs1v15Sha256, VerifyingKey::Rsa(key)) => {
                let signature = RsaPkcs1v15Signature::try_from(signature).map_err(|_| invalid())?;
                RsaPkcs1v15VerifyingKey::<Sha256>::new(key.0.clone()).verify(payload, &signature)
            }
            (Self::RsaPssSha256, VerifyingKey::Rsa(key)) => {
                let signature = RsaPssSignature::try_from(signature).map_err(|_| invalid())?;
                RsaPssVerifyingKey::<Sha256>::new(key.0.clone()).verify(payload, &signature)
            }
            (Self::Ed25519Ph, VerifyingKey::Ed25519(key)) => {
                let signature = EdSignature::from_slice(signature).map_err(|_| invalid())?;
                key.0
                    .verify_prehashed(Sha512::new_with_prefix(payload), None, &signature)
            }
            (Self::Ed25519Sha512, VerifyingKey::Ed25519(key)) => {
                let signature = EdSignature::from_slice(signature).map_err(|_| invalid())?;
                key.0.verify(&Sha512::digest(payload), &signature)
            }
            _ => return Err(ProcessingError::KeyMismatch(self)),
        };
        verified.map_err(|_| ProcessingError::VerificationFailed)
    }
}

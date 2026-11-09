//! HexView's data processing (`/DP`) and signature verification (`/SV`) operations.
//!
//! A [`DataProcessing`] operation runs over the image's blocks (see
//! [`HexFile::blocks`]) and may produce output bytes, such as a signature, which can be
//! placed into the image.

mod keys;
mod signature;

use thiserror::Error;

use crate::{HexFile, OpsError, Placement};

pub use keys::{Ed25519PrivateKey, Ed25519PublicKey, RsaPrivateKey, RsaPublicKey, decode_hex_text};
pub use signature::{SignatureMethod, SignatureScheme, SigningKey, VerifyingKey};

#[derive(Debug, Clone)]
pub enum DataProcessing {
    /// Sign the block payload; the output is the signature.
    Sign {
        method: SignatureMethod,
        key: SigningKey,
    },
}

#[derive(Debug, Error)]
pub enum ProcessingError {
    #[error("block length exceeds u32")]
    PayloadLengthOverflow,

    #[error("placement: {0}")]
    Placement(#[from] OpsError),

    #[error("{0}")]
    InvalidKey(String),

    #[error("{0:?} cannot use this key type")]
    KeyMismatch(SignatureScheme),

    #[error("invalid signature length {0}")]
    InvalidSignature(usize),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("{0}")]
    Crypto(String),
}

impl HexFile {
    /// Run `operation` on the blocks and return its output, if any. With `placement`,
    /// the output is also written into the image.
    pub fn process_data(
        &mut self,
        operation: &DataProcessing,
        placement: Option<Placement>,
    ) -> Result<Option<Vec<u8>>, ProcessingError> {
        let output = match operation {
            DataProcessing::Sign { method, key } => method
                .scheme
                .sign(key, &payload(self, method.with_metadata)?)?,
        };
        if let Some(placement) = placement
            && let Some(target) = self.placement_range(placement, output.len())?
        {
            self.write_bytes(target.start(), &output)?;
        }
        Ok(Some(output))
    }

    pub fn verify_signature(
        &self,
        method: SignatureMethod,
        key: &VerifyingKey,
        signature: &[u8],
    ) -> Result<(), ProcessingError> {
        method
            .scheme
            .verify(key, &payload(self, method.with_metadata)?, signature)
    }
}

/// The block data in address order; with metadata, each block is preceded by its start
/// address and length as big-endian `u32`s.
fn payload(hexfile: &HexFile, with_metadata: bool) -> Result<Vec<u8>, ProcessingError> {
    let mut payload = Vec::new();
    for block in hexfile.blocks() {
        if with_metadata {
            let len =
                u32::try_from(block.len()).map_err(|_| ProcessingError::PayloadLengthOverflow)?;
            payload.extend_from_slice(&block.start_address.to_be_bytes());
            payload.extend_from_slice(&len.to_be_bytes());
        }
        payload.extend_from_slice(&block.data);
    }
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    /// HexView 1.15.2 `/DP33` hashes each block as big-endian start, big-endian length
    /// and data; split pieces count as blocks (verified against its RSA signatures).
    #[test]
    fn test_metadata_payload_lists_each_block() {
        let mut file = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA; 0x180]).unwrap(),
            Segment::new(0x2000, vec![0xBB]).unwrap(),
        ]);
        file.split(0x100);
        let payload = payload(&file, true).unwrap();
        let mut expected = Vec::new();
        for (start, data) in [
            (0x1000u32, [0xAA; 0x100].as_slice()),
            (0x1100, &[0xAA; 0x80]),
            (0x2000, &[0xBB]),
        ] {
            expected.extend_from_slice(&start.to_be_bytes());
            expected.extend_from_slice(&(data.len() as u32).to_be_bytes());
            expected.extend_from_slice(data);
        }
        assert_eq!(payload, expected);
    }
}

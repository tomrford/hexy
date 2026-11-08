//! HexView's data processing (`/DP`) and signature verification (`/SV`) operations.
//!
//! A [`DataProcessing`] operation runs over the image's blocks (see
//! [`HexFile::blocks`]). Signatures and MACs produce output bytes, which can be placed
//! into the image; ciphers replace the data of the blocks.

mod gcm;
mod keys;
mod mac;
mod rsa_cipher;
mod signature;
mod symmetric;

use thiserror::Error;

use crate::{HexFile, OpsError, Placement, Segment};

pub use gcm::{AesGcm, GcmTag};
pub use keys::{
    AesKey, Ed25519PrivateKey, Ed25519PublicKey, MacKey, P256PrivateKey, P256PublicKey,
    RsaPrivateKey, RsaPublicKey, decode_hex_text,
};
pub use mac::{MacAlgorithm, MacMethod};
pub use rsa_cipher::RsaPadding;
pub use signature::{SignatureMethod, SignatureScheme, SigningKey, VerifyingKey};
pub use symmetric::{AesMode, AesPadding};

use symmetric::AesBlocks;

#[derive(Debug, Clone)]
pub enum DataProcessing {
    /// Sign the block payload; the output is the signature. `salt` is the RSA-PSS salt,
    /// which no other scheme takes; without it, RSA-PSS uses a random 32-byte salt.
    Sign {
        method: SignatureMethod,
        key: SigningKey,
        salt: Option<Vec<u8>>,
    },
    /// Authenticate the block payload; the output is the MAC.
    Mac { method: MacMethod, key: MacKey },
    /// XOR the data with the key, repeated across the blocks; an empty key inverts the
    /// data, as HexView does without a key.
    Xor { key: Vec<u8> },
    /// Encrypt each block with AES.
    Encrypt {
        key: AesKey,
        mode: AesMode,
        padding: Option<AesPadding>,
    },
    /// Decrypt each block with AES.
    Decrypt {
        key: AesKey,
        mode: AesMode,
        padding: Option<AesPadding>,
    },
    /// Encrypt the data of all blocks as one AES-GCM stream; the output is the tag.
    EncryptGcm(AesGcm),
    /// Decrypt the data of all blocks as one AES-GCM stream and check the tag.
    DecryptGcm { gcm: AesGcm, tag: GcmTag },
    /// Encrypt each block with an RSA public key.
    RsaEncrypt {
        key: RsaPublicKey,
        padding: RsaPadding,
    },
    /// Decrypt each block with an RSA private key.
    RsaDecrypt {
        key: RsaPrivateKey,
        padding: RsaPadding,
    },
}

impl DataProcessing {
    /// Whether the operation replaces block data.
    pub(crate) fn transforms_data(&self) -> bool {
        !matches!(self, Self::Sign { .. } | Self::Mac { .. })
    }
}

#[derive(Debug, Error)]
pub enum ProcessingError {
    #[error("block length exceeds u32")]
    PayloadLengthOverflow,

    #[error(transparent)]
    Ops(#[from] OpsError),

    #[error("{0}")]
    InvalidKey(String),

    #[error("{0:?} cannot use this key type")]
    KeyMismatch(SignatureScheme),

    #[error("invalid signature length {0}")]
    InvalidSignature(usize),

    #[error("{0:?} takes no salt")]
    UnusedSalt(SignatureScheme),

    #[error("this method signs a single block of data, not {0}")]
    MultipleBlocks(usize),

    #[error("signature verification failed")]
    VerificationFailed,

    #[error("AES needs data in 16-byte blocks; align the data or use padding")]
    Unaligned,

    #[error("the first block is shorter than the 16-byte IV taken from it")]
    ShortIvBlock,

    #[error("invalid AES padding")]
    InvalidPadding,

    #[error("AES-GCM needs a nonce")]
    EmptyNonce,

    #[error("the AES-GCM tag must lie at the start or end of a block")]
    TagLocation,

    #[error("AES-GCM tag verification failed")]
    TagMismatch,

    #[error("RSA decryption needs blocks of the {0}-byte key length")]
    RsaDataLength(usize),

    #[error("{0}")]
    Crypto(String),
}

impl HexFile {
    /// Run `operation` on the blocks and return its output, if any. With `placement`,
    /// the output is also written into the image.
    ///
    /// Ciphers replace each block's data from the block's start address, in block order,
    /// so data that grows overwrites what follows it; a block given no output keeps its
    /// data. When a cipher fails, the blocks before the failing one stay replaced, as in
    /// HexView.
    pub fn process_data(
        &mut self,
        operation: &DataProcessing,
        placement: Option<Placement>,
    ) -> Result<Option<Vec<u8>>, ProcessingError> {
        self.process_data_tracked(operation, placement, &mut false)
    }

    /// Record committed writes so the pipeline can normalize a partially failed stage.
    pub(crate) fn process_data_tracked(
        &mut self,
        operation: &DataProcessing,
        placement: Option<Placement>,
        wrote_data: &mut bool,
    ) -> Result<Option<Vec<u8>>, ProcessingError> {
        let output = match operation {
            DataProcessing::Sign { method, key, salt } => Some(method.scheme.sign(
                key,
                &self.signed_payload(*method)?,
                salt.as_deref(),
            )?),
            DataProcessing::Mac { method, key } => Some(
                method
                    .algorithm
                    .compute(key, &payload(&self.blocks(), method.with_metadata)?)?,
            ),
            DataProcessing::Xor { key } => {
                let key: &[u8] = if key.is_empty() { &[0xFF] } else { key };
                let mut stream = key.iter().cycle();
                self.transform_blocks(wrote_data, |data| {
                    Ok(data.iter().zip(&mut stream).map(|(b, k)| b ^ k).collect())
                })?;
                None
            }
            DataProcessing::Encrypt { key, mode, padding }
            | DataProcessing::Decrypt { key, mode, padding } => {
                let decrypt = matches!(operation, DataProcessing::Decrypt { .. });
                let mut aes = AesBlocks::new(key, *mode, *padding, decrypt);
                self.transform_blocks(wrote_data, |data| aes.process(data))?;
                None
            }
            DataProcessing::EncryptGcm(gcm) => Some(gcm.encrypt(self, wrote_data)?),
            DataProcessing::DecryptGcm { gcm, tag } => {
                gcm.decrypt(self, tag, wrote_data)?;
                None
            }
            DataProcessing::RsaEncrypt { key, padding } => {
                self.transform_blocks(wrote_data, |data| padding.encrypt(key, data))?;
                None
            }
            DataProcessing::RsaDecrypt { key, padding } => {
                self.transform_blocks(wrote_data, |data| padding.decrypt(key, data))?;
                None
            }
        };
        if let (Some(placement), Some(output)) = (placement, &output)
            && let Some(target) = self.placement_range(placement, output.len())?
        {
            self.write_bytes(target.start(), output)?;
            *wrote_data |= !output.is_empty();
        }
        Ok(output)
    }

    pub fn verify_signature(
        &self,
        method: SignatureMethod,
        key: &VerifyingKey,
        signature: &[u8],
    ) -> Result<(), ProcessingError> {
        method
            .scheme
            .verify(key, &self.signed_payload(method)?, signature)
    }

    /// The payload `method` signs; Ed25519 signs a single block.
    fn signed_payload(&self, method: SignatureMethod) -> Result<Vec<u8>, ProcessingError> {
        let blocks = self.blocks();
        if method.scheme == SignatureScheme::Ed25519 && blocks.len() > 1 {
            return Err(ProcessingError::MultipleBlocks(blocks.len()));
        }
        payload(&blocks, method.with_metadata)
    }

    /// Replace each block with `transform`'s output for it, in block order.
    fn transform_blocks(
        &mut self,
        wrote_data: &mut bool,
        mut transform: impl FnMut(&[u8]) -> Result<Vec<u8>, ProcessingError>,
    ) -> Result<(), ProcessingError> {
        let blocks = self.blocks();
        let mut outputs = Vec::with_capacity(blocks.len());
        let mut result = Ok(());
        for block in &blocks {
            match transform(&block.data) {
                Ok(output) => outputs.push(output),
                Err(e) => {
                    result = Err(e);
                    break;
                }
            }
        }
        self.replace_blocks(&blocks, outputs, Vec::new(), wrote_data)?;
        result
    }

    /// Write `outputs` in place of the first blocks, in block order, up to an output
    /// that does not fit the address space; later blocks, blocks with an empty output,
    /// and `kept`, which wins over the outputs, keep their data.
    fn replace_blocks(
        &mut self,
        blocks: &[Segment],
        outputs: Vec<Vec<u8>>,
        kept: Vec<Segment>,
        wrote_data: &mut bool,
    ) -> Result<(), ProcessingError> {
        let mut replaced = Vec::with_capacity(outputs.len());
        let mut wrote_replacement = false;
        let mut result = Ok(());
        for (block, output) in blocks.iter().zip(outputs) {
            if output.is_empty() {
                replaced.push(block.clone());
                continue;
            }
            match Segment::new(block.start_address, output) {
                Ok(segment) => {
                    replaced.push(segment);
                    wrote_replacement = true;
                }
                Err(e) => {
                    result = Err(OpsError::from(e).into());
                    break;
                }
            }
        }
        if !wrote_replacement {
            return result;
        }
        let mut segments = blocks[replaced.len()..].to_vec();
        segments.extend(replaced);
        segments.extend(kept);
        self.set_segments(segments);
        *wrote_data = true;
        result
    }
}

/// The block data in address order; with metadata, each block is preceded by its start
/// address and length as big-endian `u32`s.
fn payload(blocks: &[Segment], with_metadata: bool) -> Result<Vec<u8>, ProcessingError> {
    let mut payload = Vec::new();
    for block in blocks {
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
    use crate::AddressRange;

    /// The probe data pattern: byte `i` is `seed + 7 * i`.
    fn pat(len: usize, seed: u8) -> Vec<u8> {
        (0..len).map(|i| seed.wrapping_add((i * 7) as u8)).collect()
    }

    fn image(blocks: &[(u32, Vec<u8>)]) -> HexFile {
        HexFile::with_segments(
            blocks
                .iter()
                .map(|(start, data)| Segment::new(*start, data.clone()).unwrap())
                .collect(),
        )
    }

    fn data(file: &HexFile) -> Vec<Vec<u8>> {
        file.blocks().into_iter().map(|b| b.data).collect()
    }

    fn hex(text: &str) -> Vec<u8> {
        decode_hex_text(text.as_bytes()).unwrap()
    }

    fn aes_key() -> AesKey {
        AesKey::new(&hex("00112233445566778899aabbccddeeff")).unwrap()
    }

    /// HexView 1.15.2 `/DP1:1234ABCD`: the key continues from one block to the next.
    #[test]
    fn test_xor_key_continues_across_blocks() {
        let mut file = image(&[(0x1000, pat(0x3E, 3)), (0x2000, pat(6, 4))]);
        let xor = DataProcessing::Xor {
            key: hex("1234ABCD"),
        };
        assert_eq!(file.process_data(&xor, None).unwrap(), None);
        let blocks = data(&file);
        assert_eq!(blocks[0][..4], hex("113EBAD5"));
        assert_eq!(blocks[1], hex("AFC6002D8BEA"));
    }

    /// HexView 1.15.2 `/DP11` without `#IV`: the first 16 bytes of the first block are
    /// the IV and stay as they are; the next block uses that IV from its start.
    #[test]
    fn test_cbc_takes_iv_from_first_block() {
        let mut file = image(&[(0x1000, pat(0x40, 1)), (0x2000, pat(0x20, 2))]);
        let encrypt = DataProcessing::Encrypt {
            key: aes_key(),
            mode: AesMode::Cbc { iv: None },
            padding: Some(AesPadding::Pkcs7),
        };
        file.process_data(&encrypt, None).unwrap();
        let blocks = data(&file);
        assert_eq!((blocks[0].len(), blocks[1].len()), (0x50, 0x30));
        assert_eq!(blocks[0][..16], pat(16, 1));
        assert_eq!(blocks[0][16..32], hex("f436b5ea403cd5018f7ae5880ebae1b2"));
        assert_eq!(blocks[1][..16], hex("d5c6df82d76aa57c6438b5b074c613e7"));
    }

    /// HexView 1.15.2 `/DP53` continues its counter from all ones at one.
    #[test]
    fn test_ctr_counter_wraps_to_one() {
        let mut file = image(&[(0x1000, pat(0x45, 1))]);
        let encrypt = DataProcessing::Encrypt {
            key: aes_key(),
            mode: AesMode::Ctr {
                iv: Some([0xFF; 16]),
            },
            padding: None,
        };
        file.process_data(&encrypt, None).unwrap();
        assert_eq!(
            data(&file)[0][..32],
            hex("65b99c02de3edf68f59f397218ebfc67f5acb64606dbd38ac8531e7806971703")
        );
    }

    /// HexView 1.15.2 `/DP55:...#IV=0`: one stream over all blocks, with a 1-byte nonce.
    /// Each block takes the whole 16-byte units done by its end; the last block took
    /// none, so it keeps its data and the rest of the stream follows it.
    #[test]
    fn test_gcm_layout_matches_hexview() {
        let mut file = image(&[
            (0x1000, pat(0x45, 1)),
            (0x2000, pat(0x23, 2)),
            (0x3000, pat(7, 3)),
        ]);
        let gcm = AesGcm {
            key: aes_key(),
            nonce: vec![0],
            aad: Vec::new(),
        };
        let tag = file
            .process_data(&DataProcessing::EncryptGcm(gcm), None)
            .unwrap();
        assert_eq!(tag, Some(hex("3856B9069A5DB84D2AC9359D04E56FBD")));
        let blocks = data(&file);
        assert_eq!(
            blocks.iter().map(Vec::len).collect::<Vec<_>>(),
            [0x40, 0x20, 0x16]
        );
        assert_eq!(blocks[0][..16], hex("61bb3ebc05031e286bf5d8288e04e4ae"));
        assert_eq!(
            blocks[2],
            hex("030a11181f262d85d37ac481e557dc727d1a4db77b11")
        );
    }

    /// `/DP56` with `#TAG=@` at the start of a block: the tag stays, and the data after
    /// it is decrypted. A wrong tag fails after decrypting, as in HexView.
    #[test]
    fn test_gcm_decrypt_takes_tag_from_image() {
        let plain = [(0x1000, pat(0x40, 1)), (0x2000, pat(0x20, 2))];
        let gcm = AesGcm {
            key: aes_key(),
            nonce: (0..12).collect(),
            aad: b"AB".to_vec(),
        };
        let mut file = image(&plain);
        let tag = file
            .process_data(&DataProcessing::EncryptGcm(gcm.clone()), None)
            .unwrap()
            .unwrap();
        let ciphertext = data(&file);
        let tagged = [
            (0x1000, ciphertext[0].clone()),
            (0x2000, [tag.clone(), ciphertext[1].clone()].concat()),
        ];

        let mut file = image(&tagged);
        let tag_range = AddressRange::from_start_length(0x2000, 16).unwrap();
        let decrypt = DataProcessing::DecryptGcm {
            gcm: gcm.clone(),
            tag: GcmTag::Image(tag_range),
        };
        file.process_data(&decrypt, None).unwrap();
        file.normalize();
        assert_eq!(data(&file), [pat(0x40, 1), [tag, pat(0x20, 2)].concat()]);

        let mut file = image(&[
            (0x1000, ciphertext[0].clone()),
            (0x2000, ciphertext[1].clone()),
        ]);
        let decrypt = DataProcessing::DecryptGcm {
            gcm,
            tag: GcmTag::Bytes(vec![0; 16]),
        };
        let error = file.process_data(&decrypt, None).unwrap_err();
        assert!(matches!(error, ProcessingError::TagMismatch));
        assert_eq!(data(&file), [pat(0x40, 1), pat(0x20, 2)]);
    }

    /// HexView 1.15.2 `/DP4` and `/DP44` over gaps.hex; HMAC keys are cut after 64 bytes.
    #[test]
    fn test_mac_matches_hexview() {
        let mut file = image(&[
            (0x1000, pat(0x100, 1)),
            (0x1180, pat(0x80, 2)),
            (0x1301, pat(0x3E, 3)),
            (0x2000, pat(6, 4)),
        ]);
        let mut mac = |algorithm, key: &[u8]| {
            let method = MacMethod {
                algorithm,
                with_metadata: false,
            };
            let key = MacKey::new(key).unwrap();
            file.process_data(&DataProcessing::Mac { method, key }, None)
                .unwrap()
                .unwrap()
        };
        let key = hex("00112233445566778899aabbccddeeff");
        assert_eq!(
            mac(MacAlgorithm::HmacSha1, &key),
            hex("3A8E6287A8443A03FC254B861702942BDB06E871")
        );
        assert_eq!(
            mac(MacAlgorithm::CmacAes128, &key),
            hex("8609A186AB2B6FA9165CBFEC95D179DF")
        );
        assert_eq!(
            mac(MacAlgorithm::HmacSha1, &[0xCD; 100]),
            hex("DBAE758DBF6B9B203220F9B8A62940E6C4892DF4")
        );
    }

    /// HexView 1.15.2 `/DP33` hashes each block as big-endian start, big-endian length
    /// and data; split pieces count as blocks (verified against its RSA signatures).
    #[test]
    fn test_metadata_payload_lists_each_block() {
        let mut file = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA; 0x180]).unwrap(),
            Segment::new(0x2000, vec![0xBB]).unwrap(),
        ]);
        file.split(0x100);
        let payload = payload(&file.blocks(), true).unwrap();
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

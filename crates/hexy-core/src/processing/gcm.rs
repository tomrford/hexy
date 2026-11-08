//! AES-GCM over the data of all blocks as one stream, laid out as HexView lays it out.

use ghash::GHash;
use ghash::universal_hash::{KeyInit, UniversalHash};

use crate::{AddressRange, HexFile, Segment};

use super::ProcessingError;
use super::keys::AesKey;
use super::symmetric::{BLOCK, BlockCipher, xor_into};

/// Where AES-GCM decryption takes the tag from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GcmTag {
    Bytes(Vec<u8>),
    /// Image bytes at the start or end of a block. They are not decrypted and stay in
    /// the image.
    Image(AddressRange),
}

/// AES-GCM with a nonce of any non-empty length; the tag is 16 bytes.
#[derive(Debug, Clone)]
pub struct AesGcm {
    pub key: AesKey,
    pub nonce: Vec<u8>,
    /// Additional authenticated data.
    pub aad: Vec<u8>,
}

impl AesGcm {
    /// Encrypt the blocks in place and return the tag.
    pub(super) fn encrypt(&self, hexfile: &mut HexFile) -> Result<Vec<u8>, ProcessingError> {
        let blocks = hexfile.blocks();
        let stream: Vec<u8> = blocks.iter().flat_map(|b| b.data.iter().copied()).collect();
        let (output, tag) = self.run(&stream, true)?;
        hexfile.replace_blocks(&blocks, layout(&blocks, &output), Vec::new())?;
        Ok(tag.to_vec())
    }

    /// Decrypt the blocks in place, then check the tag; the image keeps the decrypted
    /// data when the tag does not match.
    pub(super) fn decrypt(
        &self,
        hexfile: &mut HexFile,
        tag: &GcmTag,
    ) -> Result<(), ProcessingError> {
        let (blocks, kept, expected) = match tag {
            GcmTag::Bytes(bytes) => (hexfile.blocks(), Vec::new(), bytes.clone()),
            GcmTag::Image(range) => {
                let (blocks, tag) = without_range(hexfile.blocks(), *range)?;
                let bytes = tag.data.clone();
                (blocks, vec![tag], bytes)
            }
        };
        let stream: Vec<u8> = blocks.iter().flat_map(|b| b.data.iter().copied()).collect();
        let (output, tag) = self.run(&stream, false)?;
        hexfile.replace_blocks(&blocks, layout(&blocks, &output), kept)?;
        if tag.as_slice() != expected.as_slice() {
            return Err(ProcessingError::TagMismatch);
        }
        Ok(())
    }

    /// The output stream and the tag over the ciphertext.
    fn run(&self, data: &[u8], encrypt: bool) -> Result<(Vec<u8>, [u8; BLOCK]), ProcessingError> {
        if self.nonce.is_empty() {
            return Err(ProcessingError::EmptyNonce);
        }
        let cipher = BlockCipher::new(&self.key);
        let mut h = [0; BLOCK];
        cipher.encrypt(&mut h);
        let ghash = || GHash::new(&h.into());
        let j0: [u8; BLOCK] = if self.nonce.len() == 12 {
            let mut j0 = [0; BLOCK];
            j0[..12].copy_from_slice(&self.nonce);
            j0[BLOCK - 1] = 1;
            j0
        } else {
            let mut hash = ghash();
            hash.update_padded(&self.nonce);
            hash.update_padded(&bit_lengths(0, self.nonce.len()));
            hash.finalize().into()
        };
        let mut counter = u128::from_be_bytes(j0);
        let mut output = data.to_vec();
        for block in output.chunks_mut(BLOCK) {
            counter = counter & !0xFFFF_FFFF | u128::from((counter as u32).wrapping_add(1));
            let mut stream = counter.to_be_bytes();
            cipher.encrypt(&mut stream);
            xor_into(block, &stream);
        }
        let ciphertext = if encrypt { &output } else { data };
        let mut hash = ghash();
        hash.update_padded(&self.aad);
        hash.update_padded(ciphertext);
        hash.update_padded(&bit_lengths(self.aad.len(), ciphertext.len()));
        let mut tag: [u8; BLOCK] = hash.finalize().into();
        let mut mask = j0;
        cipher.encrypt(&mut mask);
        xor_into(&mut tag, &mask);
        Ok((output, tag))
    }
}

/// The GHASH length block: both lengths in bits as big-endian `u64`s.
fn bit_lengths(aad: usize, data: usize) -> [u8; BLOCK] {
    let mut block = [0; BLOCK];
    block[..8].copy_from_slice(&(aad as u64 * 8).to_be_bytes());
    block[8..].copy_from_slice(&(data as u64 * 8).to_be_bytes());
    block
}

/// HexView's layout of the output stream: each block takes the output completed by the
/// end of its data, in 16-byte units, and the rest follows the last block. A block that
/// takes no output keeps its data.
fn layout(blocks: &[Segment], stream: &[u8]) -> Vec<Vec<u8>> {
    let mut outputs = Vec::with_capacity(blocks.len());
    let (mut start, mut total) = (0, 0);
    for block in blocks {
        total += block.len();
        let end = total / BLOCK * BLOCK;
        outputs.push(stream[start..end].to_vec());
        start = end;
    }
    if let (Some(output), Some(block)) = (outputs.last_mut(), blocks.last())
        && start < stream.len()
    {
        if output.is_empty() {
            output.clone_from(&block.data);
        }
        output.extend_from_slice(&stream[start..]);
    }
    outputs
}

/// The blocks without `range`, which must lie at the start or end of a block, and the
/// bytes in it.
fn without_range(
    mut blocks: Vec<Segment>,
    range: AddressRange,
) -> Result<(Vec<Segment>, Segment), ProcessingError> {
    let index = blocks
        .iter()
        .position(|b| b.start_address <= range.start() && range.end() <= b.end_address())
        .ok_or(ProcessingError::TagLocation)?;
    let block = blocks.remove(index);
    let start = (range.start() - block.start_address) as usize;
    let end = start + range.length() as usize;
    let (start_address, mut data) = block.into_parts();
    let tag = Segment::from_valid(range.start(), data[start..end].to_vec());
    let rest = if start == 0 {
        let rest = data.split_off(end);
        (!rest.is_empty()).then(|| Segment::from_valid(range.end().wrapping_add(1), rest))
    } else if end == data.len() {
        data.truncate(start);
        Some(Segment::from_valid(start_address, data))
    } else {
        return Err(ProcessingError::TagLocation);
    };
    blocks.splice(index..index, rest);
    Ok((blocks, tag))
}

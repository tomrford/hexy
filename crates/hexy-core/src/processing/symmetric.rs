//! AES in ECB, CBC and CTR mode, applied to one block at a time as HexView applies it.

use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use aes::{Aes128, Aes192, Aes256};

use super::ProcessingError;
use super::keys::AesKey;

/// The AES block size.
pub(super) const BLOCK: usize = 16;

/// AES with a key of any supported size.
pub(super) enum BlockCipher {
    Aes128(Aes128),
    Aes192(Aes192),
    Aes256(Aes256),
}

impl BlockCipher {
    pub(super) fn new(key: &AesKey) -> Self {
        let key = key.0.as_slice();
        match key.len() {
            16 => Self::Aes128(Aes128::new(GenericArray::from_slice(key))),
            24 => Self::Aes192(Aes192::new(GenericArray::from_slice(key))),
            _ => Self::Aes256(Aes256::new(GenericArray::from_slice(key))),
        }
    }

    /// Encrypt one 16-byte block in place.
    pub(super) fn encrypt(&self, block: &mut [u8]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Aes128(cipher) => cipher.encrypt_block(block),
            Self::Aes192(cipher) => cipher.encrypt_block(block),
            Self::Aes256(cipher) => cipher.encrypt_block(block),
        }
    }

    fn decrypt(&self, block: &mut [u8]) {
        let block = GenericArray::from_mut_slice(block);
        match self {
            Self::Aes128(cipher) => cipher.decrypt_block(block),
            Self::Aes192(cipher) => cipher.decrypt_block(block),
            Self::Aes256(cipher) => cipher.decrypt_block(block),
        }
    }
}

/// An AES mode for [`super::DataProcessing::Encrypt`] and
/// [`super::DataProcessing::Decrypt`].
///
/// Without an IV, CBC and CTR take the first 16 bytes of the first block as the IV:
/// those bytes stay as they are, and every block uses that IV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesMode {
    Ecb,
    Cbc {
        iv: Option<[u8; BLOCK]>,
    },
    /// A 128-bit big-endian counter that starts at the IV; after all ones it continues
    /// at one, as in HexView.
    Ctr {
        iv: Option<[u8; BLOCK]>,
    },
}

/// Padding added to each block before encryption and removed after decryption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesPadding {
    /// `n` bytes of value `n`.
    Pkcs7,
    /// `n - 1` zero bytes, then `n`.
    AnsiX923,
    /// 0x80, then zero bytes.
    Rfc1321,
}

impl AesPadding {
    /// Pad to a multiple of 16 bytes, adding a whole block to aligned data.
    fn pad(self, data: &mut Vec<u8>) {
        let n = BLOCK - data.len() % BLOCK;
        match self {
            Self::Pkcs7 => data.resize(data.len() + n, n as u8),
            Self::AnsiX923 => {
                data.resize(data.len() + n - 1, 0);
                data.push(n as u8);
            }
            Self::Rfc1321 => {
                data.push(0x80);
                data.resize(data.len() + n - 1, 0);
            }
        }
    }

    /// Remove the padding, checked as HexView checks it: a last byte of zero is PKCS #7
    /// or ANSI X.923 padding of no bytes, RFC 1321 padding must end in a zero byte (so a
    /// lone 0x80 is rejected), and padding may not make up the whole block.
    fn unpad(self, data: &mut Vec<u8>) -> Result<(), ProcessingError> {
        let len = match self {
            Self::Pkcs7 | Self::AnsiX923 => {
                let n = usize::from(*data.last().ok_or(ProcessingError::InvalidPadding)?);
                let padding = data
                    .len()
                    .checked_sub(n)
                    .filter(|_| n <= BLOCK)
                    .map(|start| &data[start..])
                    .ok_or(ProcessingError::InvalidPadding)?;
                let valid = match (self, padding.split_last()) {
                    (_, None) => true,
                    (Self::Pkcs7, Some(_)) => padding.iter().all(|&b| usize::from(b) == n),
                    (_, Some((_, zeros))) => zeros.iter().all(|&b| b == 0),
                };
                if !valid {
                    return Err(ProcessingError::InvalidPadding);
                }
                n
            }
            Self::Rfc1321 => {
                let zeros = data
                    .iter()
                    .rev()
                    .take(BLOCK)
                    .take_while(|&&b| b == 0)
                    .count();
                let marker = data.len().checked_sub(zeros + 1);
                if zeros == 0 || zeros == BLOCK || marker.is_none_or(|i| data[i] != 0x80) {
                    return Err(ProcessingError::InvalidPadding);
                }
                zeros + 1
            }
        };
        if len == data.len() {
            return Err(ProcessingError::InvalidPadding);
        }
        data.truncate(data.len() - len);
        Ok(())
    }
}

/// AES over each block in turn.
pub(super) struct AesBlocks {
    cipher: BlockCipher,
    mode: AesMode,
    padding: Option<AesPadding>,
    decrypt: bool,
    iv: Option<[u8; BLOCK]>,
}

impl AesBlocks {
    pub(super) fn new(
        key: &AesKey,
        mode: AesMode,
        padding: Option<AesPadding>,
        decrypt: bool,
    ) -> Self {
        let iv = match mode {
            AesMode::Ecb => None,
            AesMode::Cbc { iv } | AesMode::Ctr { iv } => iv,
        };
        Self {
            cipher: BlockCipher::new(key),
            mode,
            padding,
            decrypt,
            iv,
        }
    }

    /// One block's output.
    pub(super) fn process(&mut self, data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
        let mut output = Vec::new();
        let mut data = data;
        if self.mode != AesMode::Ecb && self.iv.is_none() {
            let (iv, rest) = data
                .split_first_chunk::<BLOCK>()
                .ok_or(ProcessingError::ShortIvBlock)?;
            output.extend_from_slice(iv);
            self.iv = Some(*iv);
            data = rest;
        }
        let iv = self.iv.unwrap_or_default();
        let mut data = data.to_vec();
        if self.decrypt {
            self.decrypt_data(&mut data, iv)?;
        } else {
            self.encrypt_data(&mut data, iv)?;
        }
        output.extend(data);
        Ok(output)
    }

    fn encrypt_data(&self, data: &mut Vec<u8>, iv: [u8; BLOCK]) -> Result<(), ProcessingError> {
        if let Some(padding) = self.padding {
            padding.pad(data);
        }
        match self.mode {
            AesMode::Ecb => aligned(data)?.for_each(|block| self.cipher.encrypt(block)),
            AesMode::Cbc { .. } => {
                let mut previous = iv;
                for block in aligned(data)? {
                    xor_into(block, &previous);
                    self.cipher.encrypt(block);
                    previous.copy_from_slice(block);
                }
            }
            AesMode::Ctr { .. } => self.ctr(data, iv),
        }
        Ok(())
    }

    /// HexView does not remove padding after CTR decryption.
    fn decrypt_data(&self, data: &mut Vec<u8>, iv: [u8; BLOCK]) -> Result<(), ProcessingError> {
        match self.mode {
            AesMode::Ecb => aligned(data)?.for_each(|block| self.cipher.decrypt(block)),
            AesMode::Cbc { .. } => {
                let mut previous = iv;
                for block in aligned(data)? {
                    let chain = previous;
                    previous.copy_from_slice(block);
                    self.cipher.decrypt(block);
                    xor_into(block, &chain);
                }
            }
            AesMode::Ctr { .. } => {
                self.ctr(data, iv);
                return Ok(());
            }
        }
        match self.padding {
            Some(padding) => padding.unpad(data),
            None => Ok(()),
        }
    }

    fn ctr(&self, data: &mut [u8], iv: [u8; BLOCK]) {
        let mut counter = u128::from_be_bytes(iv);
        for block in data.chunks_mut(BLOCK) {
            let mut stream = counter.to_be_bytes();
            self.cipher.encrypt(&mut stream);
            xor_into(block, &stream);
            counter = counter.checked_add(1).unwrap_or(1);
        }
    }
}

/// The 16-byte blocks of data whose length is a multiple of 16.
fn aligned(data: &mut [u8]) -> Result<std::slice::ChunksExactMut<'_, u8>, ProcessingError> {
    if !data.len().is_multiple_of(BLOCK) {
        return Err(ProcessingError::Unaligned);
    }
    Ok(data.chunks_exact_mut(BLOCK))
}

pub(super) fn xor_into(data: &mut [u8], stream: &[u8]) {
    data.iter_mut().zip(stream).for_each(|(b, s)| *b ^= s);
}

#[cfg(test)]
mod tests {
    use super::AesPadding::{AnsiX923, Pkcs7, Rfc1321};
    use super::*;

    fn unpad(padding: AesPadding, tail: &[u8]) -> Option<usize> {
        let mut data = [&[0x55; 16][..], tail].concat();
        padding.unpad(&mut data).ok().map(|()| data.len())
    }

    /// HexView 1.15.2's padding checks on `/DP3` decryption.
    #[test]
    fn test_unpad_matches_hexview() {
        assert_eq!(
            unpad(Pkcs7, &[[0x55; 15].as_slice(), &[1]].concat()),
            Some(31)
        );
        assert_eq!(unpad(Pkcs7, &[0; 16]), Some(32));
        assert_eq!(unpad(Pkcs7, &[16; 16]), Some(16));
        assert_eq!(unpad(Pkcs7, &[17; 16]), None);
        assert_eq!(
            unpad(AnsiX923, &[[0; 15].as_slice(), &[16]].concat()),
            Some(16)
        );
        assert_eq!(
            unpad(AnsiX923, &[[1].as_slice(), &[0; 14], &[16]].concat()),
            None
        );
        assert_eq!(
            unpad(Rfc1321, &[[0x80].as_slice(), &[0; 15]].concat()),
            Some(16)
        );
        assert_eq!(
            unpad(Rfc1321, &[[0x55; 14].as_slice(), &[0x80, 0]].concat()),
            Some(30)
        );
        assert_eq!(
            unpad(Rfc1321, &[[0x55; 15].as_slice(), &[0x80]].concat()),
            None
        );
        assert_eq!(unpad(Rfc1321, &[0; 16]), None);

        let mut all_padding = vec![16; 16];
        assert!(Pkcs7.unpad(&mut all_padding).is_err());
    }
}

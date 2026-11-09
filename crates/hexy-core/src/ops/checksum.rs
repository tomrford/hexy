//! Checksum algorithms for the cleanroom compatibility target.
//!
//! Cleanroom compatibility algorithm indices:
//! - 0: ByteSum 16-bit BE
//! - 1: ByteSum 16-bit LE
//! - 2: WordSum BE 16-bit (sum 16-bit BE words)
//! - 3: WordSum LE 16-bit (sum 16-bit LE words)
//! - 4: ByteSum 2's complement
//! - 5: WordSum BE 2's complement
//! - 6: WordSum LE 2's complement
//! - 7: CRC-16/USB
//! - 8: CRC-16 (non-standard)
//! - 9: CRC-32 IEEE
//! - 10: SHA-1
//! - 11: RIPEMD-160
//! - 12: WordSum LE 2's complement, BE output (GM new style)
//! - 13: CRC-16/IBM-3740, LE output
//! - 14: CRC-16/IBM-3740, BE output
//! - 15: MD5
//! - 17: CRC-16 CCITT LE init 0
//! - 18: CRC-16 CCITT BE init 0
//! - 19: SHA-512
//! - 20: SHA-256

use crc::Crc;
use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use super::{OpsError, materialized_len, pattern_bytes};
use crate::range::subtract_ranges;
use crate::{AddressRange, HexFile, Placement, Segment, merge_ranges};

const CRC16_USB: Crc<u16> = Crc::<u16>::new(&crc::CRC_16_USB);
const CRC16_IBM_3740: Crc<u16> = Crc::<u16>::new(&crc::CRC_16_IBM_3740);
const CRC16_XMODEM: Crc<u16> = Crc::<u16>::new(&crc::CRC_16_XMODEM);
const CRC32_ISO_HDLC: Crc<u32> = Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);

/// Range included in the checksum even where it holds no data; gaps take the pattern.
#[derive(Debug, Clone)]
pub struct ForcedRange {
    pub range: AddressRange,
    /// Repeating fill anchored at the range start; empty means 0xFF.
    pub pattern: Vec<u8>,
}

/// Checksum algorithm identifier (cleanroom-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[repr(u8)]
pub enum ChecksumAlgorithm {
    #[default]
    ByteSumBe = 0,
    ByteSumLe = 1,
    WordSumBe = 2,
    WordSumLe = 3,
    ByteSumTwosComplement = 4,
    WordSumBeTwosComplement = 5,
    WordSumLeTwosComplement = 6,
    Crc16Usb = 7,
    Crc16NonStandard = 8,
    Crc32 = 9,
    Sha1 = 10,
    Ripemd160 = 11,
    ModularSum = 12,
    Crc16Ibm3740Le = 13,
    Crc16Ibm3740Be = 14,
    Md5 = 15,
    Crc16CcittLeInit0 = 17,
    Crc16CcittBeInit0 = 18,
    Sha512 = 19,
    Sha256 = 20,
}

impl TryFrom<u8> for ChecksumAlgorithm {
    type Error = OpsError;

    fn try_from(index: u8) -> Result<Self, OpsError> {
        Ok(match index {
            0 => Self::ByteSumBe,
            1 => Self::ByteSumLe,
            2 => Self::WordSumBe,
            3 => Self::WordSumLe,
            4 => Self::ByteSumTwosComplement,
            5 => Self::WordSumBeTwosComplement,
            6 => Self::WordSumLeTwosComplement,
            7 => Self::Crc16Usb,
            8 => Self::Crc16NonStandard,
            9 => Self::Crc32,
            10 => Self::Sha1,
            11 => Self::Ripemd160,
            12 => Self::ModularSum,
            13 => Self::Crc16Ibm3740Le,
            14 => Self::Crc16Ibm3740Be,
            15 => Self::Md5,
            17 => Self::Crc16CcittLeInit0,
            18 => Self::Crc16CcittBeInit0,
            19 => Self::Sha512,
            20 => Self::Sha256,
            _ => return Err(OpsError::UnsupportedChecksumAlgorithm(index)),
        })
    }
}

impl ChecksumAlgorithm {
    /// Size of the checksum result in bytes.
    pub fn result_size(&self) -> usize {
        match self {
            Self::Crc32 => 4,
            Self::Sha1 | Self::Ripemd160 => 20,
            Self::Md5 => 16,
            Self::Sha256 => 32,
            Self::Sha512 => 64,
            _ => 2,
        }
    }

    /// Whether this algorithm's native output format is little-endian.
    pub fn native_little_endian(&self) -> bool {
        matches!(
            self,
            Self::ByteSumLe
                | Self::WordSumLe
                | Self::WordSumLeTwosComplement
                | Self::Crc16Ibm3740Le
                | Self::Crc16CcittLeInit0
        )
    }

    /// Word sums need every included run to start and end on a word boundary.
    fn sums_words(&self) -> bool {
        matches!(
            self,
            Self::WordSumBe
                | Self::WordSumLe
                | Self::WordSumBeTwosComplement
                | Self::WordSumLeTwosComplement
        )
    }
}

/// Options for checksum calculation.
#[derive(Debug, Clone, Default)]
pub struct ChecksumOptions {
    pub algorithm: ChecksumAlgorithm,
    pub range: Option<AddressRange>,
    /// Reverse the algorithm's native output byte order (`/CSR`).
    pub little_endian_output: bool,
    pub forced_range: Option<ForcedRange>,
    pub exclude_ranges: Vec<AddressRange>,
}

impl HexFile {
    /// Calculate checksum over the hex file data, using a normalized (last-wins) snapshot.
    ///
    /// Output byte order is the algorithm's native order, reversed when
    /// `little_endian_output` is set: `/CS1` (ByteSumLe) gives LE, `/CSR1` gives BE.
    pub fn calculate_checksum(&self, options: &ChecksumOptions) -> Result<Vec<u8>, OpsError> {
        self.checksum_excluding(options, None)
    }

    /// Calculate checksum and write it at `placement`. The bytes the checksum overwrites
    /// are excluded from the calculation.
    pub fn checksum(
        &mut self,
        options: &ChecksumOptions,
        placement: Option<Placement>,
    ) -> Result<Vec<u8>, OpsError> {
        let target = match placement {
            Some(placement) => self.placement_range(placement, options.algorithm.result_size())?,
            None => None,
        };
        let result = self.checksum_excluding(options, target)?;
        if let Some(target) = target {
            self.write_bytes(target.start(), &result)?;
        }
        Ok(result)
    }

    fn checksum_excluding(
        &self,
        options: &ChecksumOptions,
        target: Option<AddressRange>,
    ) -> Result<Vec<u8>, OpsError> {
        use ChecksumAlgorithm as A;

        let data = self.checksum_data(options, target)?;
        let little_endian = options.algorithm.native_little_endian() ^ options.little_endian_output;
        let word = |value: u16| {
            if little_endian {
                value.to_le_bytes().to_vec()
            } else {
                value.to_be_bytes().to_vec()
            }
        };
        let digest = |mut bytes: Vec<u8>| {
            if options.little_endian_output {
                bytes.reverse();
            }
            bytes
        };

        Ok(match options.algorithm {
            A::ByteSumBe | A::ByteSumLe => word(byte_sum(&data)),
            A::WordSumBe => word(word_sum(&data, u16::from_be_bytes)?),
            A::WordSumLe => word(word_sum(&data, u16::from_le_bytes)?),
            A::ByteSumTwosComplement => word(byte_twos_complement_sum(&data)),
            A::WordSumBeTwosComplement => word(word_sum(&data, u16::from_be_bytes)?.wrapping_neg()),
            // Method 12 is method 6 with BE output by default.
            A::WordSumLeTwosComplement | A::ModularSum => {
                word(word_sum(&data, u16::from_le_bytes)?.wrapping_neg())
            }
            A::Crc16Usb => word(CRC16_USB.checksum(&data)),
            A::Crc16NonStandard => word(crc16_non_standard(&data)),
            A::Crc16Ibm3740Le | A::Crc16Ibm3740Be => word(CRC16_IBM_3740.checksum(&data)),
            A::Crc16CcittLeInit0 | A::Crc16CcittBeInit0 => word(CRC16_XMODEM.checksum(&data)),
            A::Crc32 => {
                let crc = CRC32_ISO_HDLC.checksum(&data);
                if little_endian {
                    crc.to_le_bytes().to_vec()
                } else {
                    crc.to_be_bytes().to_vec()
                }
            }
            A::Sha1 => digest(Sha1::digest(&data).to_vec()),
            A::Ripemd160 => digest(Ripemd160::digest(&data).to_vec()),
            A::Md5 => digest(Md5::digest(&data).to_vec()),
            A::Sha256 => digest(Sha256::digest(&data).to_vec()),
            A::Sha512 => digest(Sha512::digest(&data).to_vec()),
        })
    }

    /// Bytes covered by the checksum: data and forced ranges, limited to `options.range`,
    /// minus the exclusions and `target`.
    fn checksum_data(
        &self,
        options: &ChecksumOptions,
        target: Option<AddressRange>,
    ) -> Result<Vec<u8>, OpsError> {
        let normalized = self.normalized();
        let forced = options.forced_range.as_ref();

        let mut domains: Vec<AddressRange> =
            normalized.segments().iter().map(Segment::range).collect();
        domains.extend(forced.map(|forced| forced.range));
        let mut excludes = options.exclude_ranges.clone();
        excludes.extend(target);
        let excludes = merge_ranges(&excludes);
        let included: Vec<AddressRange> = merge_ranges(&domains)
            .into_iter()
            .filter_map(|domain| match options.range {
                Some(limit) => domain.intersection(&limit),
                None => Some(domain),
            })
            .flat_map(|domain| subtract_ranges(domain, &excludes))
            .collect();
        let included = merge_ranges(&included);

        if options.algorithm.sums_words() {
            for range in &included {
                if !range.start().is_multiple_of(2) {
                    return Err(OpsError::AddressNotDivisible {
                        address: range.start(),
                        divisor: 2,
                    });
                }
                if !range.length().is_multiple_of(2) {
                    return Err(OpsError::LengthNotMultiple {
                        length: range.length(),
                        expected: 2,
                        operation: "checksum word range",
                    });
                }
            }
        }

        let mut data = Vec::new();
        for range in included {
            materialized_len(range)?;
            let mut next = Some(range.start());
            let segments = normalized.segments();
            let first = segments.partition_point(|s| s.end_address() < range.start());
            for segment in &segments[first..] {
                let Some(part) = segment.range().intersection(&range) else {
                    break;
                };
                if let Some(addr) = next
                    && addr < part.start()
                {
                    append_forced(
                        forced,
                        AddressRange::new_valid(addr, part.start() - 1),
                        &mut data,
                    )?;
                }
                let offset = (part.start() - segment.start_address) as usize;
                data.extend_from_slice(&segment.data[offset..offset + part.length() as usize]);
                next = part.end().checked_add(1);
            }
            if let Some(addr) = next
                && addr <= range.end()
            {
                append_forced(
                    forced,
                    AddressRange::new_valid(addr, range.end()),
                    &mut data,
                )?;
            }
        }
        Ok(data)
    }
}

/// Append the forced-range pattern for `gap`, which must lie inside the forced range.
fn append_forced(
    forced: Option<&ForcedRange>,
    gap: AddressRange,
    data: &mut Vec<u8>,
) -> Result<(), OpsError> {
    let forced = forced
        .filter(|forced| forced.range.contains(gap.start()) && forced.range.contains(gap.end()))
        .ok_or(OpsError::RangeNotCovered {
            start: gap.start(),
            length: gap.length(),
        })?;
    let pattern: &[u8] = if forced.pattern.is_empty() {
        &[0xFF]
    } else {
        &forced.pattern
    };
    let phase = (gap.start() - forced.range.start()) as usize;
    data.extend(pattern_bytes(pattern, phase, gap.length() as usize));
    Ok(())
}

/// Sum all bytes, wrapping to 16-bit.
fn byte_sum(data: &[u8]) -> u16 {
    data.iter()
        .fold(0u16, |acc, &b| acc.wrapping_add(u16::from(b)))
}

/// Sum the 8-bit two's complement of each byte, wrapping to 16-bit.
fn byte_twos_complement_sum(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |acc, &b| {
        acc.wrapping_add(u16::from(b.wrapping_neg()))
    })
}

/// Sum 16-bit words; the data must hold whole words.
fn word_sum(data: &[u8], word: fn([u8; 2]) -> u16) -> Result<u16, OpsError> {
    if !data.len().is_multiple_of(2) {
        return Err(OpsError::LengthNotMultiple {
            length: data.len() as u64,
            expected: 2,
            operation: "word sum",
        });
    }
    Ok(data
        .chunks_exact(2)
        .fold(0u16, |acc, pair| acc.wrapping_add(word([pair[0], pair[1]]))))
}

/// CRC-16 non-standard variant from compatibility-target expdatproc method 8.
fn crc16_non_standard(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &byte in data {
        crc = crc.rotate_left(8);
        crc ^= u16::from(byte);
        crc ^= (crc & 0x00FF) >> 4;
        crc ^= crc.wrapping_shl(12);
        crc ^= (crc & 0x00FF).wrapping_shl(5);
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hf(segments: &[(u32, &[u8])]) -> HexFile {
        HexFile::with_segments(
            segments
                .iter()
                .map(|(start, data)| Segment::new(*start, data.to_vec()).unwrap())
                .collect(),
        )
    }

    fn checksum(file: &HexFile, algorithm: ChecksumAlgorithm, reversed: bool) -> Vec<u8> {
        file.calculate_checksum(&ChecksumOptions {
            algorithm,
            little_endian_output: reversed,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn test_crc16_non_standard() {
        // Compatibility algorithm 8 pseudocode reference vector.
        assert_eq!(crc16_non_standard(b"123456789"), 0xD64E);
    }

    #[test]
    fn test_algorithm_output_order() {
        use ChecksumAlgorithm as A;
        let check = hf(&[(0x1000, b"123456789")]);
        let words = hf(&[(0x1000, &[0x34, 0x12, 0x78, 0x56])]);
        assert_eq!(checksum(&check, A::Crc16Usb, false), [0xB4, 0xC8]);
        assert_eq!(checksum(&check, A::Crc16Usb, true), [0xC8, 0xB4]);
        assert_eq!(checksum(&check, A::Crc32, false), [0xCB, 0xF4, 0x39, 0x26]);
        assert_eq!(checksum(&check, A::Crc32, true), [0x26, 0x39, 0xF4, 0xCB]);
        assert_eq!(checksum(&check, A::Crc16Ibm3740Le, false), [0xB1, 0x29]);
        assert_eq!(checksum(&check, A::Crc16Ibm3740Be, false), [0x29, 0xB1]);
        assert_eq!(checksum(&check, A::Crc16CcittLeInit0, false), [0xC3, 0x31]);
        assert_eq!(checksum(&check, A::Crc16CcittBeInit0, false), [0x31, 0xC3]);
        assert_eq!(checksum(&words, A::WordSumLe, false), [0xAC, 0x68]);
        assert_eq!(checksum(&words, A::WordSumBe, false), [0xAC, 0x68]);
        assert_eq!(
            checksum(&words, A::WordSumLeTwosComplement, false),
            [0x54, 0x97]
        );
        assert_eq!(checksum(&words, A::ModularSum, false), [0x97, 0x54]);
        assert_eq!(
            checksum(&words, A::ByteSumTwosComplement, false),
            [0x02, 0xEC]
        );
        assert_eq!(checksum(&HexFile::new(), A::Crc32, false), [0, 0, 0, 0]);
    }

    #[test]
    fn test_digest_reversed_for_csr() {
        let abc = hf(&[(0x1000, b"abc")]);
        let sha1 = checksum(&abc, ChecksumAlgorithm::Sha1, false);
        assert_eq!(&sha1[..4], &[0xA9, 0x99, 0x3E, 0x36]);
        let mut reversed = checksum(&abc, ChecksumAlgorithm::Sha1, true);
        reversed.reverse();
        assert_eq!(reversed, sha1);
    }

    #[test]
    fn test_word_sum_rejects_misaligned_runs() {
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::WordSumBe,
            ..Default::default()
        };
        assert!(matches!(
            hf(&[(0x1001, &[0xAA, 0xBB])]).calculate_checksum(&options),
            Err(OpsError::AddressNotDivisible {
                address: 0x1001,
                divisor: 2
            })
        ));
        assert!(matches!(
            hf(&[(0x1000, &[0xAA, 0xBB, 0xCC])]).calculate_checksum(&options),
            Err(OpsError::LengthNotMultiple { length: 3, .. })
        ));
    }

    #[test]
    fn test_modular_sum_rejects_odd_total_length() {
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ModularSum,
            ..Default::default()
        };
        assert!(matches!(
            hf(&[(0x1000, &[0x01, 0x02, 0x03])]).calculate_checksum(&options),
            Err(OpsError::LengthNotMultiple { length: 3, .. })
        ));
    }

    #[test]
    fn test_range_and_exclusions() {
        let file = hf(&[(0x1000, &[0x01, 0x02, 0x03, 0x04])]);
        let options = ChecksumOptions {
            range: Some(AddressRange::from_start_end(0x1000, 0x1002).unwrap()),
            exclude_ranges: vec![AddressRange::from_start_end(0x1001, 0x1001).unwrap()],
            ..Default::default()
        };
        assert_eq!(file.calculate_checksum(&options).unwrap(), [0x00, 0x04]);
    }

    #[test]
    fn test_forced_range_fills_gaps_with_anchored_pattern() {
        let file = hf(&[(0x1000, &[0x10]), (0x1003, &[0x20]), (0x2000, &[0x02])]);
        let options = ChecksumOptions {
            forced_range: Some(ForcedRange {
                range: AddressRange::from_start_end(0x1000, 0x1005).unwrap(),
                pattern: vec![0x01, 0x02],
            }),
            exclude_ranges: vec![AddressRange::from_start_end(0x1004, 0x1004).unwrap()],
            ..Default::default()
        };
        // 0x10, pattern 02 01, 0x20, 0x1004 excluded, pattern 02, then 0x02 at 0x2000
        assert_eq!(file.calculate_checksum(&options).unwrap(), [0x00, 0x37]);
    }

    #[test]
    fn test_large_forced_range_applies_exclusions_before_collecting() {
        let options = ChecksumOptions {
            forced_range: Some(ForcedRange {
                range: AddressRange::from_start_end(0, u32::MAX - 1).unwrap(),
                pattern: vec![0xAB, 0xCD],
            }),
            exclude_ranges: vec![AddressRange::from_start_end(1, u32::MAX - 2).unwrap()],
            ..Default::default()
        };
        assert_eq!(
            HexFile::new().calculate_checksum(&options).unwrap(),
            [0x01, 0x56]
        );
    }

    #[test]
    fn test_placement_excludes_target_and_writes_result() {
        let mut file = hf(&[(0x1000, &[0x01, 0x02, 0x03, 0x04])]);
        let options = ChecksumOptions::default();
        assert_eq!(
            file.checksum(&options, Some(Placement::OverwriteEnd))
                .unwrap(),
            [0x00, 0x03]
        );
        assert_eq!(
            file.checksum(&options, Some(Placement::Append)).unwrap(),
            [0x00, 0x06]
        );
        assert_eq!(
            file.read_bytes_contiguous(0x1000, 6).unwrap(),
            [0x01, 0x02, 0x00, 0x03, 0x00, 0x06]
        );
    }

    #[test]
    fn test_placement_overflow_leaves_file_unchanged() {
        let options = ChecksumOptions::default();
        for (mut file, placement) in [
            (hf(&[(0x1000, &[0x01])]), Placement::Address(u32::MAX)),
            (hf(&[(0x0, &[0x01])]), Placement::Prepend),
        ] {
            let before = file.clone();
            assert!(matches!(
                file.checksum(&options, Some(placement)),
                Err(OpsError::AddressOverflow { .. })
            ));
            assert_eq!(file, before);
        }
    }

    #[test]
    fn test_algorithm_try_from_index() {
        assert_eq!(
            ChecksumAlgorithm::try_from(12).unwrap(),
            ChecksumAlgorithm::ModularSum
        );
        assert!(ChecksumAlgorithm::try_from(16).is_err());
        assert!(ChecksumAlgorithm::try_from(21).is_err());
    }
}

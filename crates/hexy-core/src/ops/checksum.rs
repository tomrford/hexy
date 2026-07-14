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

use std::path::PathBuf;

use md5::Md5;
use ripemd::Ripemd160;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use super::filter::materialized_range_len;
use crate::{AddressRange, HexFile, OpsError, merge_ranges};

/// Target for checksum output.
#[derive(Debug, Clone)]
pub enum ChecksumTarget {
    /// Calculate without writing checksum bytes.
    None,
    /// Write to address in hex file
    Address(u32),
    /// Append after last data
    Append,
    /// Prepend before first data
    Prepend,
    /// Write at end, overwriting existing data
    OverwriteEnd,
    /// Write to external file
    File(PathBuf),
}

/// Forced range for checksum calculation, with fill pattern.
#[derive(Debug, Clone)]
pub struct ForcedRange {
    pub range: AddressRange,
    pub pattern: Vec<u8>,
}

/// Checksum algorithm identifier (cleanroom-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ChecksumAlgorithm {
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

impl ChecksumAlgorithm {
    pub fn from_index(index: u8) -> Result<Self, OpsError> {
        match index {
            0 => Ok(Self::ByteSumBe),
            1 => Ok(Self::ByteSumLe),
            2 => Ok(Self::WordSumBe),
            3 => Ok(Self::WordSumLe),
            4 => Ok(Self::ByteSumTwosComplement),
            5 => Ok(Self::WordSumBeTwosComplement),
            6 => Ok(Self::WordSumLeTwosComplement),
            7 => Ok(Self::Crc16Usb),
            8 => Ok(Self::Crc16NonStandard),
            9 => Ok(Self::Crc32),
            10 => Ok(Self::Sha1),
            11 => Ok(Self::Ripemd160),
            12 => Ok(Self::ModularSum),
            13 => Ok(Self::Crc16Ibm3740Le),
            14 => Ok(Self::Crc16Ibm3740Be),
            15 => Ok(Self::Md5),
            17 => Ok(Self::Crc16CcittLeInit0),
            18 => Ok(Self::Crc16CcittBeInit0),
            19 => Ok(Self::Sha512),
            20 => Ok(Self::Sha256),
            _ => Err(OpsError::UnsupportedChecksumAlgorithm(index)),
        }
    }

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
    /// Algorithms ending in "LE" or "Le" output little-endian by default.
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
}

/// Options for checksum calculation.
#[derive(Debug, Clone)]
pub struct ChecksumOptions {
    pub algorithm: ChecksumAlgorithm,
    pub range: Option<AddressRange>,
    pub little_endian_output: bool,
    pub forced_range: Option<ForcedRange>,
    pub exclude_ranges: Vec<AddressRange>,
    /// When set, this address range is excluded from the checksum calculation.
    /// Used internally when the checksum target is an address within the data.
    pub target_exclude: Option<AddressRange>,
}

/// One checksum operation in a sequential checksum chain.
#[derive(Debug, Clone)]
pub struct ChecksumJob {
    pub options: ChecksumOptions,
    pub target: ChecksumTarget,
}

impl Default for ChecksumOptions {
    fn default() -> Self {
        Self {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: None,
            little_endian_output: false,
            forced_range: None,
            exclude_ranges: Vec::new(),
            target_exclude: None,
        }
    }
}

impl HexFile {
    /// Calculate checksum over the hex file data.
    /// Returns the checksum bytes in the specified endianness.
    /// Uses a normalized (last-wins) snapshot for overlap resolution.
    ///
    /// Output byte order is determined by:
    /// - The algorithm's native format (e.g., ByteSumLe = LE, ByteSumBe = BE)
    /// - XOR'd with `little_endian_output` (true when /CSR is used)
    ///
    /// Example: /CS1 = ByteSumLe (native LE), little_endian_output=false -> LE
    ///          /CSR1 = ByteSumLe (native LE), little_endian_output=true -> BE
    pub fn calculate_checksum(&self, options: &ChecksumOptions) -> Result<Vec<u8>, OpsError> {
        let data = self.collect_data_for_checksum(options)?;

        // Effective endianness: algorithm's native XOR reversed flag
        // /CS uses algorithm's native format, /CSR inverts it
        let use_le = options.algorithm.native_little_endian() ^ options.little_endian_output;

        fn u16_bytes(value: u16, little_endian: bool) -> Vec<u8> {
            if little_endian {
                value.to_le_bytes().to_vec()
            } else {
                value.to_be_bytes().to_vec()
            }
        }

        fn u32_bytes(value: u32, little_endian: bool) -> Vec<u8> {
            if little_endian {
                value.to_le_bytes().to_vec()
            } else {
                value.to_be_bytes().to_vec()
            }
        }

        fn reverse_if_requested(mut value: Vec<u8>, reverse: bool) -> Vec<u8> {
            if reverse {
                value.reverse();
            }
            value
        }

        let result = match options.algorithm {
            ChecksumAlgorithm::ByteSumBe | ChecksumAlgorithm::ByteSumLe => {
                let sum = byte_sum(&data);
                u16_bytes(sum, use_le)
            }
            ChecksumAlgorithm::WordSumBe => {
                let sum = word_sum_be(&data)?;
                u16_bytes(sum, use_le)
            }
            ChecksumAlgorithm::WordSumLe => {
                let sum = word_sum_le(&data)?;
                u16_bytes(sum, use_le)
            }
            ChecksumAlgorithm::ByteSumTwosComplement => {
                u16_bytes(byte_twos_complement_sum(&data), use_le)
            }
            ChecksumAlgorithm::WordSumBeTwosComplement => {
                let sum = word_sum_be(&data)?;
                let twos = (!sum).wrapping_add(1);
                u16_bytes(twos, use_le)
            }
            ChecksumAlgorithm::WordSumLeTwosComplement => {
                let sum = word_sum_le(&data)?;
                let twos = (!sum).wrapping_add(1);
                u16_bytes(twos, use_le)
            }
            ChecksumAlgorithm::ModularSum => {
                // Compatibility method 12: same arithmetic as method 6, but BE output by default.
                let sum = word_sum_le(&data)?;
                let twos = (!sum).wrapping_add(1);
                u16_bytes(twos, use_le)
            }
            ChecksumAlgorithm::Crc16NonStandard => {
                let crc = crc16_non_standard(&data);
                u16_bytes(crc, use_le)
            }
            ChecksumAlgorithm::Sha1 => {
                reverse_if_requested(Sha1::digest(&data).to_vec(), options.little_endian_output)
            }
            ChecksumAlgorithm::Ripemd160 => reverse_if_requested(
                Ripemd160::digest(&data).to_vec(),
                options.little_endian_output,
            ),
            ChecksumAlgorithm::Md5 => {
                reverse_if_requested(Md5::digest(&data).to_vec(), options.little_endian_output)
            }
            ChecksumAlgorithm::Sha256 => {
                reverse_if_requested(Sha256::digest(&data).to_vec(), options.little_endian_output)
            }
            ChecksumAlgorithm::Sha512 => {
                reverse_if_requested(Sha512::digest(&data).to_vec(), options.little_endian_output)
            }
            ChecksumAlgorithm::Crc16Usb => {
                let crc = crc16_usb(&data);
                u16_bytes(crc, use_le)
            }
            ChecksumAlgorithm::Crc32 => {
                let crc = crc32_iso_hdlc(&data);
                u32_bytes(crc, use_le)
            }
            ChecksumAlgorithm::Crc16Ibm3740Le | ChecksumAlgorithm::Crc16Ibm3740Be => {
                let crc = crc16_ibm_3740(&data);
                u16_bytes(crc, use_le)
            }
            ChecksumAlgorithm::Crc16CcittLeInit0 | ChecksumAlgorithm::Crc16CcittBeInit0 => {
                let crc = crc16_xmodem(&data);
                u16_bytes(crc, use_le)
            }
        };

        Ok(result)
    }

    /// Calculate checksum and write to target.
    pub fn checksum(
        &mut self,
        options: &ChecksumOptions,
        target: &ChecksumTarget,
    ) -> Result<Vec<u8>, OpsError> {
        // When target overwrites existing data, exclude that range from checksum.
        // This matches compatibility behavior where the checksum target is not included.
        let mut effective_options = options.clone();
        let size = options.algorithm.result_size() as u32;
        match target {
            ChecksumTarget::Address(addr) => {
                let target_range = AddressRange::from_start_length(*addr, u64::from(size))
                    .map_err(|_| {
                        OpsError::AddressOverflow(format!(
                            "checksum target at {addr:#X} with size {size} overflows u32"
                        ))
                    })?;
                if target_range.extends_past_address_space() {
                    return Err(OpsError::AddressOverflow(format!(
                        "checksum target at {addr:#X} with size {size} overflows u32"
                    )));
                }
                effective_options.target_exclude = Some(target_range);
            }
            ChecksumTarget::OverwriteEnd => {
                // Overwrite end writes at (max_address - size + 1)
                if let Some(end) = self.max_address() {
                    let offset = size.saturating_sub(1);
                    if let Some(write_addr) = end.checked_sub(offset)
                        && let Ok(target_range) =
                            AddressRange::from_start_length(write_addr, u64::from(size))
                        && !target_range.extends_past_address_space()
                    {
                        effective_options.target_exclude = Some(target_range);
                    }
                }
            }
            ChecksumTarget::Append => {
                if let Some(end) = self.max_address() {
                    let write_addr = end.checked_add(1).ok_or_else(|| {
                        OpsError::AddressOverflow("checksum append overflows u32".into())
                    })?;
                    let target_range =
                        AddressRange::from_start_length(write_addr, u64::from(size)).map_err(
                            |_| {
                                OpsError::AddressOverflow(format!(
                                    "checksum append target at {write_addr:#X} with size {size} overflows u32"
                                ))
                            },
                        )?;
                    if target_range.extends_past_address_space() {
                        return Err(OpsError::AddressOverflow(format!(
                            "checksum append target at {write_addr:#X} with size {size} overflows u32"
                        )));
                    }
                    effective_options.target_exclude = Some(target_range);
                }
            }
            ChecksumTarget::Prepend => {
                if let Some(start) = self.min_address() {
                    let write_addr = start.checked_sub(size).ok_or_else(|| {
                        OpsError::AddressOverflow("checksum prepend underflows u32".into())
                    })?;
                    let target_range =
                        AddressRange::from_start_length(write_addr, u64::from(size)).map_err(
                            |_| {
                                OpsError::AddressOverflow(format!(
                                    "checksum prepend target at {write_addr:#X} with size {size} overflows u32"
                                ))
                            },
                        )?;
                    if target_range.extends_past_address_space() {
                        return Err(OpsError::AddressOverflow(format!(
                            "checksum prepend target at {write_addr:#X} with size {size} overflows u32"
                        )));
                    }
                    effective_options.target_exclude = Some(target_range);
                }
            }
            _ => {}
        }
        let result = self.calculate_checksum(&effective_options)?;

        match target {
            ChecksumTarget::Address(addr) => {
                self.write_bytes(*addr, &result)?;
            }
            ChecksumTarget::Append => {
                if let Some(end) = self.max_address() {
                    let addr = end.checked_add(1).ok_or_else(|| {
                        OpsError::AddressOverflow("checksum append overflows u32".into())
                    })?;
                    self.write_bytes(addr, &result)?;
                }
            }
            ChecksumTarget::Prepend => {
                if let Some(start) = self.min_address() {
                    let new_start = start.checked_sub(result.len() as u32).ok_or_else(|| {
                        OpsError::AddressOverflow("checksum prepend underflows u32".into())
                    })?;
                    self.write_bytes(new_start, &result)?;
                }
            }
            ChecksumTarget::OverwriteEnd => {
                if let Some(end) = self.max_address() {
                    // Write checksum to overwrite the last N bytes
                    // For N bytes ending at `end`, start address is `end - (N - 1)`
                    let offset = (result.len() as u32).saturating_sub(1);
                    let write_addr = end.checked_sub(offset).ok_or_else(|| {
                        OpsError::AddressOverflow("checksum overwrite underflows u32".into())
                    })?;
                    self.write_bytes(write_addr, &result)?;
                }
            }
            ChecksumTarget::None | ChecksumTarget::File(_) => {
                // File output is handled by caller; None is calculation only.
            }
        }

        Ok(result)
    }

    /// Execute checksum jobs in order against the evolving HexFile state.
    pub fn checksum_many_sequential(
        &mut self,
        jobs: &[ChecksumJob],
    ) -> Result<Vec<Vec<u8>>, OpsError> {
        let mut out = Vec::with_capacity(jobs.len());
        for job in jobs {
            out.push(self.checksum(&job.options, &job.target)?);
        }
        Ok(out)
    }

    /// Collect contiguous data for checksum calculation.
    /// If a range is specified, only include data in that range.
    fn collect_data_for_checksum(&self, options: &ChecksumOptions) -> Result<Vec<u8>, OpsError> {
        let normalized = self.normalized();
        let needs_word_alignment = matches!(
            options.algorithm,
            ChecksumAlgorithm::WordSumBe
                | ChecksumAlgorithm::WordSumLe
                | ChecksumAlgorithm::WordSumBeTwosComplement
                | ChecksumAlgorithm::WordSumLeTwosComplement
        );

        let mut excludes = options.exclude_ranges.clone();
        if let Some(target) = options.target_exclude {
            excludes.push(target);
        }
        let excludes = merge_ranges(&excludes);
        let include_ranges = checksum_include_ranges(&normalized, options, &excludes);
        if include_ranges.is_empty() {
            return Ok(Vec::new());
        }

        let mut cap_u64: u64 = 0;
        for range in &include_ranges {
            cap_u64 = cap_u64.saturating_add(
                u64::try_from(materialized_range_len(*range, "checksum range")?).map_err(|_| {
                    OpsError::AddressOverflow("checksum range length exceeds u64".to_owned())
                })?,
            );
        }

        let cap = usize::try_from(cap_u64).map_err(|_| {
            let start = include_ranges.first().map_or(0, AddressRange::start);
            let end = include_ranges.last().map_or(0, AddressRange::end);
            OpsError::AddressOverflow(format!(
                "checksum range length exceeds usize (start={:#X}, end={:#X})",
                start, end
            ))
        })?;

        let mut data = Vec::with_capacity(cap);

        let finalize_run = |run_start: u32, run_len: usize| -> Result<(), OpsError> {
            if !needs_word_alignment {
                return Ok(());
            }
            if !run_start.is_multiple_of(2) {
                return Err(OpsError::AddressNotDivisible {
                    address: run_start,
                    divisor: 2,
                });
            }
            if !run_len.is_multiple_of(2) {
                return Err(OpsError::LengthNotMultiple {
                    length: run_len,
                    expected: 2,
                    operation: "checksum word range".to_owned(),
                });
            }
            Ok(())
        };

        for range in &include_ranges {
            let run_len = materialized_range_len(*range, "checksum range")?;
            finalize_run(range.start(), run_len)?;
        }

        let mut seg_idx = 0usize;
        for range in include_ranges {
            append_checksum_range(
                &normalized,
                options.forced_range.as_ref(),
                range,
                &mut seg_idx,
                &mut data,
            )?;
        }

        Ok(data)
    }
}

fn checksum_include_ranges(
    normalized: &HexFile,
    options: &ChecksumOptions,
    excludes: &[AddressRange],
) -> Vec<AddressRange> {
    let mut domains: Vec<AddressRange> = normalized
        .segments()
        .iter()
        .filter_map(|segment| {
            AddressRange::from_start_end(segment.start_address, segment.end_address()).ok()
        })
        .collect();

    if let Some(forced) = options.forced_range.as_ref() {
        domains.push(forced.range);
    }

    let domains = merge_ranges(&domains)
        .into_iter()
        .filter_map(|range| {
            if let Some(limit) = options.range {
                range.intersection(&limit)
            } else {
                Some(range)
            }
        })
        .collect::<Vec<_>>();

    let mut include_ranges = Vec::new();
    for domain in domains {
        include_ranges.extend(subtract_ranges(domain, excludes));
    }
    merge_ranges(&include_ranges)
}

fn append_checksum_range(
    normalized: &HexFile,
    forced_range: Option<&ForcedRange>,
    range: AddressRange,
    seg_idx: &mut usize,
    data: &mut Vec<u8>,
) -> Result<(), OpsError> {
    let segments = normalized.segments();
    let mut addr = range.start();

    while addr <= range.end() {
        while *seg_idx < segments.len() && segments[*seg_idx].end_address() < addr {
            *seg_idx += 1;
        }

        if let Some(segment) = segments.get(*seg_idx)
            && segment.start_address <= addr
        {
            let end = segment.end_address().min(range.end());
            let offset = (addr - segment.start_address) as usize;
            let len = (end - addr + 1) as usize;
            data.extend_from_slice(&segment.data[offset..offset + len]);
            if segment.end_address() <= end {
                *seg_idx += 1;
            }
            let Some(next) = end.checked_add(1) else {
                break;
            };
            addr = next;
            continue;
        }

        let Some(forced) = forced_range.filter(|forced| forced.range.contains(addr)) else {
            return Err(OpsError::RangeNotCovered {
                start: addr,
                length: u64::from(range.end() - addr + 1),
            });
        };

        let mut end = forced.range.end().min(range.end());
        if let Some(segment) = segments.get(*seg_idx)
            && segment.start_address > addr
        {
            end = end.min(segment.start_address - 1);
        }
        append_forced_pattern_bytes(forced, addr, end, data)?;
        let Some(next) = end.checked_add(1) else {
            break;
        };
        addr = next;
    }

    Ok(())
}

fn append_forced_pattern_bytes(
    forced: &ForcedRange,
    start: u32,
    end: u32,
    data: &mut Vec<u8>,
) -> Result<(), OpsError> {
    let fill_pattern: &[u8] = if forced.pattern.is_empty() {
        &[0xFF]
    } else {
        &forced.pattern
    };
    let base_offset = start - forced.range.start();
    let len = usize::try_from(end - start + 1).map_err(|_| {
        OpsError::AddressOverflow(format!(
            "forced range length exceeds usize (start={start:#X}, end={end:#X})"
        ))
    })?;
    for i in 0..len {
        let pattern_idx = ((base_offset as usize) + i) % fill_pattern.len();
        data.push(fill_pattern[pattern_idx]);
    }
    Ok(())
}

fn subtract_ranges(range: AddressRange, excludes: &[AddressRange]) -> Vec<AddressRange> {
    if excludes.is_empty() {
        return vec![range];
    }
    let mut out: Vec<AddressRange> = Vec::new();
    let mut cursor = range.start();
    for ex in excludes {
        if ex.end() < cursor {
            continue;
        }
        if ex.start() > range.end() {
            break;
        }
        let ex_start = ex.start().max(range.start());
        let ex_end = ex.end().min(range.end());
        if cursor < ex_start
            && let Ok(r) = AddressRange::from_start_end(cursor, ex_start - 1)
        {
            out.push(r);
        }
        if ex_end == u32::MAX {
            return out;
        }
        cursor = ex_end + 1;
        if cursor > range.end() {
            return out;
        }
    }
    if cursor <= range.end()
        && let Ok(r) = AddressRange::from_start_end(cursor, range.end())
    {
        out.push(r);
    }
    out
}

/// Sum all bytes, wrapping to 16-bit.
fn byte_sum(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |acc, &b| acc.wrapping_add(b as u16))
}

/// Sum the 8-bit two's complement of each byte, wrapping to 16-bit.
fn byte_twos_complement_sum(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |acc, &byte| {
        acc.wrapping_add(byte.wrapping_neg() as u16)
    })
}

/// Sum 16-bit big-endian words.
fn word_sum_be(data: &[u8]) -> Result<u16, OpsError> {
    if !data.len().is_multiple_of(2) {
        return Err(OpsError::LengthNotMultiple {
            length: data.len(),
            expected: 2,
            operation: "word sum BE".to_owned(),
        });
    }
    Ok(data.chunks_exact(2).fold(0u16, |acc, chunk| {
        acc.wrapping_add(u16::from_be_bytes([chunk[0], chunk[1]]))
    }))
}

/// Sum 16-bit little-endian words.
fn word_sum_le(data: &[u8]) -> Result<u16, OpsError> {
    if !data.len().is_multiple_of(2) {
        return Err(OpsError::LengthNotMultiple {
            length: data.len(),
            expected: 2,
            operation: "word sum LE".to_owned(),
        });
    }
    Ok(data.chunks_exact(2).fold(0u16, |acc, chunk| {
        acc.wrapping_add(u16::from_le_bytes([chunk[0], chunk[1]]))
    }))
}

/// CRC-16/USB.
fn crc16_usb(data: &[u8]) -> u16 {
    const CRC: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_USB);
    CRC.checksum(data)
}

/// CRC-16 non-standard variant from compatibility-target expdatproc method 8.
fn crc16_non_standard(data: &[u8]) -> u16 {
    let mut crc = 0xFFFFu16;
    for &byte in data {
        crc = crc.rotate_left(8);
        crc ^= byte as u16;
        crc ^= (crc & 0x00FF) >> 4;
        crc ^= crc.wrapping_shl(12);
        crc ^= (crc & 0x00FF).wrapping_shl(5);
    }
    !crc
}

/// CRC-32 IEEE (ISO-HDLC).
fn crc32_iso_hdlc(data: &[u8]) -> u32 {
    const CRC: crc::Crc<u32> = crc::Crc::<u32>::new(&crc::CRC_32_ISO_HDLC);
    CRC.checksum(data)
}

/// CRC-16/IBM-3740.
fn crc16_ibm_3740(data: &[u8]) -> u16 {
    const CRC: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_IBM_3740);
    CRC.checksum(data)
}

/// CRC-16 CCITT with init 0 (XMODEM).
fn crc16_xmodem(data: &[u8]) -> u16 {
    const CRC: crc::Crc<u16> = crc::Crc::<u16>::new(&crc::CRC_16_XMODEM);
    CRC.checksum(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    #[test]
    fn test_byte_sum() {
        assert_eq!(byte_sum(&[0x01, 0x02, 0x03, 0x04]), 0x000A);
        assert_eq!(byte_sum(&[0xFF, 0xFF]), 0x01FE);
        assert_eq!(byte_sum(&[]), 0);
    }

    #[test]
    fn test_byte_sum_overflow() {
        // 257 * 0xFF = 65535 = 0xFFFF (max u16)
        let data = vec![0xFF; 257];
        assert_eq!(byte_sum(&data), 0xFFFF);

        // Test actual wrapping: 258 * 0xFF = 65790, wraps to 65790 - 65536 = 254 = 0x00FE
        let data2 = vec![0xFF; 258];
        assert_eq!(byte_sum(&data2), 0x00FE);
    }

    #[test]
    fn test_byte_twos_complement_sum() {
        assert_eq!(byte_twos_complement_sum(&[0x01, 0x02]), 0x01FD);
        assert_eq!(byte_twos_complement_sum(&[0x00, 0x80, 0xFF]), 0x0081);
        assert_eq!(byte_twos_complement_sum(&[]), 0);
    }

    #[test]
    fn test_word_sum_be() {
        assert_eq!(word_sum_be(&[0x00, 0x01, 0x00, 0x02]).unwrap(), 0x0003);
        assert_eq!(word_sum_be(&[0x12, 0x34, 0x56, 0x78]).unwrap(), 0x68AC);
    }

    #[test]
    fn test_word_sum_le() {
        assert_eq!(word_sum_le(&[0x01, 0x00, 0x02, 0x00]).unwrap(), 0x0003);
        assert_eq!(word_sum_le(&[0x34, 0x12, 0x78, 0x56]).unwrap(), 0x68AC);
    }

    #[test]
    fn test_word_sum_odd_length() {
        assert!(word_sum_be(&[0x01, 0x02, 0x03]).is_err());
        assert!(word_sum_le(&[0x01]).is_err());
    }

    #[test]
    fn test_checksum_word_sum_odd_start_rejects() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA, 0xBB])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::WordSumBe,
            ..ChecksumOptions::default()
        };
        let result = hf.calculate_checksum(&options);
        assert!(matches!(
            result,
            Err(OpsError::AddressNotDivisible {
                address: 0x1001,
                divisor: 2
            })
        ));
    }

    #[test]
    fn test_checksum_word_sum_odd_length_rejects() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::WordSumLe,
            ..ChecksumOptions::default()
        };
        let result = hf.calculate_checksum(&options);
        assert!(matches!(
            result,
            Err(OpsError::LengthNotMultiple {
                length: 3,
                expected: 2,
                ..
            })
        ));
    }

    #[test]
    fn test_twos_complement() {
        let sum: u16 = 0x1234;
        let twos = (!sum).wrapping_add(1);
        assert_eq!(twos, 0xEDCC);
        assert_eq!(sum.wrapping_add(twos), 0);
    }

    #[test]
    fn test_crc16_usb() {
        assert_eq!(crc16_usb(b"123456789"), 0xB4C8);
    }

    #[test]
    fn test_crc16_non_standard() {
        // Compatibility algorithm 8 pseudocode reference vector.
        assert_eq!(crc16_non_standard(b"123456789"), 0xD64E);
    }

    #[test]
    fn test_crc32_iso_hdlc() {
        // Known test vector: "123456789" -> 0xCBF43926
        assert_eq!(crc32_iso_hdlc(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn test_crc16_xmodem() {
        // Known test vector: "123456789" -> 0x31C3
        assert_eq!(crc16_xmodem(b"123456789"), 0x31C3);
    }

    #[test]
    fn test_crc16_ibm_3740() {
        assert_eq!(crc16_ibm_3740(b"123456789"), 0x29B1);
    }

    #[test]
    fn test_hexfile_checksum_byte_sum() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02, 0x03, 0x04])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0x00, 0x0A]);
    }

    #[test]
    fn test_hexfile_checksum_byte_twos_complement_sum() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumTwosComplement,
            ..Default::default()
        };

        assert_eq!(hf.calculate_checksum(&options).unwrap(), vec![0x01, 0xFD]);
    }

    #[test]
    fn test_hexfile_checksum_crc32() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"123456789".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc32,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0xCB, 0xF4, 0x39, 0x26]);
    }

    #[test]
    fn test_hexfile_checksum_crc32_le() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"123456789".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc32,
            range: None,
            little_endian_output: true,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0x26, 0x39, 0xF4, 0xCB]);
    }

    #[test]
    fn test_hexfile_checksum_with_range() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02, 0x03, 0x04])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: Some(AddressRange::from_start_end(0x1001, 0x1002).unwrap()),
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        // Only 0x02 + 0x03 = 0x05
        assert_eq!(result, vec![0x00, 0x05]);
    }

    #[test]
    fn test_hexfile_checksum_append() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        hf.checksum(&options, &ChecksumTarget::Append).unwrap();

        let norm = hf.normalized();
        assert_eq!(norm.max_address(), Some(0x1003));
    }

    #[test]
    fn test_hexfile_checksum_append_overflow() {
        let mut hf = HexFile::with_segments(vec![Segment::new(u32::MAX - 1, vec![0x01, 0x02])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.checksum(&options, &ChecksumTarget::Append);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
    }

    #[test]
    fn test_hexfile_checksum_fixed_target_overflow() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.checksum(&options, &ChecksumTarget::Address(u32::MAX));
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
        assert_eq!(hf.segments(), &[Segment::new(0x1000, vec![0x01])]);
    }

    #[test]
    fn test_hexfile_checksum_prepend_underflow() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x0, vec![0x01])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.checksum(&options, &ChecksumTarget::Prepend);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
    }

    #[test]
    fn test_hexfile_checksum_overwrite_underflow() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x0, vec![0x01])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.checksum(&options, &ChecksumTarget::OverwriteEnd);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
    }

    #[test]
    fn test_hexfile_checksum_overwrite_end() {
        // Data at 0x1000-0x1003 (4 bytes), checksum is 2 bytes
        // OverwriteEnd should write at 0x1002-0x1003, excluding those bytes from calculation
        // Sum of 0x01 + 0x02 = 0x03, BE = [0x00, 0x03]
        let mut hf =
            HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02, 0x03, 0x04])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        hf.checksum(&options, &ChecksumTarget::OverwriteEnd)
            .unwrap();

        let norm = hf.normalized();
        assert_eq!(norm.segments().len(), 1);
        assert_eq!(norm.min_address(), Some(0x1000));
        assert_eq!(norm.max_address(), Some(0x1003)); // Same end address
        // First two bytes unchanged, last two overwritten with checksum (0x0003)
        assert_eq!(norm.segments()[0].data, vec![0x01, 0x02, 0x00, 0x03]);
    }

    #[test]
    fn test_hexfile_checksum_overwrite_end_crc32() {
        // Data at 0x1000-0x1007 (8 bytes), CRC32 is 4 bytes
        // OverwriteEnd should write at 0x1004-0x1007
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 8])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc32,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        hf.checksum(&options, &ChecksumTarget::OverwriteEnd)
            .unwrap();

        let norm = hf.normalized();
        assert_eq!(norm.min_address(), Some(0x1000));
        assert_eq!(norm.max_address(), Some(0x1007)); // Same end address
        // First 4 bytes unchanged
        assert_eq!(&norm.segments()[0].data[..4], &[0xAA, 0xAA, 0xAA, 0xAA]);
    }

    #[test]
    fn test_algorithm_from_index() {
        assert!(ChecksumAlgorithm::from_index(0).is_ok());
        assert!(ChecksumAlgorithm::from_index(9).is_ok());
        assert!(ChecksumAlgorithm::from_index(8).is_ok());
        assert!(ChecksumAlgorithm::from_index(10).is_ok());
        assert!(ChecksumAlgorithm::from_index(11).is_ok());
        assert!(ChecksumAlgorithm::from_index(15).is_ok());
        assert!(ChecksumAlgorithm::from_index(19).is_ok());
        assert!(ChecksumAlgorithm::from_index(20).is_ok());
        assert!(ChecksumAlgorithm::from_index(21).is_err());
    }

    #[test]
    fn test_algorithm_result_size() {
        assert_eq!(ChecksumAlgorithm::Crc32.result_size(), 4);
        assert_eq!(ChecksumAlgorithm::ByteSumBe.result_size(), 2);
        assert_eq!(ChecksumAlgorithm::Crc16Usb.result_size(), 2);
        assert_eq!(ChecksumAlgorithm::Sha1.result_size(), 20);
        assert_eq!(ChecksumAlgorithm::Ripemd160.result_size(), 20);
        assert_eq!(ChecksumAlgorithm::Md5.result_size(), 16);
        assert_eq!(ChecksumAlgorithm::Sha256.result_size(), 32);
        assert_eq!(ChecksumAlgorithm::Sha512.result_size(), 64);
    }

    #[test]
    fn test_crc16_usb_empty() {
        assert_eq!(crc16_usb(&[]), 0x0000);
    }

    #[test]
    fn test_crc32_iso_hdlc_empty() {
        assert_eq!(crc32_iso_hdlc(&[]), 0x00000000);
    }

    #[test]
    fn test_crc16_xmodem_empty() {
        assert_eq!(crc16_xmodem(&[]), 0x0000);
    }

    #[test]
    fn test_hexfile_checksum_crc16() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"123456789".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc16Usb,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0xB4, 0xC8]);
    }

    #[test]
    fn test_hexfile_checksum_crc16_le() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"123456789".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc16Usb,
            range: None,
            little_endian_output: true,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0xC8, 0xB4]);
    }

    #[test]
    fn test_hexfile_checksum_crc16_ibm_3740_le() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"123456789".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc16Ibm3740Le,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0xB1, 0x29]);
    }

    #[test]
    fn test_hexfile_checksum_crc16_ibm_3740_be() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"123456789".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc16Ibm3740Be,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0x29, 0xB1]);
    }

    #[test]
    fn test_hexfile_checksum_crc16_ccitt_le_init_0() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"123456789".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc16CcittLeInit0,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        // CRC-16 XMODEM: 0x31C3, output forced LE
        assert_eq!(result, vec![0xC3, 0x31]);
    }

    #[test]
    fn test_hexfile_checksum_crc16_ccitt_be_init_0() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"123456789".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc16CcittBeInit0,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        // CRC-16 XMODEM: 0x31C3, output forced BE
        assert_eq!(result, vec![0x31, 0xC3]);
    }

    #[test]
    fn test_hexfile_checksum_crc_empty_data() {
        let hf = HexFile::new();
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc32,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn test_hexfile_checksum_crc16_with_range() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"0123456789".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Crc16Usb,
            range: Some(AddressRange::from_start_end(0x1001, 0x1009).unwrap()),
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        // AddressRange extracts "123456789"
        assert_eq!(result, vec![0xB4, 0xC8]);
    }

    #[test]
    fn test_hexfile_checksum_forced_range_fill() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: None,
            little_endian_output: false,
            forced_range: Some(ForcedRange {
                range: AddressRange::from_start_end(0x1000, 0x1003).unwrap(),
                pattern: vec![0xFF],
            }),
            exclude_ranges: Vec::new(),
            target_exclude: None,
        };
        let result = hf.calculate_checksum(&options).unwrap();
        // Compatibility: forced range gaps are filled by the requested pattern.
        assert_eq!(result, vec![0x02, 0x01]);
    }

    #[test]
    fn test_hexfile_checksum_forced_range_keeps_real_data_outside_range() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01]),
            Segment::new(0x2000, vec![0x02]),
        ]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            forced_range: Some(ForcedRange {
                range: AddressRange::from_start_end(0x1000, 0x1001).unwrap(),
                pattern: vec![0xFF],
            }),
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0x01, 0x02]);
    }

    #[test]
    fn test_hexfile_checksum_forced_range_excludes_virtual_bytes() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x10]),
            Segment::new(0x2000, vec![0x02]),
        ]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            forced_range: Some(ForcedRange {
                range: AddressRange::from_start_end(0x1000, 0x100F).unwrap(),
                pattern: vec![0x01],
            }),
            exclude_ranges: vec![AddressRange::from_start_end(0x1001, 0x100E).unwrap()],
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0x00, 0x13]);
    }

    #[test]
    fn test_hexfile_checksum_large_forced_range_applies_exclusions_before_collecting() {
        let hf = HexFile::new();
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            forced_range: Some(ForcedRange {
                range: AddressRange::from_start_end(0, u32::MAX - 1).unwrap(),
                pattern: vec![0xAB, 0xCD],
            }),
            exclude_ranges: vec![AddressRange::from_start_end(1, u32::MAX - 2).unwrap()],
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0x01, 0x56]);
    }

    #[test]
    fn test_hexfile_checksum_exclude_ranges() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02, 0x03, 0x04])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ByteSumBe,
            range: Some(AddressRange::from_start_end(0x1000, 0x1003).unwrap()),
            little_endian_output: false,
            forced_range: None,
            exclude_ranges: vec![AddressRange::from_start_end(0x1001, 0x1002).unwrap()],
            target_exclude: None,
        };
        let result = hf.calculate_checksum(&options).unwrap();
        // 0x01 + 0x04 = 0x05
        assert_eq!(result, vec![0x00, 0x05]);
    }

    #[test]
    fn test_hexfile_checksum_many_sequential_uses_updated_state() {
        let mut hf =
            HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02, 0x03, 0x04])]);
        let jobs = vec![
            ChecksumJob {
                options: ChecksumOptions {
                    algorithm: ChecksumAlgorithm::ByteSumBe,
                    ..Default::default()
                },
                target: ChecksumTarget::Address(0x1000),
            },
            ChecksumJob {
                options: ChecksumOptions {
                    algorithm: ChecksumAlgorithm::ByteSumBe,
                    ..Default::default()
                },
                target: ChecksumTarget::Append,
            },
        ];
        let results = hf.checksum_many_sequential(&jobs).unwrap();
        assert_eq!(results, vec![vec![0x00, 0x07], vec![0x00, 0x0E]]);
        let norm = hf.normalized();
        assert_eq!(
            norm.read_bytes_contiguous(0x1000, 6).unwrap(),
            vec![0x00, 0x07, 0x03, 0x04, 0x00, 0x0E]
        );
    }

    #[test]
    fn test_hexfile_checksum_method12_matches_wordsum_le_twos_complement_be() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x34, 0x12, 0x78, 0x56])]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::ModularSum,
            range: None,
            little_endian_output: false,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(result, vec![0x97, 0x54]);
    }

    #[test]
    fn test_hexfile_checksum_sha1() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"abc".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Sha1,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(
            result,
            vec![
                0xA9, 0x99, 0x3E, 0x36, 0x47, 0x06, 0x81, 0x6A, 0xBA, 0x3E, 0x25, 0x71, 0x78, 0x50,
                0xC2, 0x6C, 0x9C, 0xD0, 0xD8, 0x9D
            ]
        );
    }

    #[test]
    fn test_hexfile_checksum_sha1_reversed_for_csr() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"abc".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Sha1,
            little_endian_output: true,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(
            result,
            vec![
                0x9D, 0xD8, 0xD0, 0x9C, 0x6C, 0xC2, 0x50, 0x78, 0x71, 0x25, 0x3E, 0xBA, 0x6A, 0x81,
                0x06, 0x47, 0x36, 0x3E, 0x99, 0xA9
            ]
        );
    }

    #[test]
    fn test_hexfile_checksum_ripemd160() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"abc".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Ripemd160,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(
            result,
            vec![
                0x8E, 0xB2, 0x08, 0xF7, 0xE0, 0x5D, 0x98, 0x7A, 0x9B, 0x04, 0x4A, 0x8E, 0x98, 0xC6,
                0xB0, 0x87, 0xF1, 0x5A, 0x0B, 0xFC
            ]
        );
    }

    #[test]
    fn test_hexfile_checksum_md5() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"abc".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Md5,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(
            result,
            vec![
                0x90, 0x01, 0x50, 0x98, 0x3C, 0xD2, 0x4F, 0xB0, 0xD6, 0x96, 0x3F, 0x7D, 0x28, 0xE1,
                0x7F, 0x72
            ]
        );
    }

    #[test]
    fn test_hexfile_checksum_sha256() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"abc".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Sha256,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(
            result,
            vec![
                0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE,
                0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61,
                0xF2, 0x00, 0x15, 0xAD
            ]
        );
    }

    #[test]
    fn test_hexfile_checksum_sha512() {
        let hf = HexFile::with_segments(vec![Segment::new(0x1000, b"abc".to_vec())]);
        let options = ChecksumOptions {
            algorithm: ChecksumAlgorithm::Sha512,
            ..Default::default()
        };
        let result = hf.calculate_checksum(&options).unwrap();
        assert_eq!(
            result,
            vec![
                0xDD, 0xAF, 0x35, 0xA1, 0x93, 0x61, 0x7A, 0xBA, 0xCC, 0x41, 0x73, 0x49, 0xAE, 0x20,
                0x41, 0x31, 0x12, 0xE6, 0xFA, 0x4E, 0x89, 0xA9, 0x7E, 0xA2, 0x0A, 0x9E, 0xEE, 0xE6,
                0x4B, 0x55, 0xD3, 0x9A, 0x21, 0x92, 0x99, 0x2A, 0x27, 0x4F, 0xC1, 0xA8, 0x36, 0xBA,
                0x3C, 0x23, 0xA3, 0xFE, 0xEB, 0xBD, 0x45, 0x4D, 0x44, 0x23, 0x64, 0x3C, 0xE8, 0x0E,
                0x2A, 0x9A, 0xC9, 0x4F, 0xA5, 0x4C, 0xA4, 0x9F
            ]
        );
    }
}

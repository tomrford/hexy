use super::OpsError;
use crate::{AddressRange, HexFile, Segment};

/// Mode for byte swapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwapMode {
    /// Swap pairs: AA BB → BB AA
    Word,
    /// Swap quads: AA BB CC DD → DD CC BB AA
    DWord,
}

/// Options for alignment operations.
#[derive(Debug, Clone)]
pub struct AlignOptions {
    /// Must be non-zero
    pub alignment: u32,
    /// Byte to use for padding (default 0xFF)
    pub fill_byte: u8,
    /// Also align segment lengths
    pub align_length: bool,
}

impl Default for AlignOptions {
    fn default() -> Self {
        Self {
            alignment: 4,
            fill_byte: 0xFF,
            align_length: false,
        }
    }
}

/// Options for address remapping of banked memory layouts.
#[derive(Debug, Clone)]
pub struct RemapOptions {
    pub start: u32,
    pub end: u32,
    pub linear: u32,
    pub size: u32,
    pub inc: u32,
}

/// Options for banked address mapping.
#[derive(Debug, Clone)]
pub struct BankedMapOptions {
    pub bank_min: u8,
    pub bank_max: u8,
    pub linear_base: u32,
    pub nonbank_low_base: u32,
    pub nonbank_high_base: u32,
}

fn is_valid_alignment(n: u32) -> bool {
    n != 0
}

fn align_down(addr: u32, alignment: u32) -> u32 {
    addr - (addr % alignment)
}

fn align_up(len: u32, alignment: u32) -> u32 {
    let rem = len % alignment;
    if rem == 0 {
        len
    } else {
        len.checked_add(alignment - rem).unwrap_or(len)
    }
}

impl HexFile {
    /// Align all segment start addresses to multiples of alignment.
    /// Prepends fill bytes as needed. Optionally aligns lengths too.
    /// Fill bytes are LOW priority (existing data wins on overlap).
    pub fn align(&mut self, options: &AlignOptions) -> Result<(), OpsError> {
        if !is_valid_alignment(options.alignment) {
            return Err(OpsError::InvalidAlignment(options.alignment));
        }

        // Work on a normalized snapshot to merge any existing overlaps
        let normalized = self.normalized();
        let mut result = HexFile::new();

        // First, add fill segments as LOW priority (prepend = loses on overlap)
        for segment in normalized.segments() {
            let aligned_start = align_down(segment.start_address, options.alignment);

            if aligned_start < segment.start_address {
                // Create fill segment for the alignment gap
                let fill_len = (segment.start_address - aligned_start) as usize;
                let fill_data = vec![options.fill_byte; fill_len];
                result.prepend_segment(Segment::new(aligned_start, fill_data));
            }

            if options.align_length {
                let end_addr = segment.end_address().saturating_add(1);
                let aligned_end = align_up(end_addr, options.alignment);
                if aligned_end > end_addr {
                    // Create fill segment for length alignment
                    let fill_len = (aligned_end - end_addr) as usize;
                    let fill_data = vec![options.fill_byte; fill_len];
                    result.prepend_segment(Segment::new(end_addr, fill_data));
                }
            }
        }

        // Then add original data as HIGH priority (append = wins on overlap)
        for segment in normalized.into_segments() {
            result.append_segment(segment);
        }

        // Normalize to merge fill with data (original data wins on overlap)
        self.set_segments(result.normalized().into_segments());
        Ok(())
    }

    /// Split any segment larger than max_size into multiple segments (operates on raw segments).
    pub fn split(&mut self, max_size: u32) {
        if max_size == 0 {
            return;
        }

        let mut new_segments: Vec<Segment> = Vec::new();
        let max_size_usize = max_size as usize;

        for segment in self.take_segments() {
            if segment.len() <= max_size_usize {
                new_segments.push(segment);
                continue;
            }

            let mut addr = segment.start_address;
            for chunk in segment.data.chunks(max_size_usize) {
                new_segments.push(Segment::new(addr, chunk.to_vec()));
                addr += chunk.len() as u32;
            }
        }

        self.set_segments(new_segments);
    }

    /// Swap bytes within all segments (operates on raw segments).
    /// Compatibility parity:
    /// - SWAPWORD: no-op if any segment starts on an odd address or total byte count is odd.
    /// - SWAPLONG: no-op if span start or span length is not a multiple of 4.
    pub fn swap_bytes(&mut self, mode: SwapMode) -> Result<(), OpsError> {
        match mode {
            SwapMode::Word => {
                let total_len: usize = self.segments().iter().map(|s| s.len()).sum();
                if !total_len.is_multiple_of(2) {
                    return Ok(());
                }
                if self.segments().iter().any(|s| s.start_address % 2 != 0) {
                    return Ok(());
                }

                for segment in self.segments_mut() {
                    for chunk in segment.data.chunks_exact_mut(2) {
                        chunk.reverse();
                    }
                }
            }
            SwapMode::DWord => {
                const SWAPLONG_LARGE_SPAN_LIMIT: usize = 0x1000000;
                let Some(span_start) = self.segments().iter().map(|s| s.start_address).min() else {
                    return Ok(());
                };
                let Some(span_end) = self.segments().iter().map(|s| s.end_address()).max() else {
                    return Ok(());
                };
                let span_len = span_end
                    .checked_sub(span_start)
                    .and_then(|v| v.checked_add(1))
                    .ok_or_else(|| {
                        OpsError::AddressOverflow("swaplong span length overflows u32".into())
                    })?;
                if span_start % 4 != 0 || span_len % 4 != 0 {
                    return Ok(());
                }

                if self.segments().len() == 1 {
                    let segment = &mut self.segments_mut()[0];
                    if segment.start_address == span_start && segment.len() == span_len as usize {
                        // Compatibility quirk: large single spans repeat the first swapped word.
                        if segment.len() >= SWAPLONG_LARGE_SPAN_LIMIT {
                            if segment.data.len() < 4 {
                                return Ok(());
                            }
                            let mut word = [
                                segment.data[0],
                                segment.data[1],
                                segment.data[2],
                                segment.data[3],
                            ];
                            word.reverse();
                            for chunk in segment.data.chunks_exact_mut(4) {
                                chunk.copy_from_slice(&word);
                            }
                            return Ok(());
                        }
                        for chunk in segment.data.chunks_exact_mut(4) {
                            chunk.reverse();
                        }
                        return Ok(());
                    }
                }

                let mut data_map: std::collections::HashMap<u32, u8> =
                    std::collections::HashMap::new();
                for segment in self.segments() {
                    for (offset, &byte) in segment.data.iter().enumerate() {
                        let Some(addr) = segment.start_address.checked_add(offset as u32) else {
                            return Err(OpsError::AddressOverflow(format!(
                                "swaplong address overflow (start={:#X}, offset={})",
                                segment.start_address, offset
                            )));
                        };
                        data_map.insert(addr, byte);
                    }
                }

                let mut updates: std::collections::HashMap<u32, u8> =
                    std::collections::HashMap::new();
                let mut last_full: Option<[u8; 4]> = None;

                let mut addr = span_start;
                while addr <= span_end {
                    if !data_map.contains_key(&addr) {
                        if let Some(next) = addr.checked_add(4) {
                            addr = next;
                            continue;
                        }
                        break;
                    }

                    let mut word = [0u8; 4];
                    let mut all_present = true;
                    for i in 0..4 {
                        let Some(a) = addr.checked_add(i as u32) else {
                            return Err(OpsError::AddressOverflow(
                                "swaplong address overflow".into(),
                            ));
                        };
                        if let Some(byte) = data_map.get(&a) {
                            word[i] = *byte;
                        } else {
                            all_present = false;
                            if let Some(last) = last_full {
                                word[i] = last[i];
                            } else {
                                word[i] = 0x00;
                            }
                        }
                    }

                    if all_present {
                        last_full = Some(word);
                    }

                    let mut swapped = word;
                    swapped.reverse();
                    for (i, &byte) in swapped.iter().enumerate() {
                        let Some(a) = addr.checked_add(i as u32) else {
                            return Err(OpsError::AddressOverflow(
                                "swaplong address overflow".into(),
                            ));
                        };
                        if data_map.contains_key(&a) {
                            updates.insert(a, byte);
                        }
                    }

                    if let Some(next) = addr.checked_add(4) {
                        addr = next;
                    } else {
                        break;
                    }
                }

                for segment in self.segments_mut() {
                    for (offset, byte) in segment.data.iter_mut().enumerate() {
                        let Some(addr) = segment.start_address.checked_add(offset as u32) else {
                            return Err(OpsError::AddressOverflow(format!(
                                "swaplong address overflow (start={:#X}, offset={})",
                                segment.start_address, offset
                            )));
                        };
                        if let Some(updated) = updates.get(&addr) {
                            *byte = *updated;
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Expand dsPIC-like data: 2 bytes -> 4 bytes (appends two zero bytes).
    /// Copies data to the target address (default: source_start * 2).
    pub fn dspic_expand(
        &mut self,
        range: AddressRange,
        target: Option<u32>,
    ) -> Result<(), OpsError> {
        let length = range.length() as usize;
        if !length.is_multiple_of(2) {
            return Err(OpsError::LengthNotMultiple {
                length,
                expected: 2,
                operation: format!("/CDSPX range {:#X}-{:#X}", range.start(), range.end()),
            });
        }

        let src =
            self.read_bytes_contiguous(range.start(), length)
                .ok_or(OpsError::RangeNotCovered {
                    start: range.start(),
                    length: range.length(),
                })?;

        let mut out = Vec::with_capacity(length * 2);
        for chunk in src.chunks_exact(2) {
            out.extend_from_slice(chunk);
            out.extend_from_slice(&[0x00, 0x00]);
        }

        let target = match target {
            Some(addr) => addr,
            None => range
                .start()
                .checked_mul(2)
                .ok_or_else(|| OpsError::AddressOverflow("dspic expand target overflow".into()))?,
        };
        self.write_bytes(target, &out);
        Ok(())
    }

    /// Shrink dsPIC-like data: 4 bytes -> 2 bytes (keeps lower two bytes).
    /// Copies data to the target address (default: source_start / 2).
    pub fn dspic_shrink(
        &mut self,
        range: AddressRange,
        target: Option<u32>,
    ) -> Result<(), OpsError> {
        let length = range.length() as usize;
        if !length.is_multiple_of(4) {
            return Err(OpsError::LengthNotMultiple {
                length,
                expected: 4,
                operation: format!("/CDSPS range {:#X}-{:#X}", range.start(), range.end()),
            });
        }
        if target.is_none() && !range.start().is_multiple_of(2) {
            return Err(OpsError::AddressNotDivisible {
                address: range.start(),
                divisor: 2,
            });
        }

        let src =
            self.read_bytes_contiguous(range.start(), length)
                .ok_or(OpsError::RangeNotCovered {
                    start: range.start(),
                    length: range.length(),
                })?;

        let mut out = Vec::with_capacity(length / 2);
        for chunk in src.chunks_exact(4) {
            out.extend_from_slice(&chunk[0..2]);
        }

        let target = target.unwrap_or(range.start() / 2);
        self.write_bytes(target, &out);
        Ok(())
    }

    /// Clear dsPIC ghost bytes: set highest byte in each 4-byte group to 0.
    pub fn dspic_clear_ghost(&mut self, range: AddressRange) -> Result<(), OpsError> {
        let length = range.length() as usize;
        if !length.is_multiple_of(4) {
            return Err(OpsError::LengthNotMultiple {
                length,
                expected: 4,
                operation: format!("/CDSPG range {:#X}-{:#X}", range.start(), range.end()),
            });
        }

        let mut data =
            self.read_bytes_contiguous(range.start(), length)
                .ok_or(OpsError::RangeNotCovered {
                    start: range.start(),
                    length: range.length(),
                })?;

        for chunk in data.chunks_exact_mut(4) {
            chunk[3] = 0x00;
        }

        self.write_bytes(range.start(), &data);
        Ok(())
    }

    /// Multiply all addresses by factor. Errors if any address would overflow.
    /// If validation fails, no segments are modified (transactional).
    pub fn scale_addresses(&mut self, factor: u32) -> Result<(), OpsError> {
        // First pass: validate all addresses
        for segment in self.segments() {
            let new_start = segment.start_address.checked_mul(factor).ok_or_else(|| {
                OpsError::AddressOverflow(format!(
                    "{:#X} * {} overflows u32",
                    segment.start_address, factor
                ))
            })?;

            if segment.is_empty() {
                continue;
            }

            let length = u32::try_from(segment.len()).map_err(|_| {
                OpsError::AddressOverflow(format!(
                    "segment length {} exceeds u32 range",
                    segment.len()
                ))
            })?;
            AddressRange::from_start_length(new_start, length).map_err(|_| {
                OpsError::AddressOverflow(format!(
                    "{:#X} * {} with length {} exceeds u32 range",
                    segment.start_address,
                    factor,
                    segment.len()
                ))
            })?;
        }

        // Second pass: apply mutation
        for segment in self.segments_mut() {
            segment.start_address *= factor;
        }

        Ok(())
    }

    /// Divide all addresses by divisor. Errors if any address not evenly divisible.
    /// If validation fails, no segments are modified (transactional).
    pub fn unscale_addresses(&mut self, divisor: u32) -> Result<(), OpsError> {
        if divisor == 0 {
            return Err(OpsError::AddressNotDivisible {
                address: 0,
                divisor: 0,
            });
        }

        // First pass: validate all addresses
        for segment in self.segments() {
            if segment.start_address % divisor != 0 {
                return Err(OpsError::AddressNotDivisible {
                    address: segment.start_address,
                    divisor,
                });
            }
        }

        // Second pass: apply mutation
        for segment in self.segments_mut() {
            segment.start_address /= divisor;
        }

        Ok(())
    }

    /// Remap banked address ranges into a linear space.
    pub fn remap(&mut self, options: &RemapOptions) -> Result<(), OpsError> {
        if options.size == 0 || options.inc == 0 {
            return Err(OpsError::InvalidRemapParams(format!(
                "size and increment must be non-zero (size={}, inc={})",
                options.size, options.inc
            )));
        }
        if options.start > options.end {
            return Err(OpsError::InvalidRemapParams(format!(
                "start must be <= end (start={:#X}, end={:#X})",
                options.start, options.end
            )));
        }

        for segment in self.segments_mut() {
            let seg_start = segment.start_address;
            let seg_end = segment.end_address();

            if seg_start < options.start || seg_end > options.end {
                continue;
            }

            let offset = seg_start - options.start;
            let bank_index = offset / options.inc;
            let bank_base = options
                .start
                .checked_add(bank_index.checked_mul(options.inc).ok_or_else(|| {
                    OpsError::AddressOverflow(format!(
                        "bank base overflows (start={:#X}, inc={}, bank_index={})",
                        options.start, options.inc, bank_index
                    ))
                })?)
                .ok_or_else(|| {
                    OpsError::AddressOverflow(format!(
                        "bank base overflows (start={:#X}, inc={}, bank_index={})",
                        options.start, options.inc, bank_index
                    ))
                })?;
            let bank_end = bank_base.checked_add(options.size - 1).ok_or_else(|| {
                OpsError::AddressOverflow(format!(
                    "bank end overflows (bank_base={:#X}, size={})",
                    bank_base, options.size
                ))
            })?;

            if seg_end > bank_end {
                continue;
            }

            let bank_offset = seg_start - bank_base;
            let new_start = options
                .linear
                .checked_add(bank_index.checked_mul(options.size).ok_or_else(|| {
                    OpsError::AddressOverflow(format!(
                        "linear base overflows (linear={:#X}, bank_index={}, size={})",
                        options.linear, bank_index, options.size
                    ))
                })?)
                .and_then(|v| v.checked_add(bank_offset))
                .ok_or_else(|| {
                    OpsError::AddressOverflow(format!(
                        "linear address overflows (linear={:#X}, bank_offset={:#X})",
                        options.linear, bank_offset
                    ))
                })?;

            segment.start_address = new_start;
        }

        Ok(())
    }

    /// Map banked address ranges into a linear space.
    pub fn map_banked(&mut self, options: &BankedMapOptions) -> Result<(), OpsError> {
        if options.bank_min > options.bank_max {
            return Err(OpsError::InvalidRemapParams(format!(
                "bank_min must be <= bank_max (bank_min={}, bank_max={})",
                options.bank_min, options.bank_max
            )));
        }

        for segment in self.segments_mut() {
            let start = segment.start_address;
            let end = segment.end_address();

            if start >= 0x4000 && end <= 0x7FFF {
                let offset = start - 0x4000;
                segment.start_address =
                    options
                        .nonbank_low_base
                        .checked_add(offset)
                        .ok_or_else(|| {
                            OpsError::AddressOverflow(format!(
                                "non-banked low map overflow (base={:#X}, start={:#X})",
                                options.nonbank_low_base, start
                            ))
                        })?;
                continue;
            }
            if start >= 0xC000 && end <= 0xFFFF {
                let offset = start - 0xC000;
                segment.start_address =
                    options
                        .nonbank_high_base
                        .checked_add(offset)
                        .ok_or_else(|| {
                            OpsError::AddressOverflow(format!(
                                "non-banked high map overflow (base={:#X}, start={:#X})",
                                options.nonbank_high_base, start
                            ))
                        })?;
                continue;
            }

            let bank = (start >> 16) as u8;
            if bank < options.bank_min || bank > options.bank_max {
                continue;
            }

            let bank_base = ((bank as u32) << 16) + 0x8000;
            let bank_end = bank_base + 0x3FFF;
            if end > bank_end {
                continue;
            }

            let bank_index = (bank - options.bank_min) as u32;
            let linear_bank_base = options
                .linear_base
                .checked_add(bank_index.checked_mul(0x4000).ok_or_else(|| {
                    OpsError::AddressOverflow(format!(
                        "bank base overflow (linear={:#X}, bank_index={})",
                        options.linear_base, bank_index
                    ))
                })?)
                .ok_or_else(|| {
                    OpsError::AddressOverflow(format!(
                        "bank base overflow (linear={:#X}, bank_index={})",
                        options.linear_base, bank_index
                    ))
                })?;
            segment.start_address =
                linear_bank_base
                    .checked_add(start - bank_base)
                    .ok_or_else(|| {
                        OpsError::AddressOverflow(format!(
                            "bank map overflow (linear={:#X}, start={:#X})",
                            options.linear_base, start
                        ))
                    })?;
        }

        Ok(())
    }

    pub fn map_star12(&mut self) -> Result<(), OpsError> {
        self.map_banked(&BankedMapOptions {
            bank_min: 0x30,
            bank_max: 0x3F,
            linear_base: 0x0C0000,
            nonbank_low_base: 0x0F8000,
            nonbank_high_base: 0x0FC000,
        })
    }

    pub fn map_star12x(&mut self) -> Result<(), OpsError> {
        self.map_banked(&BankedMapOptions {
            bank_min: 0xE0,
            bank_max: 0xFF,
            linear_base: 0x780000,
            nonbank_low_base: 0x7F4000,
            nonbank_high_base: 0x7FC000,
        })
    }

    pub fn map_star08(&mut self) -> Result<(), OpsError> {
        for segment in self.segments_mut() {
            let start = segment.start_address;
            let end = segment.end_address();

            if start >= 0x4000 && end <= 0x7FFF {
                let offset = start - 0x4000;
                segment.start_address = 0x104000u32.checked_add(offset).ok_or_else(|| {
                    OpsError::AddressOverflow(format!(
                        "star08 low map overflow (start={:#X})",
                        start
                    ))
                })?;
                continue;
            }

            let bank = (start >> 16) as u8;
            let bank_base = ((bank as u32) << 16) + 0x8000;
            let bank_end = bank_base + 0x3FFF;
            if start < bank_base || end > bank_end {
                continue;
            }

            let linear_bank_base = 0x100000u32
                .checked_add((bank as u32).checked_mul(0x4000).ok_or_else(|| {
                    OpsError::AddressOverflow(format!("star08 bank base overflow (bank={})", bank))
                })?)
                .ok_or_else(|| {
                    OpsError::AddressOverflow(format!("star08 bank base overflow (bank={})", bank))
                })?;
            segment.start_address =
                linear_bank_base
                    .checked_add(start - bank_base)
                    .ok_or_else(|| {
                        OpsError::AddressOverflow(format!(
                            "star08 bank map overflow (start={:#X})",
                            start
                        ))
                    })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_prepends_fill() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA, 0xBB])]);
        hf.align(&AlignOptions {
            alignment: 4,
            fill_byte: 0xFF,
            align_length: false,
        })
        .unwrap();

        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(hf.segments()[0].data, vec![0xFF, 0xAA, 0xBB]);
    }

    #[test]
    fn test_align_with_length() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA, 0xBB])]);
        hf.align(&AlignOptions {
            alignment: 4,
            fill_byte: 0xFF,
            align_length: true,
        })
        .unwrap();

        assert_eq!(hf.segments()[0].start_address, 0x1000);
        // 1 prepended + 2 data + 1 appended = 4
        assert_eq!(hf.segments()[0].len(), 4);
        assert_eq!(hf.segments()[0].data, vec![0xFF, 0xAA, 0xBB, 0xFF]);
    }

    #[test]
    fn test_align_already_aligned() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 8])]);
        hf.align(&AlignOptions {
            alignment: 4,
            fill_byte: 0xFF,
            align_length: true,
        })
        .unwrap();

        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(hf.segments()[0].len(), 8);
    }

    #[test]
    fn test_align_invalid_alignment() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA])]);
        let result = hf.align(&AlignOptions {
            alignment: 0,
            fill_byte: 0xFF,
            align_length: false,
        });
        assert!(matches!(result, Err(OpsError::InvalidAlignment(0))));
    }

    #[test]
    fn test_align_non_power_of_two() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB])]);
        hf.align(&AlignOptions {
            alignment: 3,
            fill_byte: 0xEE,
            align_length: true,
        })
        .unwrap();

        assert_eq!(hf.segments()[0].start_address, 0x0FFF);
        assert_eq!(hf.segments()[0].data, vec![0xEE, 0xAA, 0xBB]);
    }

    #[test]
    fn test_split_segments() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 10])]);
        hf.split(4);

        assert_eq!(hf.segments().len(), 3);
        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(hf.segments()[0].len(), 4);
        assert_eq!(hf.segments()[1].start_address, 0x1004);
        assert_eq!(hf.segments()[1].len(), 4);
        assert_eq!(hf.segments()[2].start_address, 0x1008);
        assert_eq!(hf.segments()[2].len(), 2);
    }

    #[test]
    fn test_swap_word() {
        let mut hf =
            HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD])]);
        hf.swap_bytes(SwapMode::Word).unwrap();

        assert_eq!(hf.segments()[0].data, vec![0xBB, 0xAA, 0xDD, 0xCC]);
    }

    #[test]
    fn test_swap_dword() {
        let mut hf =
            HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD])]);
        hf.swap_bytes(SwapMode::DWord).unwrap();

        assert_eq!(hf.segments()[0].data, vec![0xDD, 0xCC, 0xBB, 0xAA]);
    }

    #[test]
    fn test_swap_dword_large_span_repeats_first_word() {
        let mut data = vec![0xAA; 0x1000000];
        data[0..4].copy_from_slice(&[0x01, 0x02, 0x03, 0x04]);
        let mut hf = HexFile::with_segments(vec![Segment::new(0x0, data)]);
        hf.swap_bytes(SwapMode::DWord).unwrap();

        let seg = &hf.segments()[0].data;
        assert_eq!(&seg[0..4], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&seg[4..8], &[0x04, 0x03, 0x02, 0x01]);
        assert_eq!(&seg[seg.len() - 4..], &[0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn test_swap_odd_length_leaves_trailing() {
        // Compatibility target: odd total length => no-op
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC])]);
        hf.swap_bytes(SwapMode::Word).unwrap();

        assert_eq!(hf.segments()[0].data, vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn test_scale_addresses() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA]),
            Segment::new(0x2000, vec![0xBB]),
        ]);
        hf.scale_addresses(2).unwrap();

        assert_eq!(hf.segments()[0].start_address, 0x2000);
        assert_eq!(hf.segments()[1].start_address, 0x4000);
    }

    #[test]
    fn test_unscale_addresses() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x2000, vec![0xAA]),
            Segment::new(0x4000, vec![0xBB]),
        ]);
        hf.unscale_addresses(2).unwrap();

        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(hf.segments()[1].start_address, 0x2000);
    }

    #[test]
    fn test_unscale_not_divisible() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA])]);
        let result = hf.unscale_addresses(2);

        assert!(matches!(
            result,
            Err(OpsError::AddressNotDivisible {
                address: 0x1001,
                divisor: 2
            })
        ));
    }

    // --- Edge case tests ---

    #[test]
    fn test_align_causes_overlap() {
        // Two segments that will both align to 0x1000
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1001, vec![0xAA]),
            Segment::new(0x1003, vec![0xBB]),
        ]);
        hf.align(&AlignOptions {
            alignment: 4,
            fill_byte: 0xFF,
            align_length: false,
        })
        .unwrap();

        // Align now resolves overlaps internally with original data winning
        // Result: single segment 0x1000-0x1003 with [0xFF, 0xAA, 0xFF, 0xBB]
        // (fill at 0x1000, data at 0x1001, fill at 0x1002, data at 0x1003)
        assert_eq!(hf.segments().len(), 1);
        let seg = &hf.segments()[0];
        assert_eq!(seg.start_address, 0x1000);
        assert_eq!(seg.data, vec![0xFF, 0xAA, 0xFF, 0xBB]);
    }

    #[test]
    fn test_align_with_alignment_1() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA, 0xBB])]);
        hf.align(&AlignOptions {
            alignment: 1,
            fill_byte: 0xFF,
            align_length: true,
        })
        .unwrap();
        // No change expected
        assert_eq!(hf.segments()[0].start_address, 0x1001);
        assert_eq!(hf.segments()[0].len(), 2);
    }

    #[test]
    fn test_split_zero_size_noop() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 10])]);
        hf.split(0);
        assert_eq!(hf.segments().len(), 1);
    }

    #[test]
    fn test_split_larger_than_segment() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 4])]);
        hf.split(100);
        assert_eq!(hf.segments().len(), 1);
    }

    #[test]
    fn test_swap_multiple_segments() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02]),
            Segment::new(0x2000, vec![0x03, 0x04]),
        ]);
        hf.swap_bytes(SwapMode::Word).unwrap();
        assert_eq!(hf.segments()[0].data, vec![0x02, 0x01]);
        assert_eq!(hf.segments()[1].data, vec![0x04, 0x03]);
    }

    #[test]
    fn test_swap_dword_larger_buffer() {
        let mut hf = HexFile::with_segments(vec![Segment::new(
            0x1000,
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08],
        )]);
        hf.swap_bytes(SwapMode::DWord).unwrap();
        assert_eq!(
            hf.segments()[0].data,
            vec![0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05]
        );
    }

    #[test]
    fn test_swap_word_odd_start_noop() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0x11, 0x22])]);
        hf.swap_bytes(SwapMode::Word).unwrap();
        assert_eq!(hf.segments()[0].data, vec![0x11, 0x22]);
    }

    #[test]
    fn test_swap_word_total_odd_noop() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB]),
            Segment::new(0x2000, vec![0xCC]),
        ]);
        hf.swap_bytes(SwapMode::Word).unwrap();
        assert_eq!(hf.segments()[0].data, vec![0xAA, 0xBB]);
        assert_eq!(hf.segments()[1].data, vec![0xCC]);
    }

    #[test]
    fn test_swap_dword_span_misaligned_noop() {
        let mut hf =
            HexFile::with_segments(vec![Segment::new(0x1002, vec![0x01, 0x02, 0x03, 0x04])]);
        hf.swap_bytes(SwapMode::DWord).unwrap();
        assert_eq!(hf.segments()[0].data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_swap_dword_span_length_noop() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02, 0x03, 0x04]),
            Segment::new(0x2000, vec![0x05, 0x06]),
        ]);
        hf.swap_bytes(SwapMode::DWord).unwrap();
        assert_eq!(hf.segments()[0].data, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(hf.segments()[1].data, vec![0x05, 0x06]);
    }

    #[test]
    fn test_swap_dword_compat_gap_fill() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x0000, vec![0x10, 0x11, 0x12, 0x13]),
            Segment::new(0x0004, vec![0x20, 0x21]),
            Segment::new(0x0008, vec![0x30, 0x31, 0x32, 0x33]),
        ]);
        hf.swap_bytes(SwapMode::DWord).unwrap();
        assert_eq!(hf.segments()[0].data, vec![0x13, 0x12, 0x11, 0x10]);
        assert_eq!(hf.segments()[1].data, vec![0x13, 0x12]);
        assert_eq!(hf.segments()[2].data, vec![0x33, 0x32, 0x31, 0x30]);
    }

    #[test]
    fn test_scale_unscale_roundtrip() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA]),
            Segment::new(0x2000, vec![0xBB]),
        ]);
        let original = hf.clone();
        hf.scale_addresses(4).unwrap();
        hf.unscale_addresses(4).unwrap();
        assert_eq!(
            hf.segments()[0].start_address,
            original.segments()[0].start_address
        );
        assert_eq!(
            hf.segments()[1].start_address,
            original.segments()[1].start_address
        );
    }

    #[test]
    fn test_unscale_transactional() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x2000, vec![0xAA]), // divisible by 2
            Segment::new(0x3001, vec![0xBB]), // NOT divisible by 2
        ]);
        let original_first = hf.segments()[0].start_address;
        let result = hf.unscale_addresses(2);
        assert!(result.is_err());
        // First segment should NOT have been modified
        assert_eq!(hf.segments()[0].start_address, original_first);
    }

    #[test]
    fn test_scale_overflow_errors() {
        let mut hf = HexFile::with_segments(vec![Segment::new(u32::MAX / 2 + 1, vec![0xAA])]);
        let original_addr = hf.segments()[0].start_address;
        let result = hf.scale_addresses(3);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
        // Unchanged (transactional)
        assert_eq!(hf.segments()[0].start_address, original_addr);
    }

    #[test]
    fn test_scale_segment_end_overflow_errors() {
        let start = u32::MAX / 2;
        let mut hf = HexFile::with_segments(vec![Segment::new(start, vec![0xAA, 0xBB, 0xCC])]);
        let result = hf.scale_addresses(2);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
        assert_eq!(hf.segments()[0].start_address, start);
    }

    #[test]
    fn test_unscale_by_zero() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA])]);
        let result = hf.unscale_addresses(0);
        assert!(result.is_err());
    }

    #[test]
    fn test_align_then_split() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA; 15])]);
        hf.align(&AlignOptions {
            alignment: 4,
            fill_byte: 0xFF,
            align_length: true,
        })
        .unwrap();
        // After align: start=0x1000, len=16 (1 prepend + 15 data)
        // Actually: 0x1001 aligns down to 0x1000, prepend 1. length 16, aligned to 4 = 16.
        hf.split(8);
        assert_eq!(hf.segments().len(), 2);
        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(hf.segments()[0].len(), 8);
        assert_eq!(hf.segments()[1].start_address, 0x1008);
        assert_eq!(hf.segments()[1].len(), 8);
    }

    #[test]
    fn test_remap_basic_banked() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA]),
            Segment::new(0x018000, vec![0x01, 0x02]),
            Segment::new(0x028000, vec![0x03]),
        ]);
        let options = RemapOptions {
            start: 0x018000,
            end: 0x02BFFF,
            linear: 0x008000,
            size: 0x4000,
            inc: 0x010000,
        };

        hf.remap(&options).unwrap();
        let mut segments = hf.segments().to_vec();
        segments.sort_by_key(|s| s.start_address);
        assert_eq!(segments.len(), 3);
        assert_eq!(segments[0].start_address, 0x1000);
        assert_eq!(segments[1].start_address, 0x008000);
        assert_eq!(segments[2].start_address, 0x00C000);
    }

    #[test]
    fn test_remap_skips_oversize_block() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x018000, vec![0xAA; 0x4001])]);
        let options = RemapOptions {
            start: 0x018000,
            end: 0x02BFFF,
            linear: 0x008000,
            size: 0x4000,
            inc: 0x010000,
        };

        hf.remap(&options).unwrap();
        assert_eq!(hf.segments()[0].start_address, 0x018000);
    }

    #[test]
    fn test_remap_invalid_params() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x018000, vec![0xAA])]);
        let options = RemapOptions {
            start: 0x2000,
            end: 0x1000,
            linear: 0x0,
            size: 0,
            inc: 0x1000,
        };

        let result = hf.remap(&options);
        assert!(matches!(result, Err(OpsError::InvalidRemapParams(_))));
    }

    #[test]
    fn test_map_star12_basic() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x4000, vec![0xAA]),
            Segment::new(0xC000, vec![0xBB]),
            Segment::new(0x308000, vec![0x01]),
        ]);

        hf.map_star12().unwrap();
        let mut segments = hf.segments().to_vec();
        segments.sort_by_key(|s| s.start_address);
        assert_eq!(segments[0].start_address, 0x0C0000);
        assert_eq!(segments[1].start_address, 0x0F8000);
        assert_eq!(segments[2].start_address, 0x0FC000);
    }

    #[test]
    fn test_map_star12x_basic() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x4000, vec![0xAA]),
            Segment::new(0xC000, vec![0xBB]),
            Segment::new(0xE08000, vec![0x01]),
        ]);

        hf.map_star12x().unwrap();
        let mut segments = hf.segments().to_vec();
        segments.sort_by_key(|s| s.start_address);
        assert_eq!(segments[0].start_address, 0x780000);
        assert_eq!(segments[1].start_address, 0x7F4000);
        assert_eq!(segments[2].start_address, 0x7FC000);
    }

    #[test]
    fn test_map_star08_examples() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x4000, vec![0xAA]),
            Segment::new(0x028000, vec![0xBB]),
        ]);

        hf.map_star08().unwrap();
        let mut segments = hf.segments().to_vec();
        segments.sort_by_key(|s| s.start_address);
        assert_eq!(segments[0].start_address, 0x104000);
        assert_eq!(segments[1].start_address, 0x108000);
    }

    #[test]
    fn test_dspic_expand_appends_zeros() {
        let mut hf =
            HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD])]);
        hf.dspic_expand(AddressRange::from_start_length(0x1000, 4).unwrap(), None)
            .unwrap();

        let out = hf.read_bytes_contiguous(0x2000, 8).unwrap();
        assert_eq!(out, vec![0xAA, 0xBB, 0x00, 0x00, 0xCC, 0xDD, 0x00, 0x00]);
    }

    #[test]
    fn test_dspic_shrink_keeps_low_bytes() {
        let mut hf = HexFile::with_segments(vec![Segment::new(
            0x2000,
            vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        )]);
        hf.dspic_shrink(AddressRange::from_start_length(0x2000, 8).unwrap(), None)
            .unwrap();

        let out = hf.read_bytes_contiguous(0x1000, 4).unwrap();
        assert_eq!(out, vec![0x11, 0x22, 0x55, 0x66]);
    }

    #[test]
    fn test_dspic_clear_ghost() {
        let mut hf = HexFile::with_segments(vec![Segment::new(
            0x3000,
            vec![0x01, 0x02, 0x03, 0xFF, 0x10, 0x11, 0x12, 0xEE],
        )]);
        hf.dspic_clear_ghost(AddressRange::from_start_length(0x3000, 8).unwrap())
            .unwrap();

        let out = hf.read_bytes_contiguous(0x3000, 8).unwrap();
        assert_eq!(out, vec![0x01, 0x02, 0x03, 0x00, 0x10, 0x11, 0x12, 0x00]);
    }
}

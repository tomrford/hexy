use super::{OpsError, materialized_len};
use crate::segment::end_address_for;
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

impl HexFile {
    /// Align all segment start addresses to multiples of alignment.
    /// Prepends fill bytes as needed. Optionally aligns lengths too.
    /// Fill bytes are LOW priority (existing data wins on overlap).
    pub fn align(&mut self, options: &AlignOptions) -> Result<(), OpsError> {
        let alignment = options.alignment;
        if alignment == 0 {
            return Err(OpsError::InvalidAlignment(alignment));
        }

        let normalized = self.normalized();
        let mut result = HexFile::new();
        for segment in normalized.segments() {
            let aligned_start = segment.start_address - segment.start_address % alignment;
            if aligned_start < segment.start_address {
                let fill_len = (segment.start_address - aligned_start) as usize;
                result.prepend_segment(Segment::from_valid(
                    aligned_start,
                    vec![options.fill_byte; fill_len],
                ));
            }

            if options.align_length {
                let end_addr = u64::from(segment.end_address()) + 1;
                let aligned_end = end_addr.next_multiple_of(u64::from(alignment));
                if aligned_end > end_addr && aligned_end <= u64::from(u32::MAX) + 1 {
                    let fill_len = (aligned_end - end_addr) as usize;
                    result.prepend_segment(Segment::from_valid(
                        end_addr as u32,
                        vec![options.fill_byte; fill_len],
                    ));
                }
            }
        }
        for segment in normalized.into_segments() {
            result.append_segment(segment);
        }

        *self = result.normalized();
        Ok(())
    }

    /// Split each normalized block into pieces of at most `max_size` bytes; the pieces
    /// stay separate blocks (see [`HexFile::blocks`]).
    pub fn split(&mut self, max_size: u32) {
        if max_size == 0 {
            return;
        }
        let mut segments = Vec::new();
        for segment in self.normalized().into_segments() {
            if segment.len() <= max_size as usize {
                segments.push(segment);
                continue;
            }
            let mut addr = segment.start_address;
            for chunk in segment.data.chunks(max_size as usize) {
                segments.push(Segment::from_valid(addr, chunk.to_vec()));
                addr = addr.wrapping_add(chunk.len() as u32);
            }
        }
        self.set_segments(segments);
    }

    /// Reverse the bytes of every aligned 2-byte (`Word`) or 4-byte (`DWord`) word, as
    /// HexView's `/SWAPWORD` and `/SWAPLONG` do:
    /// - nothing changes unless the span from the lowest to the highest address starts
    ///   and ends on word boundaries;
    /// - a word is swapped when its first byte holds data; its missing bytes take the
    ///   value of the latest complete word (zero before one), and only bytes that hold
    ///   data are written.
    pub fn swap_bytes(&mut self, mode: SwapMode) {
        let width: usize = match mode {
            SwapMode::Word => 2,
            SwapMode::DWord => 4,
        };
        let (Some(span_start), Some(span_end)) = (self.min_address(), self.max_address()) else {
            return;
        };
        let span_len = u64::from(span_end - span_start) + 1;
        if !(span_start as usize).is_multiple_of(width) || !span_len.is_multiple_of(width as u64) {
            return;
        }

        if let [segment] = self.segments_mut() {
            for chunk in segment.data.chunks_exact_mut(width) {
                chunk.reverse();
            }
            return;
        }

        let view = self.normalized().into_segments();
        let mut swapped = view.clone();
        let mut last_full = [0u8; 4];
        for segment in &view {
            let mut next_word = segment.start_address.checked_next_multiple_of(width as u32);
            while let Some(word_addr) = next_word.filter(|addr| *addr <= segment.end_address()) {
                let positions: [Option<(usize, usize)>; 4] = std::array::from_fn(|k| {
                    (k < width)
                        .then(|| locate(&view, word_addr.checked_add(k as u32)?))
                        .flatten()
                });
                let mut word = last_full;
                for (byte, position) in word.iter_mut().zip(&positions) {
                    if let Some((index, offset)) = *position {
                        *byte = view[index].data[offset];
                    }
                }
                if positions[..width].iter().all(Option::is_some) {
                    last_full = word;
                }
                for (k, position) in positions[..width].iter().enumerate() {
                    if let Some((index, offset)) = *position {
                        swapped[index].data[offset] = word[width - 1 - k];
                    }
                }
                next_word = word_addr.checked_add(width as u32);
            }
        }

        let mask = !(width as u32 - 1);
        for segment in self.segments_mut() {
            let start = segment.start_address;
            for (offset, byte) in segment.data.iter_mut().enumerate() {
                let addr = start + offset as u32;
                if locate(&view, addr & mask).is_some()
                    && let Some((index, offset)) = locate(&view, addr)
                {
                    *byte = swapped[index].data[offset];
                }
            }
        }
    }

    /// Expand dsPIC-like data: 2 bytes -> 4 bytes (appends two zero bytes).
    /// Copies data to the target address (default: source_start * 2).
    pub fn dspic_expand(
        &mut self,
        range: AddressRange,
        target: Option<u32>,
    ) -> Result<(), OpsError> {
        let src = self.read_dspic_range(range, 2, "dsPIC expand")?;
        let out: Vec<u8> = src
            .chunks_exact(2)
            .flat_map(|pair| [pair[0], pair[1], 0x00, 0x00])
            .collect();
        let target = match target {
            Some(addr) => addr,
            None => range
                .start()
                .checked_mul(2)
                .ok_or(OpsError::AddressOverflow {
                    address: range.start(),
                })?,
        };
        self.write_bytes(target, &out)
    }

    /// Shrink dsPIC-like data: 4 bytes -> 2 bytes (keeps lower two bytes).
    /// Copies data to the target address (default: source_start / 2).
    pub fn dspic_shrink(
        &mut self,
        range: AddressRange,
        target: Option<u32>,
    ) -> Result<(), OpsError> {
        let src = self.read_dspic_range(range, 4, "dsPIC shrink")?;
        if target.is_none() && !range.start().is_multiple_of(2) {
            return Err(OpsError::AddressNotDivisible {
                address: range.start(),
                divisor: 2,
            });
        }
        let out: Vec<u8> = src
            .chunks_exact(4)
            .flat_map(|quad| [quad[0], quad[1]])
            .collect();
        self.write_bytes(target.unwrap_or(range.start() / 2), &out)
    }

    /// Clear dsPIC ghost bytes: set highest byte in each 4-byte group to 0.
    pub fn dspic_clear_ghost(&mut self, range: AddressRange) -> Result<(), OpsError> {
        let mut data = self.read_dspic_range(range, 4, "dsPIC clear ghost")?;
        for chunk in data.chunks_exact_mut(4) {
            chunk[3] = 0x00;
        }
        self.write_bytes(range.start(), &data)
    }

    fn read_dspic_range(
        &self,
        range: AddressRange,
        multiple: u64,
        operation: &'static str,
    ) -> Result<Vec<u8>, OpsError> {
        let length = materialized_len(range)?;
        if !range.length().is_multiple_of(multiple) {
            return Err(OpsError::LengthNotMultiple {
                length: range.length(),
                expected: multiple,
                operation,
            });
        }
        self.read_bytes_contiguous(range.start(), length)
            .ok_or(OpsError::RangeNotCovered {
                start: range.start(),
                length: range.length(),
            })
    }

    /// Add offset to all segment addresses. Errors if any address would overflow or underflow.
    /// If validation fails, no segments are modified (transactional).
    pub fn offset_addresses(&mut self, offset: i64) -> Result<(), OpsError> {
        self.relocate(|segment| {
            i64::from(segment.start_address)
                .checked_add(offset)
                .and_then(|addr| u32::try_from(addr).ok())
                .map(Some)
                .ok_or(OpsError::AddressOverflow {
                    address: segment.start_address,
                })
        })
    }

    /// Multiply all addresses by factor. Errors if any address would overflow.
    /// If validation fails, no segments are modified (transactional).
    pub fn scale_addresses(&mut self, factor: u32) -> Result<(), OpsError> {
        self.relocate(|segment| {
            segment
                .start_address
                .checked_mul(factor)
                .map(Some)
                .ok_or(OpsError::AddressOverflow {
                    address: segment.start_address,
                })
        })
    }

    /// Divide all addresses by divisor. Errors if any address not evenly divisible.
    /// If validation fails, no segments are modified (transactional).
    pub fn unscale_addresses(&mut self, divisor: u32) -> Result<(), OpsError> {
        if divisor == 0 {
            return Err(OpsError::AddressNotDivisible {
                address: 0,
                divisor,
            });
        }
        self.relocate(|segment| match segment.start_address.checked_rem(divisor) {
            Some(0) => Ok(Some(segment.start_address / divisor)),
            _ => Err(OpsError::AddressNotDivisible {
                address: segment.start_address,
                divisor,
            }),
        })
    }

    /// Move each segment to the start `new_start` returns for it (`None` leaves it in
    /// place). Every move is validated before any is applied.
    fn relocate(
        &mut self,
        new_start: impl Fn(&Segment) -> Result<Option<u32>, OpsError>,
    ) -> Result<(), OpsError> {
        let starts = self
            .segments()
            .iter()
            .map(|segment| {
                let start = new_start(segment)?;
                if let Some(start) = start
                    && end_address_for(start, segment.len()).is_none()
                {
                    return Err(OpsError::AddressOverflow {
                        address: segment.start_address,
                    });
                }
                Ok(start)
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (segment, start) in self.segments_mut().iter_mut().zip(starts) {
            if let Some(start) = start {
                segment.start_address = start;
            }
        }
        Ok(())
    }
}

/// Position (segment index, byte offset) of `addr` in sorted, non-overlapping segments.
fn locate(segments: &[Segment], addr: u32) -> Option<(usize, usize)> {
    let index = segments.partition_point(|s| s.end_address() < addr);
    let offset = addr.checked_sub(segments.get(index)?.start_address)?;
    Some((index, offset as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_prepends_fill() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA, 0xBB]).unwrap()]);
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
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA, 0xBB]).unwrap()]);
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
    fn test_align_length_can_fill_last_address() {
        let mut hf = HexFile::with_segments(vec![Segment::new(u32::MAX - 3, vec![0xAA]).unwrap()]);
        let options = AlignOptions {
            alignment: 4,
            align_length: true,
            ..Default::default()
        };

        hf.align(&options).unwrap();
        assert_eq!(hf.segments()[0].data, [0xAA, 0xFF, 0xFF, 0xFF]);

        hf.align(&options).unwrap();
        assert_eq!(hf.segments()[0].data, [0xAA, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn test_align_already_aligned() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 8]).unwrap()]);
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
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA]).unwrap()]);
        let result = hf.align(&AlignOptions {
            alignment: 0,
            fill_byte: 0xFF,
            align_length: false,
        });
        assert!(matches!(result, Err(OpsError::InvalidAlignment(0))));
    }

    #[test]
    fn test_align_non_power_of_two() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB]).unwrap()]);
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
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 10]).unwrap()]);
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
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD]).unwrap(),
        ]);
        hf.swap_bytes(SwapMode::Word);

        assert_eq!(hf.segments()[0].data, vec![0xBB, 0xAA, 0xDD, 0xCC]);
    }

    #[test]
    fn test_swap_dword() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD]).unwrap(),
        ]);
        hf.swap_bytes(SwapMode::DWord);

        assert_eq!(hf.segments()[0].data, vec![0xDD, 0xCC, 0xBB, 0xAA]);
    }

    #[test]
    fn test_swap_word_partial_pairs_match_hexview() {
        // HexView 1.15.2 /SWAPWORD: the span 0x1000..=0x1105 is word aligned; 0x1102 lacks
        // its partner and takes the last complete pair's byte; 0x1105 has no first byte.
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![1, 2, 3, 4, 5, 6, 7, 8]).unwrap(),
            Segment::new(0x1100, vec![1, 2, 3]).unwrap(),
            Segment::new(0x1105, vec![1]).unwrap(),
        ]);
        hf.swap_bytes(SwapMode::Word);
        let data: Vec<&[u8]> = hf.segments().iter().map(Segment::data).collect();
        assert_eq!(data, [&[2, 1, 4, 3, 6, 5, 8, 7][..], &[2, 1, 2], &[1]]);
    }

    #[test]
    fn test_scale_addresses() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA]).unwrap(),
            Segment::new(0x2000, vec![0xBB]).unwrap(),
        ]);
        hf.scale_addresses(2).unwrap();

        assert_eq!(hf.segments()[0].start_address, 0x2000);
        assert_eq!(hf.segments()[1].start_address, 0x4000);
    }

    #[test]
    fn test_unscale_addresses() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x2000, vec![0xAA]).unwrap(),
            Segment::new(0x4000, vec![0xBB]).unwrap(),
        ]);
        hf.unscale_addresses(2).unwrap();

        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(hf.segments()[1].start_address, 0x2000);
    }

    #[test]
    fn test_unscale_not_divisible() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA]).unwrap()]);
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
            Segment::new(0x1001, vec![0xAA]).unwrap(),
            Segment::new(0x1003, vec![0xBB]).unwrap(),
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
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA, 0xBB]).unwrap()]);
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
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 10]).unwrap()]);
        hf.split(0);
        assert_eq!(hf.segments().len(), 1);
    }

    #[test]
    fn test_split_larger_than_segment() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 4]).unwrap()]);
        hf.split(100);
        assert_eq!(hf.segments().len(), 1);
    }

    #[test]
    fn test_swap_multiple_segments() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02]).unwrap(),
            Segment::new(0x2000, vec![0x03, 0x04]).unwrap(),
        ]);
        hf.swap_bytes(SwapMode::Word);
        assert_eq!(hf.segments()[0].data, vec![0x02, 0x01]);
        assert_eq!(hf.segments()[1].data, vec![0x04, 0x03]);
    }

    #[test]
    fn test_swap_dword_larger_buffer() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]).unwrap(),
        ]);
        hf.swap_bytes(SwapMode::DWord);
        assert_eq!(
            hf.segments()[0].data,
            vec![0x04, 0x03, 0x02, 0x01, 0x08, 0x07, 0x06, 0x05]
        );
    }

    #[test]
    fn test_swap_word_odd_start_noop() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0x11, 0x22]).unwrap()]);
        hf.swap_bytes(SwapMode::Word);
        assert_eq!(hf.segments()[0].data, vec![0x11, 0x22]);
    }

    #[test]
    fn test_swap_word_total_odd_noop() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB]).unwrap(),
            Segment::new(0x2000, vec![0xCC]).unwrap(),
        ]);
        hf.swap_bytes(SwapMode::Word);
        assert_eq!(hf.segments()[0].data, vec![0xAA, 0xBB]);
        assert_eq!(hf.segments()[1].data, vec![0xCC]);
    }

    #[test]
    fn test_swap_dword_span_misaligned_noop() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1002, vec![0x01, 0x02, 0x03, 0x04]).unwrap(),
        ]);
        hf.swap_bytes(SwapMode::DWord);
        assert_eq!(hf.segments()[0].data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_swap_dword_span_length_noop() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02, 0x03, 0x04]).unwrap(),
            Segment::new(0x2000, vec![0x05, 0x06]).unwrap(),
        ]);
        hf.swap_bytes(SwapMode::DWord);
        assert_eq!(hf.segments()[0].data, vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(hf.segments()[1].data, vec![0x05, 0x06]);
    }

    #[test]
    fn test_swap_dword_compat_gap_fill() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x0000, vec![0x10, 0x11, 0x12, 0x13]).unwrap(),
            Segment::new(0x0004, vec![0x20, 0x21]).unwrap(),
            Segment::new(0x0008, vec![0x30, 0x31, 0x32, 0x33]).unwrap(),
        ]);
        hf.swap_bytes(SwapMode::DWord);
        assert_eq!(hf.segments()[0].data, vec![0x13, 0x12, 0x11, 0x10]);
        assert_eq!(hf.segments()[1].data, vec![0x13, 0x12]);
        assert_eq!(hf.segments()[2].data, vec![0x33, 0x32, 0x31, 0x30]);
    }

    #[test]
    fn test_swap_dword_partial_words_match_hexview() {
        // HexView 1.15.2: a word whose first byte is missing is left alone, and missing
        // bytes before any complete word read as zero.
        let mut first_missing = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x08, 0x0F, 0x16]).unwrap(),
            Segment::new(0x1005, vec![0x02, 0x09, 0x10]).unwrap(),
            Segment::new(0x1010, vec![0x03, 0x0A, 0x11, 0x18]).unwrap(),
        ]);
        first_missing.swap_bytes(SwapMode::DWord);
        let data: Vec<&[u8]> = first_missing.segments().iter().map(Segment::data).collect();
        assert_eq!(
            data,
            [
                &[0x16, 0x0F, 0x08, 0x01][..],
                &[0x02, 0x09, 0x10],
                &[0x18, 0x11, 0x0A, 0x03]
            ]
        );

        let mut no_full_word = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x08]).unwrap(),
            Segment::new(0x1008, vec![0x02, 0x09, 0x10, 0x17, 0x1E, 0x25, 0x2C, 0x33]).unwrap(),
        ]);
        no_full_word.swap_bytes(SwapMode::DWord);
        assert_eq!(no_full_word.segments()[0].data, [0x00, 0x00]);
        assert_eq!(
            no_full_word.segments()[1].data,
            [0x17, 0x10, 0x09, 0x02, 0x33, 0x2C, 0x25, 0x1E]
        );
    }

    #[test]
    fn test_scale_unscale_roundtrip() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA]).unwrap(),
            Segment::new(0x2000, vec![0xBB]).unwrap(),
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
            Segment::new(0x2000, vec![0xAA]).unwrap(), // divisible by 2
            Segment::new(0x3001, vec![0xBB]).unwrap(), // NOT divisible by 2
        ]);
        let original_first = hf.segments()[0].start_address;
        let result = hf.unscale_addresses(2);
        assert!(result.is_err());
        // First segment should NOT have been modified
        assert_eq!(hf.segments()[0].start_address, original_first);
    }

    #[test]
    fn test_scale_overflow_errors() {
        let mut hf =
            HexFile::with_segments(vec![Segment::new(u32::MAX / 2 + 1, vec![0xAA]).unwrap()]);
        let original_addr = hf.segments()[0].start_address;
        let result = hf.scale_addresses(3);
        assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
        // Unchanged (transactional)
        assert_eq!(hf.segments()[0].start_address, original_addr);
    }

    #[test]
    fn test_scale_segment_end_overflow_errors() {
        let start = u32::MAX / 2;
        let mut hf =
            HexFile::with_segments(vec![Segment::new(start, vec![0xAA, 0xBB, 0xCC]).unwrap()]);
        let result = hf.scale_addresses(2);
        assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
        assert_eq!(hf.segments()[0].start_address, start);
    }

    #[test]
    fn test_unscale_by_zero() {
        for mut hf in [
            HexFile::new(),
            HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA]).unwrap()]),
        ] {
            assert!(matches!(
                hf.unscale_addresses(0),
                Err(OpsError::AddressNotDivisible { divisor: 0, .. })
            ));
        }
    }

    #[test]
    fn test_align_then_split() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA; 15]).unwrap()]);
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
    fn test_dspic_expand_appends_zeros() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC, 0xDD]).unwrap(),
        ]);
        hf.dspic_expand(AddressRange::from_start_length(0x1000, 4).unwrap(), None)
            .unwrap();

        let out = hf.read_bytes_contiguous(0x2000, 8).unwrap();
        assert_eq!(out, vec![0xAA, 0xBB, 0x00, 0x00, 0xCC, 0xDD, 0x00, 0x00]);
    }

    #[test]
    fn test_dspic_shrink_keeps_low_bytes() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x2000, vec![0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]).unwrap(),
        ]);
        hf.dspic_shrink(AddressRange::from_start_length(0x2000, 8).unwrap(), None)
            .unwrap();

        let out = hf.read_bytes_contiguous(0x1000, 4).unwrap();
        assert_eq!(out, vec![0x11, 0x22, 0x55, 0x66]);
    }

    #[test]
    fn test_dspic_clear_ghost() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x3000, vec![0x01, 0x02, 0x03, 0xFF, 0x10, 0x11, 0x12, 0xEE]).unwrap(),
        ]);
        hf.dspic_clear_ghost(AddressRange::from_start_length(0x3000, 8).unwrap())
            .unwrap();

        let out = hf.read_bytes_contiguous(0x3000, 8).unwrap();
        assert_eq!(out, vec![0x01, 0x02, 0x03, 0x00, 0x10, 0x11, 0x12, 0x00]);
    }
}

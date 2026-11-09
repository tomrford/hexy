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

/// Options for alignment operations (`/AD`, `/AL`). HexView aligns with the bit mask of
/// `alignment - 1`: a power of two aligns to its multiples, other values clear or set
/// the bits of that mask instead.
#[derive(Debug, Clone)]
pub struct AlignOptions {
    /// Block starts move down to this alignment; 0 leaves them.
    pub address_alignment: u32,
    /// Block lengths, counted from the aligned start, grow to this alignment; 0 leaves
    /// them.
    pub length_alignment: u32,
    /// Byte to use for padding (default 0xFF)
    pub fill_byte: u8,
}

impl Default for AlignOptions {
    fn default() -> Self {
        Self {
            address_alignment: 4,
            length_alignment: 0,
            fill_byte: 0xFF,
        }
    }
}

impl HexFile {
    /// Align block starts and lengths. Fill bytes are LOW priority (existing data wins
    /// on overlap); a length that would reach past the address space stops at its end.
    pub fn align(&mut self, options: &AlignOptions) {
        let normalized = self.normalized();
        let mut result = HexFile::new();
        for segment in normalized.segments() {
            let start = match options.address_alignment {
                0 => segment.start_address,
                alignment => segment.start_address & !(alignment - 1),
            };
            if start < segment.start_address {
                let fill_len = (segment.start_address - start) as usize;
                result.prepend_segment(Segment::from_valid(
                    start,
                    vec![options.fill_byte; fill_len],
                ));
            }
            if options.length_alignment > 0 {
                let end = u64::from(segment.end_address()) + 1;
                let mask = u64::from(options.length_alignment - 1);
                let len = (end - u64::from(start) + mask) & !mask;
                let aligned_end = (u64::from(start) + len).min(1 << 32);
                if aligned_end > end {
                    let fill_len = (aligned_end - end) as usize;
                    result.prepend_segment(Segment::from_valid(
                        end as u32,
                        vec![options.fill_byte; fill_len],
                    ));
                }
            }
        }
        for segment in normalized.into_segments() {
            result.append_segment(segment);
        }

        *self = result.normalized();
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
    ///   data are written;
    /// - for `DWord`, blocks of at least 16 MiB keep their first swapped word, then
    ///   repeat their second swapped word through the remaining complete words.
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

        const LARGE_BLOCK: usize = 0x100_0000;
        if width == 4 && self.total_bytes() >= LARGE_BLOCK && self.segments().len() > 1 {
            self.set_segments(self.blocks());
        }
        self.swap_words(width);
        if width == 4 {
            for block in self
                .segments_mut()
                .iter_mut()
                .filter(|b| b.len() >= LARGE_BLOCK)
            {
                let second = [block.data[4], block.data[5], block.data[6], block.data[7]];
                for word in block.data[8..].chunks_exact_mut(4) {
                    word.copy_from_slice(&second);
                }
            }
        }
    }

    fn swap_words(&mut self, width: usize) {
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

    /// Move all data by `offset` bytes. Fails, changing nothing, when any data would
    /// leave the address space.
    pub fn offset_addresses(&mut self, offset: i64) -> Result<(), OpsError> {
        let starts = self
            .segments()
            .iter()
            .map(|segment| {
                i64::from(segment.start_address)
                    .checked_add(offset)
                    .and_then(|start| u32::try_from(start).ok())
                    .filter(|&start| end_address_for(start, segment.len()).is_some())
                    .ok_or(OpsError::AddressOverflow {
                        address: segment.start_address,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        for (segment, start) in self.segments_mut().iter_mut().zip(starts) {
            segment.start_address = start;
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

    /// HexView 1.15.2 `/AD:4 /AL:0x10`: the start moves down to a multiple of 4 and the
    /// length from there grows to a multiple of 0x10.
    #[test]
    fn test_align_length_counts_from_aligned_start() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1035, vec![0xAA; 0x13]).unwrap()]);
        hf.align(&AlignOptions {
            address_alignment: 4,
            length_alignment: 0x10,
            fill_byte: 0xFF,
        });

        assert_eq!(hf.segments()[0].start_address, 0x1034);
        assert_eq!(hf.segments()[0].len(), 0x20);
        assert_eq!(hf.segments()[0].data[0], 0xFF);
        assert_eq!(hf.segments()[0].data[0x14..], [0xFF; 0xC]);
    }

    #[test]
    fn test_align_through_final_address() {
        let mut image =
            HexFile::with_segments(vec![Segment::new(u32::MAX - 3, vec![0xAA]).unwrap()]);
        let options = AlignOptions {
            address_alignment: 4,
            length_alignment: 4,
            ..Default::default()
        };
        image.align(&options);
        assert_eq!(image.segments()[0].data, [0xAA, 0xFF, 0xFF, 0xFF]);
        assert_eq!(image.segments()[0].end_address(), u32::MAX);
        image.align(&options);
        assert_eq!(image.segments()[0].data, [0xAA, 0xFF, 0xFF, 0xFF]);
    }

    /// HexView 1.15.2 `/AD:6 /AL` and `/AL:7` on a block at 0x1035: bit masks of 5 and 6.
    #[test]
    fn test_align_other_values_use_bit_masks() {
        let align = |address_alignment, length_alignment, len| {
            let mut hf =
                HexFile::with_segments(vec![Segment::new(0x1035, vec![0xAA; len]).unwrap()]);
            hf.align(&AlignOptions {
                address_alignment,
                length_alignment,
                fill_byte: 0xFF,
            });
            (hf.segments()[0].start_address, hf.segments()[0].len())
        };
        assert_eq!(align(6, 6, 0x13), (0x1030, 0x18));
        assert_eq!(align(6, 6, 0x20), (0x1030, 0x2A));
        assert_eq!(align(0, 7, 0x13), (0x1035, 0x19));
        assert_eq!(align(0, 7, 0x20), (0x1035, 0x20));
    }

    #[test]
    fn test_split_segments() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 10]).unwrap()]);
        let before = hf.clone();
        hf.split(0);
        assert_eq!(hf, before);
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
    fn test_align_causes_overlap() {
        // Two segments that will both align to 0x1000
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1001, vec![0xAA]).unwrap(),
            Segment::new(0x1003, vec![0xBB]).unwrap(),
        ]);
        hf.align(&AlignOptions::default());

        // Align now resolves overlaps internally with original data winning
        // Result: single segment 0x1000-0x1003 with [0xFF, 0xAA, 0xFF, 0xBB]
        // (fill at 0x1000, data at 0x1001, fill at 0x1002, data at 0x1003)
        assert_eq!(hf.segments().len(), 1);
        let seg = &hf.segments()[0];
        assert_eq!(seg.start_address, 0x1000);
        assert_eq!(seg.data, vec![0xFF, 0xAA, 0xFF, 0xBB]);
    }

    /// Nothing changes unless the span from the lowest to the highest address starts and
    /// ends on word boundaries.
    #[test]
    fn test_swap_needs_an_aligned_span() {
        for (segments, mode) in [
            (vec![(0x1001, vec![0x11, 0x22])], SwapMode::Word),
            (
                vec![(0x1000, vec![1, 2]), (0x2000, vec![3])],
                SwapMode::Word,
            ),
            (vec![(0x1002, vec![1, 2, 3, 4])], SwapMode::DWord),
            (
                vec![(0x1000, vec![1, 2, 3, 4]), (0x2000, vec![5, 6])],
                SwapMode::DWord,
            ),
        ] {
            let segments: Vec<Segment> = segments
                .into_iter()
                .map(|(start, data)| Segment::new(start, data).unwrap())
                .collect();
            let mut hf = HexFile::with_segments(segments.clone());
            hf.swap_bytes(mode);
            assert_eq!(hf.segments(), segments);
        }
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
}

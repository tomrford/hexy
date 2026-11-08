use super::{OpsError, materialized_len, pattern_bytes};
use crate::range::merge_ranges;
use crate::range::subtract_ranges;
use crate::{AddressRange, HexFile, Segment};

/// Largest gap-fill span the CLI materializes.
pub const DEFAULT_DENSE_SPAN_LIMIT: u64 = 256 * 1024 * 1024;

/// Options for fill operations.
#[derive(Debug, Clone)]
pub struct FillOptions {
    /// Pattern to repeat (default: 0xFF)
    pub pattern: Vec<u8>,
    /// If true, overwrites existing data; if false, only fills gaps
    pub overwrite: bool,
}

impl Default for FillOptions {
    fn default() -> Self {
        Self {
            pattern: vec![0xFF],
            overwrite: false,
        }
    }
}

/// Mode for merging files.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MergeMode {
    /// New data overwrites existing (opaque)
    #[default]
    Overwrite,
    /// Existing data preserved, new fills gaps (transparent)
    Preserve,
}

/// Options for merge operations.
#[derive(Debug, Clone, Default)]
pub struct MergeOptions {
    pub mode: MergeMode,
    /// Address offset to apply (can be negative)
    pub offset: i64,
    /// Only merge data within this range (applied before offset)
    pub range: Option<AddressRange>,
}

impl HexFile {
    /// Remove every block shorter than `min_len` bytes (see [`HexFile::blocks`]).
    pub fn remove_small_blocks(&mut self, min_len: usize) {
        let blocks = self.blocks();
        self.set_segments(
            blocks
                .into_iter()
                .filter(|block| block.len() >= min_len)
                .collect(),
        );
    }

    /// Keep only data within any of the specified ranges.
    pub fn filter_ranges(&mut self, ranges: &[AddressRange]) {
        let ranges = merge_ranges(ranges);
        let segments = self
            .take_segments()
            .iter()
            .flat_map(|segment| ranges.iter().filter_map(|range| segment.clipped(*range)))
            .collect();
        self.set_segments(segments);
    }

    /// Remove data within multiple ranges (operates on raw segments; preserves order).
    pub fn cut_ranges(&mut self, ranges: &[AddressRange]) {
        let ranges = merge_ranges(ranges);
        let mut segments = Vec::new();
        for segment in self.take_segments() {
            let kept = subtract_ranges(segment.range(), &ranges);
            if kept == [segment.range()] {
                segments.push(segment);
            } else {
                segments.extend(kept.into_iter().filter_map(|part| segment.clipped(part)));
            }
        }
        self.set_segments(segments);
    }

    /// Fill multiple regions with the specified pattern (operates on raw segments).
    /// By default, only fills gaps - existing data is preserved.
    /// When overwrite=true, removes existing data first then fills the entire range.
    /// The pattern is anchored at each range start.
    pub fn fill_ranges(
        &mut self,
        ranges: &[AddressRange],
        options: &FillOptions,
    ) -> Result<(), OpsError> {
        if options.pattern.is_empty() {
            return Ok(());
        }
        for range in ranges {
            materialized_len(*range)?;
        }

        for &range in ranges {
            let gaps = if options.overwrite {
                self.cut_ranges(&[range]);
                vec![range]
            } else {
                let occupied: Vec<AddressRange> = self
                    .segments()
                    .iter()
                    .filter_map(|segment| segment.range().intersection(&range))
                    .collect();
                subtract_ranges(range, &merge_ranges(&occupied))
            };
            for gap in gaps {
                let phase = (gap.start() - range.start()) as usize;
                let data = pattern_bytes(&options.pattern, phase, gap.length() as usize).collect();
                self.append_segment(Segment::from_valid(gap.start(), data));
            }
        }
        Ok(())
    }

    /// Fill the gaps in each range with pseudo-random bytes. The bytes depend only on
    /// `seed` and the range, so a fixed seed reproduces the same image.
    pub fn fill_random(&mut self, ranges: &[AddressRange], seed: u64) -> Result<(), OpsError> {
        for &range in ranges {
            let len = materialized_len(range)?;
            let mut state = seed ^ (u64::from(range.start()) << 32) ^ range.length();
            if state == 0 {
                state = 0x9E37_79B9_7F4A_7C15;
            }
            let data = (0..len)
                .map(|_| {
                    state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                    (state >> 32) as u8
                })
                .collect();
            self.prepend_segment(Segment::new(range.start(), data)?);
        }
        Ok(())
    }

    /// Replace all data with one contiguous segment from first to last byte, filling
    /// gaps with `fill_byte` (last-wins on overlap). Errors if the span exceeds `limit`.
    pub fn fill_gaps(&mut self, fill_byte: u8, limit: u64) -> Result<(), OpsError> {
        if let Some(segment) = self.as_contiguous(fill_byte, limit)? {
            self.set_segments(vec![segment]);
        }
        Ok(())
    }

    /// Merge another file into this one (operates on raw segments).
    pub fn merge(&mut self, other: &HexFile, options: &MergeOptions) -> Result<(), OpsError> {
        let mut other = other.clone();
        if let Some(range) = options.range {
            other.filter_ranges(&[range]);
        }
        other.offset_addresses(options.offset)?;

        for segment in other.into_segments() {
            match options.mode {
                // Other data is high priority - append so it wins
                MergeMode::Overwrite => self.append_segment(segment),
                // Other data is low priority - prepend so existing wins
                MergeMode::Preserve => self.prepend_segment(segment),
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(segments: &[(u32, &[u8])]) -> HexFile {
        HexFile::with_segments(
            segments
                .iter()
                .map(|(start, data)| Segment::new(*start, data.to_vec()).unwrap())
                .collect(),
        )
    }

    fn range(start: u32, end: u32) -> AddressRange {
        AddressRange::from_start_end(start, end).unwrap()
    }

    #[test]
    fn test_filter_keeps_disjoint_range_union() {
        let mut hf = image(&[(0x1000, &[0, 1, 2, 3, 4, 5, 6, 7])]);
        hf.filter_ranges(&[range(0x1001, 0x1002), range(0x1005, 0x1006)]);
        assert_eq!(hf, image(&[(0x1001, &[1, 2]), (0x1005, &[5, 6])]));
    }

    #[test]
    fn test_filter_keeps_bytes_up_to_the_address_space_end() {
        let mut hf = image(&[(u32::MAX - 3, &[0xFC, 0xFD, 0xFE, 0xFF])]);
        hf.filter_ranges(&[range(0, u32::MAX)]);
        assert_eq!(hf, image(&[(u32::MAX - 3, &[0xFC, 0xFD, 0xFE, 0xFF])]));
    }

    #[test]
    fn test_cut_spans_segments() {
        let mut hf = image(&[(0x1000, &[1; 0x10]), (0x1020, &[2; 0x10])]);
        hf.cut_ranges(&[range(0x1008, 0x1027)]);
        assert_eq!(hf, image(&[(0x1000, &[1; 8]), (0x1028, &[2; 8])]));
    }

    /// The pattern is anchored at the range start; existing data wins unless
    /// `overwrite`.
    #[test]
    fn test_fill_anchors_pattern_at_range_start() {
        let fill = |overwrite| {
            let mut hf = image(&[(0x1002, &[0xAA; 2])]);
            let options = FillOptions {
                pattern: vec![1, 2, 3],
                overwrite,
            };
            hf.fill_ranges(&[range(0x1000, 0x1005)], &options).unwrap();
            hf.normalized()
                .into_segments()
                .pop()
                .unwrap()
                .into_parts()
                .1
        };
        assert_eq!(fill(false), [1, 2, 0xAA, 0xAA, 2, 3]);
        assert_eq!(fill(true), [1, 2, 3, 1, 2, 3]);
    }

    #[test]
    fn test_fill_rejects_full_span_allocation() {
        let mut hf = HexFile::new();
        let result = hf.fill_ranges(&[range(0, u32::MAX)], &FillOptions::default());
        assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
        assert!(hf.is_empty());
    }

    #[test]
    fn test_fill_gaps_rejects_span_over_limit() {
        let mut hf = image(&[(0x0000, &[0xAA]), (0x1000, &[0xBB])]);
        let result = hf.fill_gaps(0xFF, 16);
        assert!(matches!(result, Err(OpsError::DenseSpanTooLarge { .. })));
        assert_eq!(hf.segments().len(), 2);
    }

    /// `/MO` and `/MT`: the range applies before the offset.
    #[test]
    fn test_merge_range_applies_before_offset() {
        let other = image(&[(0x1000, &[0x10, 0x11, 0x12, 0x13])]);
        let merge = |mode| {
            let mut base = image(&[(0x1011, &[0xEE, 0xEE])]);
            let options = MergeOptions {
                mode,
                offset: 0x10,
                range: Some(range(0x1001, 0x1002)),
            };
            base.merge(&other, &options).unwrap();
            base.normalized()
        };
        assert_eq!(
            merge(MergeMode::Overwrite),
            image(&[(0x1011, &[0x11, 0x12])])
        );
        assert_eq!(
            merge(MergeMode::Preserve),
            image(&[(0x1011, &[0xEE, 0xEE])])
        );
    }

    #[test]
    fn test_offset_past_address_space_changes_nothing() {
        let mut hf = image(&[(0x1000, &[1]), (u32::MAX - 1, &[0xAA, 0xBB])]);
        for offset in [1, -0x2000, i64::MIN] {
            let result = hf.offset_addresses(offset);
            assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
        }
        assert_eq!(hf, image(&[(0x1000, &[1]), (u32::MAX - 1, &[0xAA, 0xBB])]));
    }
}

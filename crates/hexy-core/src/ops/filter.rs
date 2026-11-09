use super::{OpsError, materialized_len, pattern_bytes};
use crate::range::subtract_ranges;
use crate::{AddressRange, HexFile, Segment, merge_ranges};

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
    /// Keep only data within the specified range. Clips segments that partially overlap.
    pub fn filter_range(&mut self, range: AddressRange) {
        self.filter_ranges(&[range]);
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

    /// Remove all data within the specified range. Splits segments if cut is in the middle.
    pub fn cut(&mut self, range: AddressRange) {
        self.cut_ranges(&[range]);
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

    /// Fill a region with the specified pattern.
    /// By default (overwrite=false), only fills gaps - existing data is preserved.
    pub fn fill(&mut self, range: AddressRange, options: &FillOptions) -> Result<(), OpsError> {
        self.fill_ranges(&[range], options)
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
                self.cut(range);
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
            other.filter_range(range);
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

    #[test]
    fn test_filter_range_clips_segment() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02, 0x03, 0x04, 0x05]).unwrap(),
        ]);
        hf.filter_range(AddressRange::from_start_end(0x1001, 0x1003).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x1001);
        assert_eq!(hf.segments()[0].data, vec![0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_filter_range_removes_outside() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02]).unwrap(),
            Segment::new(0x2000, vec![0x03, 0x04]).unwrap(),
            Segment::new(0x3000, vec![0x05, 0x06]).unwrap(),
        ]);
        hf.filter_range(AddressRange::from_start_end(0x2000, 0x2FFF).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x2000);
    }

    #[test]
    fn test_filter_multiple_ranges() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x100]).unwrap()]);
        hf.filter_ranges(&[
            AddressRange::from_start_end(0x1010, 0x101F).unwrap(),
            AddressRange::from_start_end(0x1080, 0x108F).unwrap(),
        ]);

        assert_eq!(hf.segments().len(), 2);
        assert_eq!(hf.segments()[0].start_address, 0x1010);
        assert_eq!(hf.segments()[0].len(), 0x10);
        assert_eq!(hf.segments()[1].start_address, 0x1080);
        assert_eq!(hf.segments()[1].len(), 0x10);
    }

    #[test]
    fn test_cut_splits_segment() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x100]).unwrap()]);
        hf.cut(AddressRange::from_start_end(0x1040, 0x107F).unwrap());

        let norm = hf.normalized();
        assert_eq!(norm.segments().len(), 2);
        assert_eq!(norm.segments()[0].start_address, 0x1000);
        assert_eq!(norm.segments()[0].end_address(), 0x103F);
        assert_eq!(norm.segments()[1].start_address, 0x1080);
        assert_eq!(norm.segments()[1].end_address(), 0x10FF);
    }

    #[test]
    fn test_cut_removes_entire_segment() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01; 0x10]).unwrap(),
            Segment::new(0x2000, vec![0x02; 0x10]).unwrap(),
        ]);
        hf.cut(AddressRange::from_start_end(0x1000, 0x100F).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x2000);
    }

    #[test]
    fn test_fill_creates_segment() {
        let mut hf = HexFile::new();
        hf.fill(
            AddressRange::from_start_length(0x1000, 8).unwrap(),
            &FillOptions::default(),
        )
        .unwrap();

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(hf.segments()[0].data, vec![0xFF; 8]);
    }

    #[test]
    fn test_fill_with_pattern() {
        let mut hf = HexFile::new();
        hf.fill(
            AddressRange::from_start_length(0x1000, 8).unwrap(),
            &FillOptions {
                pattern: vec![0xDE, 0xAD, 0xBE, 0xEF],
                overwrite: false,
            },
        )
        .unwrap();

        assert_eq!(
            hf.segments()[0].data,
            vec![0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_filter_full_span_keeps_boundary_bytes() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(u32::MAX - 3, vec![0xFC, 0xFD, 0xFE, 0xFF]).unwrap(),
        ]);

        hf.filter_range(AddressRange::from_start_end(0, u32::MAX).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, u32::MAX - 3);
        assert_eq!(hf.segments()[0].data, vec![0xFC, 0xFD, 0xFE, 0xFF]);
    }

    #[test]
    fn test_filter_length_form_boundary_keeps_bytes() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(u32::MAX - 3, vec![0xFC, 0xFD, 0xFE, 0xFF]).unwrap(),
        ]);

        hf.filter_range(AddressRange::from_start_length(u32::MAX - 3, 4).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, u32::MAX - 3);
        assert_eq!(hf.segments()[0].data, vec![0xFC, 0xFD, 0xFE, 0xFF]);
    }

    #[test]
    fn test_filter_overflowing_length_form_clips_to_address_space() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(u32::MAX - 3, vec![0xFC, 0xFD, 0xFE, 0xFF]).unwrap(),
        ]);

        hf.filter_range(AddressRange::from_start_length(u32::MAX - 3, 8).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, u32::MAX - 3);
        assert_eq!(hf.segments()[0].data, vec![0xFC, 0xFD, 0xFE, 0xFF]);
    }

    #[test]
    fn test_fill_rejects_full_span_allocation() {
        let mut hf = HexFile::new();
        let result = hf.fill(
            AddressRange::from_start_end(0, u32::MAX).unwrap(),
            &FillOptions::default(),
        );

        assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
        assert!(hf.segments().is_empty());
    }

    #[test]
    fn test_fill_gaps() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB]).unwrap(),
            Segment::new(0x1004, vec![0xCC, 0xDD]).unwrap(),
        ]);
        hf.fill_gaps(0xFF, u64::MAX).unwrap();

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(
            hf.segments()[0].data,
            vec![0xAA, 0xBB, 0xFF, 0xFF, 0xCC, 0xDD]
        );
    }

    #[test]
    fn test_fill_gaps_rejects_span_over_limit() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x0000, vec![0xAA]).unwrap(),
            Segment::new(0x1000, vec![0xBB]).unwrap(),
        ]);
        let result = hf.fill_gaps(0xFF, 16);
        assert!(matches!(result, Err(OpsError::DenseSpanTooLarge { .. })));
        assert_eq!(hf.segments().len(), 2);
    }

    #[test]
    fn test_offset_positive() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01]).unwrap()]);
        hf.offset_addresses(0x1000).unwrap();
        assert_eq!(hf.segments()[0].start_address, 0x2000);
    }

    #[test]
    fn test_offset_negative() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x2000, vec![0x01]).unwrap()]);
        hf.offset_addresses(-0x1000).unwrap();
        assert_eq!(hf.segments()[0].start_address, 0x1000);
    }

    #[test]
    fn test_offset_underflow_errors() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01]).unwrap()]);
        let result = hf.offset_addresses(-0x2000);
        assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
        // Segment unchanged (transactional)
        assert_eq!(hf.segments()[0].start_address, 0x1000);
    }

    #[test]
    fn test_merge_overwrite() {
        let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB]).unwrap()]);
        let hf2 = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xFF]).unwrap()]);

        hf1.merge(&hf2, &MergeOptions::default()).unwrap();
        let norm = hf1.normalized();

        assert_eq!(norm.segments()[0].data, vec![0xAA, 0xFF]);
    }

    #[test]
    fn test_merge_preserve() {
        let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB]).unwrap()]);
        let hf2 = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xFF]).unwrap()]);

        hf1.merge(
            &hf2,
            &MergeOptions {
                mode: MergeMode::Preserve,
                ..Default::default()
            },
        )
        .unwrap();
        let norm = hf1.normalized();

        assert_eq!(norm.segments()[0].data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_merge_with_offset() {
        let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA]).unwrap()]);
        let hf2 = HexFile::with_segments(vec![Segment::new(0x0000, vec![0xBB]).unwrap()]);

        hf1.merge(
            &hf2,
            &MergeOptions {
                offset: 0x2000,
                ..Default::default()
            },
        )
        .unwrap();
        let norm = hf1.normalized();

        assert_eq!(norm.segments().len(), 2);
        assert_eq!(norm.segments()[1].start_address, 0x2000);
    }

    // --- Edge case tests ---

    #[test]
    fn test_filter_range_all_removed() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02]).unwrap(),
            Segment::new(0x2000, vec![0x03, 0x04]).unwrap(),
        ]);
        hf.filter_range(AddressRange::from_start_end(0x5000, 0x5FFF).unwrap());
        assert!(hf.segments().is_empty());
    }

    #[test]
    fn test_filter_ranges_empty_clears_all() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02]).unwrap()]);
        hf.filter_ranges(&[]);
        assert!(hf.segments().is_empty());
    }

    #[test]
    fn test_filter_ranges_overlapping() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x20]).unwrap()]);
        hf.filter_ranges(&[
            AddressRange::from_start_end(0x1005, 0x1015).unwrap(),
            AddressRange::from_start_end(0x1010, 0x101A).unwrap(), // overlaps
        ]);
        let norm = hf.normalized();
        // Should have data from 0x1005 to 0x101A (0x16 bytes)
        assert_eq!(norm.min_address(), Some(0x1005));
        assert_eq!(norm.max_address(), Some(0x101A));
        assert_eq!(norm.total_bytes(), 0x101A - 0x1005 + 1);
    }

    #[test]
    fn test_cut_head_only() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x10]).unwrap()]);
        hf.cut(AddressRange::from_start_end(0x1000, 0x1003).unwrap());
        assert_eq!(hf.segments()[0].start_address, 0x1004);
        assert_eq!(hf.segments()[0].len(), 0x0C);
    }

    #[test]
    fn test_cut_tail_only() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x10]).unwrap()]);
        hf.cut(AddressRange::from_start_end(0x100C, 0x100F).unwrap());
        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(hf.segments()[0].len(), 0x0C);
    }

    #[test]
    fn test_cut_multiple_ranges_on_single_segment() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x20]).unwrap()]);
        hf.cut_ranges(&[
            AddressRange::from_start_end(0x1004, 0x1007).unwrap(),
            AddressRange::from_start_end(0x1010, 0x1013).unwrap(),
        ]);
        let norm = hf.normalized();
        assert_eq!(norm.segments().len(), 3);
    }

    #[test]
    fn test_cut_spanning_multiple_segments() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01; 0x10]).unwrap(),
            Segment::new(0x1020, vec![0x02; 0x10]).unwrap(),
        ]);
        hf.cut(AddressRange::from_start_end(0x1008, 0x1027).unwrap());
        let norm = hf.normalized();
        assert_eq!(norm.segments().len(), 2);
        assert_eq!(norm.segments()[0].end_address(), 0x1007);
        assert_eq!(norm.segments()[1].start_address, 0x1028);
    }

    #[test]
    fn test_fill_overwrite_partial() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 8]).unwrap()]);
        hf.fill(
            AddressRange::from_start_length(0x1002, 4).unwrap(),
            &FillOptions {
                pattern: vec![0xFF],
                overwrite: true,
            },
        )
        .unwrap();
        let norm = hf.normalized();
        assert_eq!(
            norm.segments()[0].data,
            vec![0xAA, 0xAA, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA, 0xAA]
        );
    }

    #[test]
    fn test_fill_gaps_with_overlapping_segments() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC]).unwrap(),
            Segment::new(0x1001, vec![0xFF]).unwrap(), // overlaps
        ]);
        hf.fill_gaps(0x00, u64::MAX).unwrap();
        let seg = &hf.segments()[0];
        assert_eq!(seg.start_address, 0x1000);
        // normalized: last wins, so 0x1001 = 0xFF
        assert_eq!(seg.data, vec![0xAA, 0xFF, 0xCC]);
    }

    #[test]
    fn test_fill_gaps_single_segment() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB]).unwrap()]);
        hf.fill_gaps(0xFF, u64::MAX).unwrap();
        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_merge_with_negative_offset() {
        let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA]).unwrap()]);
        let hf2 = HexFile::with_segments(vec![Segment::new(0x3000, vec![0xBB]).unwrap()]);

        hf1.merge(
            &hf2,
            &MergeOptions {
                offset: -0x1000,
                ..Default::default()
            },
        )
        .unwrap();
        let norm = hf1.normalized();
        assert_eq!(norm.segments().len(), 2);
        assert_eq!(norm.segments()[1].start_address, 0x2000);
    }

    #[test]
    fn test_merge_with_range_filter() {
        let mut hf1 = HexFile::new();
        let hf2 = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA; 0x10]).unwrap(),
            Segment::new(0x2000, vec![0xBB; 0x10]).unwrap(),
        ]);

        hf1.merge(
            &hf2,
            &MergeOptions {
                range: Some(AddressRange::from_start_end(0x2000, 0x2FFF).unwrap()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(hf1.segments().len(), 1);
        assert_eq!(hf1.segments()[0].start_address, 0x2000);
    }

    #[test]
    fn test_merge_range_applies_before_offset() {
        let mut base = HexFile::new();
        let other = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 4]).unwrap()]);

        base.merge(
            &other,
            &MergeOptions {
                mode: MergeMode::Overwrite,
                offset: 0x1000,
                range: Some(AddressRange::from_start_end(0x1000, 0x1001).unwrap()),
            },
        )
        .unwrap();

        let norm = base.normalized();
        assert_eq!(norm.segments().len(), 1);
        assert_eq!(norm.segments()[0].start_address, 0x2000);
        assert_eq!(norm.segments()[0].len(), 2);
    }

    #[test]
    fn test_offset_overflow_errors() {
        let mut hf =
            HexFile::with_segments(vec![Segment::new(u32::MAX - 0x100, vec![0x01]).unwrap()]);
        let result = hf.offset_addresses(0x1000);
        assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
        // Unchanged
        assert_eq!(hf.segments()[0].start_address, u32::MAX - 0x100);
    }

    #[test]
    fn test_offset_segment_end_overflow_errors() {
        let mut hf =
            HexFile::with_segments(vec![Segment::new(u32::MAX - 1, vec![0xAA, 0xBB]).unwrap()]);
        let result = hf.offset_addresses(1);
        assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
        assert_eq!(hf.segments()[0].start_address, u32::MAX - 1);
    }

    #[test]
    fn test_offset_i64_min_errors() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01]).unwrap()]);
        let result = hf.offset_addresses(i64::MIN);
        assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
    }

    #[test]
    fn test_offset_large_negative_errors() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01]).unwrap()]);
        let result = hf.offset_addresses(-0x1_0000_0000_i64); // > u32::MAX
        assert!(matches!(result, Err(OpsError::AddressOverflow { .. })));
    }
}

use super::OpsError;
use crate::{AddressRange, HexFile, Segment, merge_ranges};

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
#[derive(Debug, Clone)]
pub struct MergeOptions {
    pub mode: MergeMode,
    /// Address offset to apply (can be negative)
    pub offset: i64,
    /// Only merge data within this range (applied before offset)
    pub range: Option<AddressRange>,
}

impl Default for MergeOptions {
    fn default() -> Self {
        Self {
            mode: MergeMode::Overwrite,
            offset: 0,
            range: None,
        }
    }
}

impl HexFile {
    /// Keep only data within the specified range. Clips segments that partially overlap.
    pub fn filter_range(&mut self, range: AddressRange) {
        self.filter_ranges(&[range]);
    }

    /// Keep only data within any of the specified ranges.
    pub fn filter_ranges(&mut self, ranges: &[AddressRange]) {
        if ranges.is_empty() {
            self.set_segments(Vec::new());
            return;
        }

        let merged_ranges = merge_ranges(ranges);
        let mut new_segments = Vec::new();

        for segment in self.segments() {
            if segment.is_empty() {
                continue;
            }
            let seg_range =
                match AddressRange::from_start_end(segment.start_address, segment.end_address()) {
                    Ok(r) => r,
                    Err(_) => continue,
                };

            for range in &merged_ranges {
                if let Some(intersection) = seg_range.intersection(range) {
                    let start_offset = (intersection.start() - segment.start_address) as usize;
                    let end_offset = (intersection.end() - segment.start_address) as usize + 1;
                    let data = segment.data[start_offset..end_offset].to_vec();
                    new_segments.push(Segment::new(intersection.start(), data));
                }
            }
        }

        self.set_segments(new_segments);
    }

    /// Remove all data within the specified range. Splits segments if cut is in the middle.
    pub fn cut(&mut self, range: AddressRange) {
        self.cut_ranges(&[range]);
    }

    /// Remove data within multiple ranges (operates on raw segments; preserves order).
    pub fn cut_ranges(&mut self, ranges: &[AddressRange]) {
        for range in ranges {
            let mut new_segments = Vec::new();

            for segment in self.take_segments() {
                if segment.is_empty() {
                    continue;
                }
                let seg_start = segment.start_address;
                let seg_end = segment.end_address();

                // No overlap - keep entire segment
                if seg_end < range.start() || seg_start > range.end() {
                    new_segments.push(segment);
                    continue;
                }

                // Keep portion before the cut
                if seg_start < range.start() {
                    let end_offset = (range.start() - seg_start) as usize;
                    let data = segment.data[..end_offset].to_vec();
                    new_segments.push(Segment::new(seg_start, data));
                }

                // Keep portion after the cut
                if seg_end > range.end() {
                    let start_offset = (range.end() - seg_start + 1) as usize;
                    let data = segment.data[start_offset..].to_vec();
                    new_segments.push(Segment::new(range.end() + 1, data));
                }
            }

            self.set_segments(new_segments);
        }
    }

    /// Fill a region with the specified pattern.
    /// By default (overwrite=false), only fills gaps - existing data is preserved.
    pub fn fill(&mut self, range: AddressRange, options: &FillOptions) -> Result<(), OpsError> {
        self.fill_ranges(&[range], options)
    }

    /// Fill multiple regions with the specified pattern (operates on raw segments).
    /// By default, only fills gaps - existing data is preserved.
    /// When overwrite=true, removes existing data first then fills the entire range.
    pub fn fill_ranges(
        &mut self,
        ranges: &[AddressRange],
        options: &FillOptions,
    ) -> Result<(), OpsError> {
        if options.pattern.is_empty() {
            return Ok(());
        }

        let materialized: Vec<(AddressRange, usize)> = ranges
            .iter()
            .map(|range| materialized_range_len(*range, "fill range").map(|len| (*range, len)))
            .collect::<Result<_, _>>()?;

        for (range, len) in materialized {
            if options.overwrite {
                // Remove existing data in range, then fill entire range
                self.cut(range);
                let mut data = Vec::with_capacity(len);
                let pattern = &options.pattern;
                for i in 0..len {
                    data.push(pattern[i % pattern.len()]);
                }
                self.append_segment(Segment::try_new(range.start(), data).map_err(|e| {
                    OpsError::AddressOverflow(format!("fill range exceeds u32 address space: {e}"))
                })?);
            } else {
                // Fill only gaps within the range - existing data preserved
                self.fill_gaps_in_range(range, &options.pattern)?;
            }
        }
        Ok(())
    }

    /// Fill gaps within a specific range with a pattern. Does not touch existing data.
    fn fill_gaps_in_range(&mut self, range: AddressRange, pattern: &[u8]) -> Result<(), OpsError> {
        // Collect existing data segments that overlap with the range
        let mut occupied: Vec<(u32, u32)> = Vec::new();
        for segment in self.segments() {
            if segment.is_empty() {
                continue;
            }
            let seg_start = segment.start_address;
            let seg_end = segment.end_address();

            // Check if segment overlaps with range
            if seg_end >= range.start() && seg_start <= range.end() {
                let clipped_start = seg_start.max(range.start());
                let clipped_end = seg_end.min(range.end());
                occupied.push((clipped_start, clipped_end));
            }
        }

        // Sort by start address
        occupied.sort_by_key(|&(start, _)| start);

        // Merge overlapping/adjacent intervals
        let mut merged: Vec<(u32, u32)> = Vec::new();
        for (start, end) in occupied {
            if let Some(last) = merged.last_mut()
                && start <= last.1.saturating_add(1)
            {
                // Overlapping or adjacent - extend
                last.1 = last.1.max(end);
                continue;
            }
            merged.push((start, end));
        }

        // Find gaps and fill them
        let mut cursor = range.start();
        for (occ_start, occ_end) in merged {
            if cursor < occ_start {
                // Gap from cursor to occ_start-1
                let gap_start = cursor;
                let gap_end = occ_start - 1;
                let len = (gap_end - gap_start + 1) as usize;
                let offset = (gap_start - range.start()) as usize;
                let mut data = Vec::with_capacity(len);
                for i in 0..len {
                    data.push(pattern[(offset + i) % pattern.len()]);
                }
                self.append_segment(Segment::try_new(gap_start, data).map_err(|e| {
                    OpsError::AddressOverflow(format!("fill gap exceeds u32 address space: {e}"))
                })?);
            }
            let Some(next_cursor) = occ_end.checked_add(1) else {
                return Ok(());
            };
            cursor = next_cursor;
        }

        // Fill trailing gap if any
        if cursor <= range.end() {
            let gap_start = cursor;
            let gap_end = range.end();
            let len = (gap_end - gap_start + 1) as usize;
            let offset = (gap_start - range.start()) as usize;
            let mut data = Vec::with_capacity(len);
            for i in 0..len {
                data.push(pattern[(offset + i) % pattern.len()]);
            }
            self.append_segment(Segment::try_new(gap_start, data).map_err(|e| {
                OpsError::AddressOverflow(format!("fill gap exceeds u32 address space: {e}"))
            })?);
        }
        Ok(())
    }

    /// Fill all gaps between first and last segment with fill byte.
    /// Result: single contiguous segment (normalizes with last-wins).
    pub fn fill_gaps(&mut self, fill_byte: u8) -> Result<(), OpsError> {
        let normalized = self.normalized();
        let Some(min_addr) = normalized.min_address() else {
            return Ok(());
        };
        let Some(max_addr) = normalized.max_address() else {
            return Ok(());
        };

        // Compute span in u64 to avoid overflow
        let span = (max_addr as u64) - (min_addr as u64) + 1;
        if span > u32::MAX as u64 || span > usize::MAX as u64 {
            return Err(OpsError::AddressOverflow(format!(
                "fill gaps span {span} bytes cannot be materialized"
            )));
        }

        let total_len = span as usize;
        let mut data = vec![fill_byte; total_len];

        // Copy existing data into the buffer
        for segment in normalized.segments() {
            let offset = (segment.start_address - min_addr) as usize;
            data[offset..offset + segment.len()].copy_from_slice(&segment.data);
        }

        self.set_segments(vec![Segment::try_new(min_addr, data).map_err(|e| {
            OpsError::AddressOverflow(format!("fill gaps exceeds u32 address space: {e}"))
        })?]);
        Ok(())
    }

    /// Merge another file into this one (operates on raw segments).
    pub fn merge(&mut self, other: &HexFile, options: &MergeOptions) -> Result<(), OpsError> {
        let mut other_filtered = other.clone();

        // Apply range filter if specified
        if let Some(range) = options.range {
            other_filtered.filter_range(range);
        }

        // Apply offset
        if options.offset != 0 {
            other_filtered.offset_addresses(options.offset)?;
        }

        match options.mode {
            MergeMode::Overwrite => {
                // Other data is high priority - append so it wins
                for segment in other_filtered.into_segments() {
                    self.append_segment(segment);
                }
            }
            MergeMode::Preserve => {
                // Other data is low priority - prepend so existing wins
                for segment in other_filtered.into_segments() {
                    self.prepend_segment(segment);
                }
            }
        }

        Ok(())
    }

    /// Add offset to all segment addresses. Errors if any address would overflow or underflow.
    /// If validation fails, no segments are modified (transactional).
    pub fn offset_addresses(&mut self, offset: i64) -> Result<(), OpsError> {
        // First pass: validate all addresses
        for segment in self.segments() {
            if segment.is_empty() {
                continue;
            }
            let new_addr = (segment.start_address as i64).checked_add(offset);

            let new_start = match new_addr {
                Some(addr) if addr >= 0 && addr <= u32::MAX as i64 => addr as u32,
                _ => {
                    return Err(OpsError::AddressOverflow(format!(
                        "{:#X} + {} is out of u32 range",
                        segment.start_address, offset
                    )));
                }
            };

            let length = u32::try_from(segment.len()).map_err(|_| {
                OpsError::AddressOverflow(format!(
                    "segment length {} exceeds u32 range",
                    segment.len()
                ))
            })?;
            let range =
                AddressRange::from_start_length(new_start, u64::from(length)).map_err(|_| {
                    OpsError::AddressOverflow(format!(
                        "{:#X} + {} with length {} exceeds u32 range",
                        segment.start_address,
                        offset,
                        segment.len()
                    ))
                })?;
            if range.extends_past_address_space() {
                return Err(OpsError::AddressOverflow(format!(
                    "{:#X} + {} with length {} exceeds u32 range",
                    segment.start_address,
                    offset,
                    segment.len()
                )));
            }
        }

        // Second pass: apply mutation
        for segment in self.segments_mut() {
            if segment.is_empty() {
                continue;
            }
            segment.start_address = ((segment.start_address as i64) + offset) as u32;
        }

        Ok(())
    }
}

pub(crate) fn materialized_range_len(
    range: AddressRange,
    context: &str,
) -> Result<usize, OpsError> {
    if range.extends_past_address_space() {
        return Err(OpsError::AddressOverflow(format!(
            "{context} {:#X}-{:#X} requests end {:#X} beyond u32 address space",
            range.start(),
            range.end(),
            range.requested_end()
        )));
    }
    if range.length() > u32::MAX as u64 {
        return Err(OpsError::AddressOverflow(format!(
            "{context} length {} cannot be materialized",
            range.length()
        )));
    }
    usize::try_from(range.length()).map_err(|_| {
        OpsError::AddressOverflow(format!("{context} length {} exceeds usize", range.length()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filter_range_clips_segment() {
        let mut hf = HexFile::with_segments(vec![Segment::new(
            0x1000,
            vec![0x01, 0x02, 0x03, 0x04, 0x05],
        )]);
        hf.filter_range(AddressRange::from_start_end(0x1001, 0x1003).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x1001);
        assert_eq!(hf.segments()[0].data, vec![0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_filter_range_removes_outside() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02]),
            Segment::new(0x2000, vec![0x03, 0x04]),
            Segment::new(0x3000, vec![0x05, 0x06]),
        ]);
        hf.filter_range(AddressRange::from_start_end(0x2000, 0x2FFF).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x2000);
    }

    #[test]
    fn test_filter_multiple_ranges() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x100])]);
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
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x100])]);
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
            Segment::new(0x1000, vec![0x01; 0x10]),
            Segment::new(0x2000, vec![0x02; 0x10]),
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
        let mut hf = HexFile::with_segments(vec![Segment::new(
            u32::MAX - 3,
            vec![0xFC, 0xFD, 0xFE, 0xFF],
        )]);

        hf.filter_range(AddressRange::from_start_end(0, u32::MAX).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, u32::MAX - 3);
        assert_eq!(hf.segments()[0].data, vec![0xFC, 0xFD, 0xFE, 0xFF]);
    }

    #[test]
    fn test_filter_length_form_boundary_keeps_bytes() {
        let mut hf = HexFile::with_segments(vec![Segment::new(
            u32::MAX - 3,
            vec![0xFC, 0xFD, 0xFE, 0xFF],
        )]);

        hf.filter_range(AddressRange::from_start_length(u32::MAX - 3, 4).unwrap());

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, u32::MAX - 3);
        assert_eq!(hf.segments()[0].data, vec![0xFC, 0xFD, 0xFE, 0xFF]);
    }

    #[test]
    fn test_filter_overflowing_length_form_clips_to_address_space() {
        let mut hf = HexFile::with_segments(vec![Segment::new(
            u32::MAX - 3,
            vec![0xFC, 0xFD, 0xFE, 0xFF],
        )]);

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

        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
        assert!(hf.segments().is_empty());
    }

    #[test]
    fn test_fill_rejects_range_extending_past_address_space() {
        let mut hf = HexFile::new();
        let result = hf.fill(
            AddressRange::from_start_length(u32::MAX - 3, 8).unwrap(),
            &FillOptions::default(),
        );

        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
        assert!(hf.segments().is_empty());
    }

    #[test]
    fn test_fill_gaps() {
        let mut hf = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB]),
            Segment::new(0x1004, vec![0xCC, 0xDD]),
        ]);
        hf.fill_gaps(0xFF).unwrap();

        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(
            hf.segments()[0].data,
            vec![0xAA, 0xBB, 0xFF, 0xFF, 0xCC, 0xDD]
        );
    }

    #[test]
    fn test_offset_positive() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01])]);
        hf.offset_addresses(0x1000).unwrap();
        assert_eq!(hf.segments()[0].start_address, 0x2000);
    }

    #[test]
    fn test_offset_negative() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x2000, vec![0x01])]);
        hf.offset_addresses(-0x1000).unwrap();
        assert_eq!(hf.segments()[0].start_address, 0x1000);
    }

    #[test]
    fn test_offset_underflow_errors() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01])]);
        let result = hf.offset_addresses(-0x2000);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
        // Segment unchanged (transactional)
        assert_eq!(hf.segments()[0].start_address, 0x1000);
    }

    #[test]
    fn test_merge_overwrite() {
        let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB])]);
        let hf2 = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xFF])]);

        hf1.merge(&hf2, &MergeOptions::default()).unwrap();
        let norm = hf1.normalized();

        assert_eq!(norm.segments()[0].data, vec![0xAA, 0xFF]);
    }

    #[test]
    fn test_merge_preserve() {
        let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB])]);
        let hf2 = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xFF])]);

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
        let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA])]);
        let hf2 = HexFile::with_segments(vec![Segment::new(0x0000, vec![0xBB])]);

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
            Segment::new(0x1000, vec![0x01, 0x02]),
            Segment::new(0x2000, vec![0x03, 0x04]),
        ]);
        hf.filter_range(AddressRange::from_start_end(0x5000, 0x5FFF).unwrap());
        assert!(hf.segments().is_empty());
    }

    #[test]
    fn test_filter_ranges_empty_clears_all() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02])]);
        hf.filter_ranges(&[]);
        assert!(hf.segments().is_empty());
    }

    #[test]
    fn test_filter_ranges_overlapping() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x20])]);
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
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x10])]);
        hf.cut(AddressRange::from_start_end(0x1000, 0x1003).unwrap());
        assert_eq!(hf.segments()[0].start_address, 0x1004);
        assert_eq!(hf.segments()[0].len(), 0x0C);
    }

    #[test]
    fn test_cut_tail_only() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x10])]);
        hf.cut(AddressRange::from_start_end(0x100C, 0x100F).unwrap());
        assert_eq!(hf.segments()[0].start_address, 0x1000);
        assert_eq!(hf.segments()[0].len(), 0x0C);
    }

    #[test]
    fn test_cut_multiple_ranges_on_single_segment() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01; 0x20])]);
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
            Segment::new(0x1000, vec![0x01; 0x10]),
            Segment::new(0x1020, vec![0x02; 0x10]),
        ]);
        hf.cut(AddressRange::from_start_end(0x1008, 0x1027).unwrap());
        let norm = hf.normalized();
        assert_eq!(norm.segments().len(), 2);
        assert_eq!(norm.segments()[0].end_address(), 0x1007);
        assert_eq!(norm.segments()[1].start_address, 0x1028);
    }

    #[test]
    fn test_fill_overwrite_partial() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 8])]);
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
            Segment::new(0x1000, vec![0xAA, 0xBB, 0xCC]),
            Segment::new(0x1001, vec![0xFF]), // overlaps
        ]);
        hf.fill_gaps(0x00).unwrap();
        let seg = &hf.segments()[0];
        assert_eq!(seg.start_address, 0x1000);
        // normalized: last wins, so 0x1001 = 0xFF
        assert_eq!(seg.data, vec![0xAA, 0xFF, 0xCC]);
    }

    #[test]
    fn test_fill_gaps_single_segment() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA, 0xBB])]);
        hf.fill_gaps(0xFF).unwrap();
        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_merge_with_negative_offset() {
        let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA])]);
        let hf2 = HexFile::with_segments(vec![Segment::new(0x3000, vec![0xBB])]);

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
            Segment::new(0x1000, vec![0xAA; 0x10]),
            Segment::new(0x2000, vec![0xBB; 0x10]),
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
        let other = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 4])]);

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
        let mut hf = HexFile::with_segments(vec![Segment::new(u32::MAX - 0x100, vec![0x01])]);
        let result = hf.offset_addresses(0x1000);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
        // Unchanged
        assert_eq!(hf.segments()[0].start_address, u32::MAX - 0x100);
    }

    #[test]
    fn test_offset_segment_end_overflow_errors() {
        let mut hf = HexFile::with_segments(vec![Segment::new(u32::MAX - 1, vec![0xAA, 0xBB])]);
        let result = hf.offset_addresses(1);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
        assert_eq!(hf.segments()[0].start_address, u32::MAX - 1);
    }

    #[test]
    fn test_offset_i64_min_errors() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01])]);
        let result = hf.offset_addresses(i64::MIN);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
    }

    #[test]
    fn test_offset_large_negative_errors() {
        let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01])]);
        let result = hf.offset_addresses(-0x1_0000_0000_i64); // > u32::MAX
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
    }
}

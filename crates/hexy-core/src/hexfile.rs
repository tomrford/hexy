use crate::segment::end_address_for;
use crate::{AddressRange, Segment, ops::OpsError};

/// A collection of memory segments.
///
/// Segments may overlap and preserve insertion order. Operations that iterate raw segments
/// use this order. Call `normalized()` to flatten overlaps with "last wins" semantics:
/// later-inserted segments overwrite earlier ones at the same address.
///
/// Use `append_segment` for high-priority data (wins on overlap).
/// Use `prepend_segment` for low-priority data (loses on overlap).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HexFile {
    segments: Vec<Segment>,
}

/// Where an operation writes its result bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placement {
    /// At a fixed address.
    Address(u32),
    /// Directly after the last data byte.
    Append,
    /// Over the first data bytes.
    Begin,
    /// Directly before the first data byte.
    Prepend,
    /// Over the last data bytes.
    OverwriteEnd,
}

impl HexFile {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_segments(segments: Vec<Segment>) -> Self {
        Self { segments }
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub(crate) fn segments_mut(&mut self) -> &mut [Segment] {
        &mut self.segments
    }

    pub fn into_segments(self) -> Vec<Segment> {
        self.segments
    }

    pub(crate) fn take_segments(&mut self) -> Vec<Segment> {
        std::mem::take(&mut self.segments)
    }

    pub(crate) fn set_segments(&mut self, segments: Vec<Segment>) {
        self.segments = segments;
    }

    /// Add segment with HIGH priority (wins on overlap after normalize).
    pub fn append_segment(&mut self, segment: Segment) {
        self.segments.push(segment);
    }

    /// Add segment with LOW priority (loses on overlap after normalize).
    pub fn prepend_segment(&mut self, segment: Segment) {
        self.segments.insert(0, segment);
    }

    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn min_address(&self) -> Option<u32> {
        self.segments.iter().map(Segment::start_address).min()
    }

    pub fn max_address(&self) -> Option<u32> {
        self.segments.iter().map(Segment::end_address).max()
    }

    pub fn total_bytes(&self) -> usize {
        self.segments.iter().map(Segment::len).sum()
    }

    /// Returns sorted/merged copy with overlaps resolved via "last wins" semantics.
    /// Later-inserted segments overwrite earlier ones at overlapping addresses.
    pub fn normalized(&self) -> HexFile {
        let mut sorted: Vec<&Segment> = self.segments.iter().collect();
        sorted.sort_by_key(|s| s.start_address);
        let has_overlap = sorted
            .windows(2)
            .any(|pair| pair[1].start_address <= pair[0].end_address());

        let segments = if has_overlap {
            let mut merged: Vec<Segment> = Vec::new();
            for seg in &self.segments {
                merged = overlay_segment(merged, seg.clone());
            }
            merged
        } else {
            sorted.into_iter().cloned().collect()
        };
        HexFile {
            segments: merge_adjacent_segments(segments),
        }
    }

    /// Count gaps between segments (after sorting).
    pub fn gap_count(&self) -> usize {
        self.normalized().segments.len().saturating_sub(1)
    }

    // --- Address-based access ---

    /// Read a single byte at address. Returns None if address is not covered by any segment.
    /// If multiple segments overlap, the most recently added segment wins.
    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        self.segments.iter().rev().find_map(|seg| {
            let offset = addr.checked_sub(seg.start_address)?;
            seg.data.get(offset as usize).copied()
        })
    }

    /// Read bytes from address range. Returns None for gaps.
    pub fn read_bytes(&self, addr: u32, len: usize) -> Vec<Option<u8>> {
        (0..len)
            .map(|i| {
                let offset = u32::try_from(i).ok()?;
                self.read_byte(addr.checked_add(offset)?)
            })
            .collect()
    }

    /// Read bytes from address range. Returns None if any address in range is not covered.
    pub fn read_bytes_contiguous(&self, addr: u32, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        let end = end_address_for(addr, len)?;
        let normalized = self.normalized();
        let segment = normalized
            .segments
            .iter()
            .find(|s| s.start_address <= addr && end <= s.end_address())?;
        let offset = (addr - segment.start_address) as usize;
        Some(segment.data[offset..offset + len].to_vec())
    }

    /// Write bytes at address. Creates new segment, will overlap with existing data.
    /// Use normalized() after to merge and resolve overlaps.
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> Result<(), OpsError> {
        if !data.is_empty() {
            self.segments.push(Segment::new(addr, data.to_vec())?);
        }
        Ok(())
    }

    /// The address range `len` bytes occupy when written at `placement`, or `None` when
    /// the placement is relative to data and the file is empty.
    pub fn placement_range(
        &self,
        placement: Placement,
        len: usize,
    ) -> Result<Option<AddressRange>, OpsError> {
        let overflow = |address| OpsError::AddressOverflow { address };
        let len32 = u32::try_from(len).map_err(|_| overflow(0))?;
        let start = match placement {
            Placement::Address(addr) => Some(addr),
            Placement::Begin => self.min_address(),
            Placement::Append => self
                .max_address()
                .map(|end| end.checked_add(1).ok_or(overflow(end)))
                .transpose()?,
            Placement::Prepend => self
                .min_address()
                .map(|start| start.checked_sub(len32).ok_or(overflow(start)))
                .transpose()?,
            Placement::OverwriteEnd => self
                .max_address()
                .map(|end| {
                    end.checked_sub(len32.saturating_sub(1))
                        .ok_or(overflow(end))
                })
                .transpose()?,
        };
        let Some(start) = start else {
            return Ok(None);
        };
        let end = end_address_for(start, len).ok_or(overflow(start))?;
        Ok(Some(AddressRange::new_valid(start, end)))
    }

    /// Return a single contiguous segment spanning min..=max with gaps filled, using a
    /// normalized (last-wins) snapshot. Returns `None` when empty and an error when the
    /// span exceeds `limit` bytes (capped at the largest segment length, `u32::MAX`).
    pub fn as_contiguous(&self, fill_byte: u8, limit: u64) -> Result<Option<Segment>, OpsError> {
        let normalized = self.normalized();
        let (Some(min), Some(max)) = (normalized.min_address(), normalized.max_address()) else {
            return Ok(None);
        };
        let span = u64::from(max - min) + 1;
        let limit = limit.min(u64::from(u32::MAX));
        if span > limit {
            return Err(OpsError::DenseSpanTooLarge { span, limit });
        }
        let mut data = vec![fill_byte; span as usize];
        for segment in normalized.segments {
            let offset = (segment.start_address - min) as usize;
            data[offset..offset + segment.len()].copy_from_slice(&segment.data);
        }
        Ok(Some(Segment::from_valid(min, data)))
    }
}

fn merge_adjacent_segments(segments: Vec<Segment>) -> Vec<Segment> {
    let mut merged: Vec<Segment> = Vec::with_capacity(segments.len());
    for seg in segments {
        if let Some(last) = merged.last_mut()
            && last.is_contiguous_with(&seg)
        {
            last.data.extend(seg.data);
            continue;
        }
        merged.push(seg);
    }
    merged
}

/// Overlay `seg` onto sorted, non-overlapping `segments`, keeping the result sorted.
fn overlay_segment(segments: Vec<Segment>, seg: Segment) -> Vec<Segment> {
    let seg_start = seg.start_address;
    let seg_end = seg.end_address();
    let mut next: Vec<Segment> = Vec::with_capacity(segments.len() + 2);
    let mut new_seg = Some(seg);

    for cur in segments {
        if cur.end_address() < seg_start {
            next.push(cur);
            continue;
        }
        if cur.start_address > seg_end {
            next.extend(new_seg.take());
            next.push(cur);
            continue;
        }
        if cur.start_address < seg_start {
            let left_len = (seg_start - cur.start_address) as usize;
            next.push(Segment::from_valid(
                cur.start_address,
                cur.data[..left_len].to_vec(),
            ));
        }
        if cur.end_address() > seg_end {
            next.extend(new_seg.take());
            let right_offset = (seg_end - cur.start_address) as usize + 1;
            next.push(Segment::from_valid(
                seg_end + 1,
                cur.data[right_offset..].to_vec(),
            ));
        }
    }
    next.extend(new_seg);
    next
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

    #[test]
    fn test_normalized_merges_contiguous() {
        let norm = hf(&[(0x100, &[0x01, 0x02]), (0x102, &[0x03, 0x04])]).normalized();
        assert_eq!(norm.segments.len(), 1);
        assert_eq!(norm.segments[0].start_address, 0x100);
        assert_eq!(norm.segments[0].data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_normalized_preserves_gaps_and_sorts() {
        let norm = hf(&[(0x300, &[0x03]), (0x100, &[0x01]), (0x200, &[0x02])]).normalized();
        let starts: Vec<u32> = norm.segments.iter().map(|s| s.start_address).collect();
        assert_eq!(starts, vec![0x100, 0x200, 0x300]);
    }

    #[test]
    fn test_normalized_last_wins() {
        let norm = hf(&[(0x100, &[0x01, 0x02, 0x03]), (0x101, &[0xFF])]).normalized();
        assert_eq!(norm.segments.len(), 1);
        assert_eq!(norm.segments[0].data, vec![0x01, 0xFF, 0x03]);
    }

    #[test]
    fn test_normalized_multiple_overlaps_last_wins() {
        let norm = hf(&[
            (0x100, &[0x01, 0x01, 0x01, 0x01]),
            (0x102, &[0x02, 0x02]),
            (0x101, &[0x03, 0x03, 0x03]),
        ])
        .normalized();
        assert_eq!(norm.segments.len(), 1);
        assert_eq!(norm.segments[0].data, vec![0x01, 0x03, 0x03, 0x03]);
    }

    #[test]
    fn test_normalized_overlap_at_address_space_end() {
        let norm = hf(&[(u32::MAX - 1, &[0x01, 0x02]), (u32::MAX, &[0xFF])]).normalized();
        assert_eq!(
            norm.segments,
            vec![Segment::new(u32::MAX - 1, vec![0x01, 0xFF]).unwrap()]
        );
    }

    #[test]
    fn test_write_bytes_rejects_overflow() {
        let mut hf = HexFile::new();
        let result = hf.write_bytes(u32::MAX, &[0xAA, 0xBB]);
        assert!(matches!(result, Err(OpsError::Segment(_))));
        assert!(hf.segments.is_empty());
    }

    #[test]
    fn test_read_byte_last_wins() {
        let hf = hf(&[(0x100, &[0xAA, 0xBB, 0xCC]), (0x101, &[0xFF])]);
        assert_eq!(hf.read_byte(0x100), Some(0xAA));
        assert_eq!(hf.read_byte(0x101), Some(0xFF));
        assert_eq!(hf.read_byte(0x103), None);
        assert_eq!(hf.read_byte(0x0FF), None);
        assert_eq!(hf.read_bytes(0x102, 3), vec![Some(0xCC), None, None]);
    }

    #[test]
    fn test_read_bytes_contiguous() {
        let hf = hf(&[(0x100, &[0xAA, 0xBB, 0xCC]), (u32::MAX, &[0xEE])]);
        assert_eq!(
            hf.read_bytes_contiguous(0x100, 3),
            Some(vec![0xAA, 0xBB, 0xCC])
        );
        assert_eq!(hf.read_bytes_contiguous(0x100, 4), None);
        assert_eq!(hf.read_bytes_contiguous(u32::MAX, 1), Some(vec![0xEE]));
        assert_eq!(hf.read_bytes_contiguous(u32::MAX - 1, 2), None);
    }

    #[test]
    fn test_as_contiguous_fills_gaps_and_respects_limit() {
        let hf = hf(&[(0x100, &[0xAA]), (0x102, &[0xCC])]);
        let seg = hf.as_contiguous(0xFF, 3).unwrap().unwrap();
        assert_eq!(seg.start_address, 0x100);
        assert_eq!(seg.data, vec![0xAA, 0xFF, 0xCC]);
        assert!(matches!(
            hf.as_contiguous(0xFF, 2),
            Err(OpsError::DenseSpanTooLarge { span: 3, limit: 2 })
        ));
        assert_eq!(HexFile::new().as_contiguous(0xFF, 3).unwrap(), None);
    }

    #[test]
    fn test_placement_range() {
        let hf = hf(&[(0x1000, &[0x01; 4])]);
        let range = |p| {
            hf.placement_range(p, 2)
                .unwrap()
                .map(|r| (r.start(), r.end()))
        };
        assert_eq!(range(Placement::Address(0x10)), Some((0x10, 0x11)));
        assert_eq!(range(Placement::Append), Some((0x1004, 0x1005)));
        assert_eq!(range(Placement::Begin), Some((0x1000, 0x1001)));
        assert_eq!(range(Placement::Prepend), Some((0x0FFE, 0x0FFF)));
        assert_eq!(range(Placement::OverwriteEnd), Some((0x1002, 0x1003)));
        assert_eq!(
            HexFile::new()
                .placement_range(Placement::Append, 2)
                .unwrap(),
            None
        );
        assert!(hf.placement_range(Placement::Address(u32::MAX), 2).is_err());
        assert!(hf.placement_range(Placement::Prepend, 0x1001).is_err());
    }

    #[test]
    fn test_gap_count_with_overlap_and_gap() {
        assert_eq!(
            hf(&[(0x1000, &[0xAA, 0xBB]), (0x1001, &[0xCC])]).gap_count(),
            0
        );
        assert_eq!(hf(&[(0x1000, &[0xAA]), (0x1002, &[0xBB])]).gap_count(), 1);
    }
}

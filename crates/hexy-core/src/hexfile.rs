use crate::{Segment, ops::OpsError};

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

impl HexFile {
    pub fn new() -> Self {
        Self { segments: vec![] }
    }

    pub fn with_segments(segments: Vec<Segment>) -> Self {
        Self {
            segments: segments.into_iter().filter(|s| !s.is_empty()).collect(),
        }
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn segments_mut(&mut self) -> &mut [Segment] {
        &mut self.segments
    }

    pub fn into_segments(self) -> Vec<Segment> {
        self.segments
    }

    /// Take all segments out, leaving the HexFile empty.
    pub fn take_segments(&mut self) -> Vec<Segment> {
        std::mem::take(&mut self.segments)
    }

    pub fn set_segments(&mut self, segments: Vec<Segment>) {
        self.segments = segments.into_iter().filter(|s| !s.is_empty()).collect();
    }

    /// Add segment with HIGH priority (wins on overlap after normalize).
    pub fn append_segment(&mut self, segment: Segment) {
        if segment.is_empty() {
            return;
        }
        self.segments.push(segment);
    }

    /// Add segment with LOW priority (loses on overlap after normalize).
    pub fn prepend_segment(&mut self, segment: Segment) {
        if segment.is_empty() {
            return;
        }
        self.segments.insert(0, segment);
    }

    pub fn is_empty(&self) -> bool {
        self.segments.iter().all(|s| s.is_empty())
    }

    pub fn min_address(&self) -> Option<u32> {
        self.segments
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.start_address)
            .min()
    }

    pub fn max_address(&self) -> Option<u32> {
        self.segments
            .iter()
            .filter(|s| !s.is_empty())
            .map(|s| s.end_address())
            .max()
    }

    /// Span start across all segments (raw order).
    pub fn span_start(&self) -> Option<u32> {
        self.min_address()
    }

    /// Span end across all segments (raw order).
    pub fn span_end(&self) -> Option<u32> {
        self.max_address()
    }

    pub fn total_bytes(&self) -> usize {
        self.segments.iter().map(|s| s.len()).sum()
    }

    /// Returns sorted/merged copy with overlaps resolved via "last wins" semantics.
    /// Later-inserted segments overwrite earlier ones at overlapping addresses.
    pub fn normalized(&self) -> HexFile {
        let mut segments: Vec<Segment> = self
            .segments
            .iter()
            .filter(|segment| !segment.is_empty())
            .cloned()
            .collect();

        if segments.is_empty() {
            return HexFile::new();
        }

        let mut sorted_refs: Vec<&Segment> = segments.iter().collect();
        sorted_refs.sort_by_key(|s| s.start_address);
        let mut has_overlap = false;
        let mut last_end = sorted_refs[0].end_address();
        for seg in sorted_refs.iter().skip(1) {
            if seg.start_address <= last_end {
                has_overlap = true;
                break;
            }
            last_end = seg.end_address();
        }

        if !has_overlap {
            segments.sort_by_key(|s| s.start_address);
            return HexFile {
                segments: merge_adjacent_segments(segments),
            };
        }

        let mut merged: Vec<Segment> = Vec::new();
        for seg in segments {
            merged = overlay_segment(merged, seg);
        }
        merged.sort_by_key(|s| s.start_address);
        HexFile {
            segments: merge_adjacent_segments(merged),
        }
    }

    /// Count gaps between segments (after sorting).
    pub fn gap_count(&self) -> usize {
        let segments = self.normalized().into_segments();
        if segments.len() <= 1 {
            return 0;
        }
        segments.len() - 1
    }

    // --- Address-based access ---

    /// Read a single byte at address. Returns None if address is not covered by any segment.
    /// If multiple segments overlap, the most recently added segment wins.
    pub fn read_byte(&self, addr: u32) -> Option<u8> {
        for seg in self.segments.iter().rev() {
            if seg.is_empty() {
                continue;
            }
            if addr >= seg.start_address && addr <= seg.end_address() {
                let offset = (addr - seg.start_address) as usize;
                if offset < seg.data.len() {
                    return Some(seg.data[offset]);
                }
            }
        }
        None
    }

    /// Read bytes from address range. Returns None for gaps.
    pub fn read_bytes(&self, addr: u32, len: usize) -> Vec<Option<u8>> {
        (0..len)
            .map(|i| {
                let offset = u32::try_from(i).ok()?;
                let a = addr.checked_add(offset)?;
                self.read_byte(a)
            })
            .collect()
    }

    /// Read bytes from address range. Returns None if any address in range is not covered.
    pub fn read_bytes_contiguous(&self, addr: u32, len: usize) -> Option<Vec<u8>> {
        if len == 0 {
            return Some(Vec::new());
        }
        let len_u32 = u32::try_from(len).ok()?;
        let end = addr.checked_add(len_u32).and_then(|v| v.checked_sub(1))?;
        let normalized = self.normalized();
        for segment in normalized.segments() {
            if end < segment.start_address {
                break;
            }
            if addr >= segment.start_address && end <= segment.end_address() {
                let offset = (addr - segment.start_address) as usize;
                return Some(segment.data[offset..offset + len].to_vec());
            }
        }
        None
    }

    /// Write bytes at address. Creates new segment, will overlap with existing data.
    /// Use normalized() after to merge and resolve overlaps.
    pub fn write_bytes(&mut self, addr: u32, data: &[u8]) -> Result<(), OpsError> {
        if data.is_empty() {
            return Ok(());
        }
        let segment = Segment::try_new(addr, data.to_vec()).map_err(|e| {
            OpsError::AddressOverflow(format!(
                "write at {addr:#X} with length {} exceeds u32 address space: {e}",
                data.len()
            ))
        })?;
        self.segments.push(segment);
        Ok(())
    }

    /// Return a single contiguous segment spanning min..=max with gaps filled.
    /// Uses a normalized (last-wins) snapshot. Returns None if empty or too large.
    pub fn as_contiguous(&self, fill_byte: u8) -> Option<Segment> {
        let normalized = self.normalized();
        let min_addr = normalized.min_address()?;
        let max_addr = normalized.max_address()?;
        let span = (max_addr as u64) - (min_addr as u64) + 1;
        if span > u32::MAX as u64 || span > usize::MAX as u64 {
            return None;
        }
        let total_len = span as usize;
        let mut data = vec![fill_byte; total_len];
        for segment in normalized.segments() {
            let offset = (segment.start_address - min_addr) as usize;
            data[offset..offset + segment.len()].copy_from_slice(&segment.data);
        }
        Segment::try_new(min_addr, data).ok()
    }
}

fn merge_adjacent_segments(segments: Vec<Segment>) -> Vec<Segment> {
    let mut merged: Vec<Segment> = Vec::with_capacity(segments.len());
    for seg in segments {
        if let Some(last) = merged.last_mut()
            && last.is_contiguous_with(&seg)
        {
            last.data.extend_from_slice(&seg.data);
            continue;
        }
        merged.push(seg);
    }
    merged
}

fn overlay_segment(segments: Vec<Segment>, seg: Segment) -> Vec<Segment> {
    if segments.is_empty() {
        return vec![seg];
    }
    let seg_start = seg.start_address;
    let seg_end = seg.end_address();
    let mut next: Vec<Segment> = Vec::with_capacity(segments.len() + 1);
    let mut new_seg = Some(seg);

    for cur in segments {
        if cur.end_address() < seg_start {
            next.push(cur);
            continue;
        }
        if cur.start_address > seg_end {
            if let Some(seg) = new_seg.take() {
                next.push(seg);
            }
            next.push(cur);
            continue;
        }

        if cur.start_address < seg_start {
            let left_len = (seg_start - cur.start_address) as usize;
            if left_len > 0 {
                next.push(Segment::new(
                    cur.start_address,
                    cur.data[..left_len].to_vec(),
                ));
            }
        }

        if cur.end_address() > seg_end {
            if let Some(seg) = new_seg.take() {
                next.push(seg);
            }
            if let Some(right_start) = seg_end.checked_add(1) {
                let right_offset = (right_start - cur.start_address) as usize;
                if right_offset < cur.data.len() {
                    next.push(Segment::new(right_start, cur.data[right_offset..].to_vec()));
                }
            }
        }
    }

    if let Some(seg) = new_seg.take() {
        next.push(seg);
    }

    merge_adjacent_segments(next)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalized_merges_contiguous() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x100, vec![0x01, 0x02]),
            Segment::new(0x102, vec![0x03, 0x04]),
        ]);
        let norm = hf.normalized();
        assert_eq!(norm.segments.len(), 1);
        assert_eq!(norm.segments[0].start_address, 0x100);
        assert_eq!(norm.segments[0].data, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_normalized_preserves_gaps() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x100, vec![0x01, 0x02]),
            Segment::new(0x200, vec![0x03, 0x04]),
        ]);
        let norm = hf.normalized();
        assert_eq!(norm.segments.len(), 2);
    }

    #[test]
    fn test_normalized_last_wins() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x100, vec![0x01, 0x02, 0x03]),
            Segment::new(0x101, vec![0xFF]),
        ]);
        let norm = hf.normalized();
        assert_eq!(norm.segments.len(), 1);
        assert_eq!(norm.segments[0].data, vec![0x01, 0xFF, 0x03]);
    }

    #[test]
    fn test_normalized_multiple_overlaps_last_wins() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x100, vec![0x01, 0x01, 0x01, 0x01]),
            Segment::new(0x102, vec![0x02, 0x02]),
            Segment::new(0x101, vec![0x03, 0x03, 0x03]),
        ]);
        let norm = hf.normalized();
        assert_eq!(norm.segments.len(), 1);
        assert_eq!(norm.segments[0].data, vec![0x01, 0x03, 0x03, 0x03]);
    }

    #[test]
    fn test_write_bytes_rejects_overflow() {
        let mut hf = HexFile::new();
        let result = hf.write_bytes(u32::MAX, &[0xAA, 0xBB]);
        assert!(matches!(result, Err(OpsError::AddressOverflow(_))));
        assert!(hf.segments.is_empty());
    }

    #[test]
    fn test_read_byte() {
        let hf = HexFile::with_segments(vec![Segment::new(0x100, vec![0xAA, 0xBB, 0xCC])]);
        assert_eq!(hf.read_byte(0x100), Some(0xAA));
        assert_eq!(hf.read_byte(0x101), Some(0xBB));
        assert_eq!(hf.read_byte(0x102), Some(0xCC));
        assert_eq!(hf.read_byte(0x103), None);
        assert_eq!(hf.read_byte(0x0FF), None);
    }

    #[test]
    fn test_read_bytes_with_gaps() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x100, vec![0xAA]),
            Segment::new(0x102, vec![0xCC]),
        ]);
        let result = hf.read_bytes(0x100, 3);
        assert_eq!(result, vec![Some(0xAA), None, Some(0xCC)]);
    }

    #[test]
    fn test_read_bytes_contiguous() {
        let hf = HexFile::with_segments(vec![Segment::new(0x100, vec![0xAA, 0xBB, 0xCC])]);
        assert_eq!(
            hf.read_bytes_contiguous(0x100, 3),
            Some(vec![0xAA, 0xBB, 0xCC])
        );
        assert_eq!(hf.read_bytes_contiguous(0x100, 4), None);
    }

    #[test]
    fn test_write_bytes() {
        let mut hf = HexFile::new();
        hf.write_bytes(0x100, &[0x01, 0x02]).unwrap();
        hf.write_bytes(0x101, &[0xFF]).unwrap(); // overlaps
        let norm = hf.normalized();
        assert_eq!(norm.segments[0].data, vec![0x01, 0xFF]);
    }

    #[test]
    fn test_sorted_order() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x300, vec![0x03]),
            Segment::new(0x100, vec![0x01]),
            Segment::new(0x200, vec![0x02]),
        ]);
        let norm = hf.normalized();
        assert_eq!(norm.segments[0].start_address, 0x100);
        assert_eq!(norm.segments[1].start_address, 0x200);
        assert_eq!(norm.segments[2].start_address, 0x300);
    }

    #[test]
    fn test_as_contiguous_fills_gaps() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x100, vec![0xAA]),
            Segment::new(0x102, vec![0xCC]),
        ]);
        let seg = hf.as_contiguous(0xFF).unwrap();
        assert_eq!(seg.start_address, 0x100);
        assert_eq!(seg.data, vec![0xAA, 0xFF, 0xCC]);
    }

    #[test]
    fn test_span_start_end() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x300, vec![0x03]),
            Segment::new(0x100, vec![0x01, 0x02]),
        ]);
        assert_eq!(hf.span_start(), Some(0x100));
        assert_eq!(hf.span_end(), Some(0x300));
    }

    #[test]
    fn test_read_byte_ignores_empty_segments() {
        let mut hf = HexFile::new();
        hf.append_segment(Segment::new(0x1000, vec![]));
        assert_eq!(hf.read_byte(0x1000), None);

        hf.append_segment(Segment::new(0x1000, vec![0xAA]));
        assert_eq!(hf.read_byte(0x1000), Some(0xAA));
    }

    #[test]
    fn test_gap_count_with_overlap_and_gap() {
        let hf_overlap = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB]),
            Segment::new(0x1001, vec![0xCC]),
        ]);
        assert_eq!(hf_overlap.gap_count(), 0);

        let hf_gap = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA]),
            Segment::new(0x1002, vec![0xBB]),
        ]);
        assert_eq!(hf_gap.gap_count(), 1);
    }
}

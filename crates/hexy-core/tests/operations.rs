//! Integration tests for operation combinations.
//!
//! These tests verify that chaining multiple operations produces correct results.

use hexy_core::{
    AddressRange, AlignOptions, FillOptions, HexFile, MergeMode, MergeOptions, Segment, SwapMode,
};

// --- Cut → Fill → Normalize ---

#[test]
fn test_cut_fill_normalize() {
    // Start with two segments with a gap
    let mut hf = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0xAA; 0x20]),
        Segment::new(0x1040, vec![0xBB; 0x20]),
    ]);

    // Cut a subrange from the first segment
    hf.cut(AddressRange::from_start_end(0x1008, 0x100F).unwrap());

    // Fill the cut range with a pattern
    hf.fill(
        AddressRange::from_start_length(0x1008, 8).unwrap(),
        &FillOptions {
            pattern: vec![0xCC],
            overwrite: false,
        },
    )
    .unwrap();

    let norm = hf.normalized();

    // The first segment should now have 0xAA, then 0xCC fill, then 0xAA
    assert_eq!(norm.segments()[0].start_address, 0x1000);
    // Check the filled region
    let filled_data = norm.read_bytes_contiguous(0x1008, 8).unwrap();
    assert_eq!(filled_data, vec![0xCC; 8]);
}

// --- Merge → Align → Normalize ---

#[test]
fn test_merge_align_normalize_overwrite() {
    let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA; 8])]);
    let hf2 = HexFile::with_segments(vec![Segment::new(0x1003, vec![0xBB; 4])]);

    // Merge with overwrite mode
    hf1.merge(&hf2, &MergeOptions::default()).unwrap();

    // Align to 4 bytes
    hf1.align(&AlignOptions {
        alignment: 4,
        fill_byte: 0xFF,
        align_length: true,
    })
    .unwrap();

    let norm = hf1.normalized();

    // After merge (overwrite): 0x1003-0x1006 should be 0xBB
    // After align: starts at 0x1000
    assert_eq!(norm.segments()[0].start_address, 0x1000);

    // Check that merged bytes are present (BB overwrote AA at 0x1003-0x1006)
    let data = norm.read_bytes_contiguous(0x1003, 4).unwrap();
    assert_eq!(data, vec![0xBB; 4]);
}

#[test]
fn test_merge_align_normalize_preserve() {
    let mut hf1 = HexFile::with_segments(vec![Segment::new(0x1001, vec![0xAA; 8])]);
    let hf2 = HexFile::with_segments(vec![Segment::new(0x1003, vec![0xBB; 4])]);

    // Merge with preserve mode
    hf1.merge(
        &hf2,
        &MergeOptions {
            mode: MergeMode::Preserve,
            ..Default::default()
        },
    )
    .unwrap();

    let norm = hf1.normalized();

    // Existing data (AA) should be preserved at overlap
    let data = norm.read_bytes_contiguous(0x1003, 4).unwrap();
    assert_eq!(data, vec![0xAA; 4]);
}

// --- Scale → Unscale round-trip ---

#[test]
fn test_scale_unscale_roundtrip() {
    let original = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0xAA, 0xBB]),
        Segment::new(0x2000, vec![0xCC, 0xDD]),
        Segment::new(0x3000, vec![0xEE, 0xFF]),
    ]);

    let mut hf = original.clone();
    hf.scale_addresses(4).unwrap();

    // Check scaled addresses
    assert_eq!(hf.segments()[0].start_address, 0x4000);
    assert_eq!(hf.segments()[1].start_address, 0x8000);
    assert_eq!(hf.segments()[2].start_address, 0xC000);

    hf.unscale_addresses(4).unwrap();

    // Should be back to original
    assert_eq!(
        hf.segments()[0].start_address,
        original.segments()[0].start_address
    );
    assert_eq!(
        hf.segments()[1].start_address,
        original.segments()[1].start_address
    );
    assert_eq!(
        hf.segments()[2].start_address,
        original.segments()[2].start_address
    );

    // Data unchanged
    assert_eq!(hf.segments()[0].data, original.segments()[0].data);
}

// --- Align → Split ---

#[test]
fn test_align_then_split() {
    let mut hf = HexFile::with_segments(vec![Segment::new(0x1003, vec![0xAA; 29])]);

    // Align to 8-byte boundary with length alignment
    hf.align(&AlignOptions {
        alignment: 8,
        fill_byte: 0xFF,
        align_length: true,
    })
    .unwrap();

    // After align: start at 0x1000 (3 prepended), length becomes 32 (next multiple of 8)
    assert_eq!(hf.segments()[0].start_address, 0x1000);
    assert_eq!(hf.segments()[0].len(), 32);

    // Split into 8-byte chunks
    hf.split(8);

    assert_eq!(hf.segments().len(), 4);
    for (i, seg) in hf.segments().iter().enumerate() {
        assert_eq!(seg.start_address, 0x1000 + (i as u32) * 8);
        assert_eq!(seg.len(), 8);
    }
}

// --- Fill gaps → Merge ---

#[test]
fn test_fill_gaps_then_merge_overwrite() {
    // File A: sparse segments with gaps
    let mut hf_a = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0xAA; 4]),
        Segment::new(0x1010, vec![0xBB; 4]),
    ]);

    // Fill gaps
    hf_a.fill_gaps(0x00).unwrap();

    // Now it's contiguous 0x1000-0x1013, gaps filled with 0x00
    assert_eq!(hf_a.segments().len(), 1);
    assert_eq!(hf_a.segments()[0].len(), 0x14);

    // File B: overlaps with filled region
    let hf_b = HexFile::with_segments(vec![Segment::new(0x1008, vec![0xCC; 4])]);

    // Merge with overwrite
    hf_a.merge(&hf_b, &MergeOptions::default()).unwrap();

    let norm = hf_a.normalized();

    // Check that merged data overwrote the filled zeros
    let data = norm.read_bytes_contiguous(0x1008, 4).unwrap();
    assert_eq!(data, vec![0xCC; 4]);

    // Original data still intact
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 4).unwrap(),
        vec![0xAA; 4]
    );
    assert_eq!(
        norm.read_bytes_contiguous(0x1010, 4).unwrap(),
        vec![0xBB; 4]
    );
}

#[test]
fn test_fill_gaps_then_merge_preserve() {
    let mut hf_a = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0xAA; 4]),
        Segment::new(0x1010, vec![0xBB; 4]),
    ]);
    hf_a.fill_gaps(0x00).unwrap();

    let hf_b = HexFile::with_segments(vec![Segment::new(0x1008, vec![0xCC; 4])]);

    hf_a.merge(
        &hf_b,
        &MergeOptions {
            mode: MergeMode::Preserve,
            ..Default::default()
        },
    )
    .unwrap();

    let norm = hf_a.normalized();

    // Existing filled zeros should be preserved (they were in hf_a which goes last in preserve mode)
    let data = norm.read_bytes_contiguous(0x1008, 4).unwrap();
    assert_eq!(data, vec![0x00; 4]);
}

// --- Swap → Read contiguously ---

#[test]
fn test_swap_and_read() {
    let original_data = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, original_data.clone())]);

    hf.swap_bytes(SwapMode::Word).unwrap();

    let swapped = hf.read_bytes_contiguous(0x1000, 8).unwrap();
    assert_eq!(
        swapped,
        vec![0x02, 0x01, 0x04, 0x03, 0x06, 0x05, 0x08, 0x07]
    );

    // Swap again to get back to original
    hf.swap_bytes(SwapMode::Word).unwrap();
    let restored = hf.read_bytes_contiguous(0x1000, 8).unwrap();
    assert_eq!(restored, original_data);
}

// --- Complex multi-operation chain ---

#[test]
fn test_filter_cut_fill_align_split() {
    // Large segment
    let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 0x100])]);

    // Filter to keep only part
    hf.filter_range(AddressRange::from_start_end(0x1020, 0x10FF).unwrap());

    // Cut out a middle section
    hf.cut(AddressRange::from_start_end(0x1040, 0x105F).unwrap());

    // Fill the cut section
    hf.fill(
        AddressRange::from_start_length(0x1040, 0x20).unwrap(),
        &FillOptions {
            pattern: vec![0xBB],
            overwrite: false,
        },
    )
    .unwrap();

    // Align to 16 bytes
    hf.align(&AlignOptions {
        alignment: 16,
        fill_byte: 0xFF,
        align_length: true,
    })
    .unwrap();

    // Fill gaps to merge everything
    hf.fill_gaps(0x00).unwrap();

    // Now we have a single contiguous segment - verify data integrity
    let norm = hf.normalized();

    // After fill_gaps, we have one contiguous segment
    assert_eq!(norm.segments().len(), 1);

    // Verify data integrity
    let all_bytes = &norm.segments()[0].data;

    // Should contain 0xBB (filled) and 0xAA (original)
    assert!(all_bytes.contains(&0xAA));
    assert!(all_bytes.contains(&0xBB));

    // Now split it
    let mut hf2 = norm;
    hf2.split(32);
    assert!(hf2.segments().len() > 1);
}

// --- Edge case: Operations on empty file ---

#[test]
fn test_operations_on_empty_file() {
    let mut hf = HexFile::new();

    // None of these should panic (scale/offset on empty are no-ops)
    hf.filter_range(AddressRange::from_start_end(0x1000, 0x1FFF).unwrap());
    hf.cut(AddressRange::from_start_end(0x1000, 0x1FFF).unwrap());
    hf.fill_gaps(0xFF).unwrap();
    hf.scale_addresses(2).unwrap();
    hf.offset_addresses(0x1000).unwrap();
    hf.split(16);
    hf.align(&AlignOptions::default()).unwrap();

    assert!(hf.segments().is_empty());
}

// --- Normalization uses last-wins overlap resolution ---

#[test]
fn test_normalized_last_wins_on_overlap() {
    let hf = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0xAA; 8]),
        Segment::new(0x1004, vec![0xBB; 4]), // overlaps
    ]);

    let norm = hf.normalized();
    assert_eq!(norm.segments().len(), 1);

    // 0x1000-0x1003 = 0xAA (from first)
    // 0x1004-0x1007 = 0xBB (from second, overwrites)
    let data = norm.read_bytes_contiguous(0x1000, 8).unwrap();
    assert_eq!(data, vec![0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xBB, 0xBB, 0xBB]);
}

// --- Three overlapping segments (verify last-wins per-byte) ---

#[test]
fn test_three_overlapping_segments_last_wins() {
    let hf = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0x11, 0x11, 0x11, 0x11]),
        Segment::new(0x1001, vec![0x22, 0x22]),
        Segment::new(0x1002, vec![0x33]),
    ]);

    let norm = hf.normalized();
    let data = norm.read_bytes_contiguous(0x1000, 4).unwrap();

    // 0x1000 = 0x11 (only first covers it)
    // 0x1001 = 0x22 (second overwrites first)
    // 0x1002 = 0x33 (third overwrites both)
    // 0x1003 = 0x11 (only first covers it)
    assert_eq!(data, vec![0x11, 0x22, 0x33, 0x11]);
}

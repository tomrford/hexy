//! Integration tests based on cleanroom compatibility documentation.
//!
//! Focus: multi-stage operations and command semantics.

use hexy_core::{AddressRange, FillOptions, HexFile, MergeMode, MergeOptions, Segment};

#[test]
fn test_fill_region_preserves_existing_data() {
    // /FR with /FP should fill gaps and preserve existing bytes.
    let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 8]).unwrap()]);

    hf.fill(
        AddressRange::from_start_end(0x1004, 0x100B).unwrap(),
        &FillOptions {
            pattern: vec![0x11, 0x22],
            overwrite: false,
        },
    )
    .unwrap();

    let norm = hf.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1004, 4).unwrap(),
        vec![0xAA; 4]
    );
    assert_eq!(
        norm.read_bytes_contiguous(0x1008, 4).unwrap(),
        vec![0x11, 0x22, 0x11, 0x22]
    );
}

#[test]
fn test_merge_range_then_offset_transparent() {
    // /MT: range applies before offset; transparent merge preserves existing data.
    let mut base = HexFile::with_segments(vec![Segment::new(0x1011, vec![0xEE, 0xEE]).unwrap()]);
    let merge = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0x10, 0x11, 0x12, 0x13]).unwrap(),
    ]);

    base.merge(
        &merge,
        &MergeOptions {
            mode: MergeMode::Preserve,
            offset: 0x10,
            range: Some(AddressRange::from_start_end(0x1001, 0x1002).unwrap()),
        },
    )
    .unwrap();

    let norm = base.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1011, 2).unwrap(),
        vec![0xEE, 0xEE]
    );
    assert_eq!(norm.read_byte(0x1010), None);
}

#[test]
fn test_merge_range_then_offset_opaque() {
    // /MO: range applies before offset; opaque merge overwrites existing data.
    let mut base = HexFile::with_segments(vec![Segment::new(0x1011, vec![0xEE, 0xEE]).unwrap()]);
    let merge = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0x10, 0x11, 0x12, 0x13]).unwrap(),
    ]);

    base.merge(
        &merge,
        &MergeOptions {
            mode: MergeMode::Overwrite,
            offset: 0x10,
            range: Some(AddressRange::from_start_end(0x1001, 0x1002).unwrap()),
        },
    )
    .unwrap();

    let norm = base.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1011, 2).unwrap(),
        vec![0x11, 0x12]
    );
}

//! Integration tests based on HexView command-line documentation.
//!
//! Focus: multi-stage operations and command semantics.

use hexy_core::{
    AddressRange, AlignOptions, ChecksumAlgorithm, ChecksumOptions, ChecksumTarget, FillOptions,
    HexFile, MergeMode, MergeOptions, Segment,
};

#[test]
fn test_fill_region_preserves_existing_data() {
    // /FR with /FP should fill gaps and preserve existing bytes.
    let mut hf = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 8])]);

    hf.fill(
        AddressRange::from_start_end(0x1004, 0x100B).unwrap(),
        &FillOptions {
            pattern: vec![0x11, 0x22],
            overwrite: false,
        },
    );

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
    let mut base = HexFile::with_segments(vec![Segment::new(0x1011, vec![0xEE, 0xEE])]);
    let merge = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x10, 0x11, 0x12, 0x13])]);

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
    let mut base = HexFile::with_segments(vec![Segment::new(0x1011, vec![0xEE, 0xEE])]);
    let merge = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x10, 0x11, 0x12, 0x13])]);

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

#[test]
fn test_hexview_multistage_order() {
    // /FR -> /CR -> /MO -> /AR -> /AD /AL -> /CS
    let mut hf = HexFile::with_segments(vec![Segment::new(
        0x1000,
        vec![0x10, 0x11, 0x12, 0x13, 0x14, 0x15],
    )]);

    hf.fill(
        AddressRange::from_start_end(0x1003, 0x1007).unwrap(),
        &FillOptions {
            pattern: vec![0xAA, 0xBB],
            overwrite: false,
        },
    );

    hf.cut(AddressRange::from_start_end(0x1001, 0x1001).unwrap());

    let merge = HexFile::with_segments(vec![Segment::new(0x2000, vec![0x20, 0x21, 0x22, 0x23])]);
    hf.merge(
        &merge,
        &MergeOptions {
            mode: MergeMode::Overwrite,
            offset: -0x1000,
            range: Some(AddressRange::from_start_end(0x2001, 0x2002).unwrap()),
        },
    )
    .unwrap();

    hf.filter_range(AddressRange::from_start_end(0x1000, 0x1004).unwrap());

    hf.align(&AlignOptions {
        alignment: 3,
        fill_byte: 0xEE,
        align_length: true,
    })
    .unwrap();

    let cs_options = ChecksumOptions {
        algorithm: ChecksumAlgorithm::ByteSumBe,
        range: None,
        little_endian_output: false,
        ..Default::default()
    };
    hf.checksum(&cs_options, &ChecksumTarget::Append).unwrap();

    let norm = hf.normalized();
    assert_eq!(norm.segments()[0].start_address, 0x0FFF);
    assert_eq!(
        norm.read_bytes_contiguous(0x0FFF, 6).unwrap(),
        vec![0xEE, 0x10, 0x21, 0x22, 0x13, 0x14]
    );
    assert_eq!(
        norm.read_bytes_contiguous(0x1005, 2).unwrap(),
        vec![0x01, 0x68]
    );
}

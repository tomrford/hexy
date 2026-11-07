#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use hexy_core::{
    AddressRange, AlignOptions, ChecksumAlgorithm, ChecksumOptions, ChecksumStage, Fill, FillData,
    HexFile, Merge, MergeMode, MergeOptions, Pipeline, Segment,
};

/// Bytes `(seed + 7 * i) & 0xFF`, the harness fixture pattern.
fn pat(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add((i * 7) as u8)).collect()
}

fn hexfile(segments: &[(u32, usize, u8)]) -> HexFile {
    HexFile::with_segments(
        segments
            .iter()
            .map(|&(start, len, seed)| Segment::new(start, pat(len, seed)).unwrap())
            .collect(),
    )
}

fn range(start: u32, end: u32) -> AddressRange {
    AddressRange::from_start_end(start, end).unwrap()
}

/// HexView 1.15.2: `gaps.hex /CS9:cs.txt /SWAPWORD /SB:0x40 /AL /AD:0x40 /AF:00
/// /AR:0x0F00-0x1FFF /MT:merge.hex;0x100 /CR:0x1010-0x101F /FP:A55A /FR:0x0F00-0x0F3F`
/// writes `0x4E, 0x5E, 0x64, 0x5E`: the CRC-32 of the image after every earlier stage.
#[test]
fn test_pipeline_matches_hexview_multistage_checksum() {
    let mut image = hexfile(&[
        (0x1000, 0x100, 1),
        (0x1180, 0x80, 2),
        (0x1301, 0x3E, 3),
        (0x2000, 6, 4),
    ]);
    let pipeline = Pipeline {
        fill: Some(Fill {
            ranges: vec![range(0x0F00, 0x0F3F)],
            data: FillData::Pattern(vec![0xA5, 0x5A]),
        }),
        cut: vec![range(0x1010, 0x101F)],
        merges: vec![Merge {
            file: hexfile(&[(0x10F0, 0x40, 9), (0x1500, 0x10, 10)]),
            options: MergeOptions {
                mode: MergeMode::Preserve,
                offset: 0x100,
                range: None,
            },
        }],
        address_filter: Some(vec![range(0x0F00, 0x1FFF)]),
        align: Some(AlignOptions {
            alignment: 0x40,
            fill_byte: 0x00,
            align_length: true,
        }),
        split: Some(0x40),
        swap_word: true,
        checksums: vec![ChecksumStage {
            options: ChecksumOptions {
                algorithm: ChecksumAlgorithm::Crc32,
                ..Default::default()
            },
            placement: None,
        }],
        ..Default::default()
    };

    let output = pipeline.run(&mut image).unwrap();

    assert_eq!(output.checksums, vec![vec![0x4E, 0x5E, 0x64, 0x5E]]);
}

#[test]
fn test_random_fill_is_seeded_and_fills_only_gaps() {
    let source = hexfile(&[(0x1004, 4, 1)]);
    let pipeline = |seed| Pipeline {
        fill: Some(Fill {
            ranges: vec![range(0x1000, 0x100F)],
            data: FillData::Random { seed },
        }),
        ..Default::default()
    };
    let run = |seed| {
        let mut image = source.clone();
        pipeline(seed).run(&mut image).unwrap();
        image.normalized()
    };

    let first = run(1);
    assert_eq!(first, run(1));
    assert_ne!(first, run(2));
    assert_eq!(first.read_bytes_contiguous(0x1004, 4).unwrap(), pat(4, 1));
    assert_eq!(first.total_bytes(), 0x10);
}

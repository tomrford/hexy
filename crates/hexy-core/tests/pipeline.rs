#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use hexy_core::{
    AddressRange, AesKey, AesMode, AlignOptions, ChecksumAlgorithm, ChecksumOptions, ChecksumStage,
    DataProcessing, DataProcessingStage, Fill, FillData, HexFile, Merge, MergeMode, MergeOptions,
    Pipeline, Placement, Segment, SwapMode,
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

#[test]
fn test_unconfigured_stages_keep_split_blocks() {
    let mut file = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xAA; 0x200]).unwrap()]);
    file.split(0x100);
    let pipeline = Pipeline {
        remove_small_blocks: Some(0x101),
        ..Default::default()
    };
    pipeline.run(&mut file).unwrap();
    assert!(file.is_empty());
}

#[test]
fn test_failed_checksum_placement_keeps_split_blocks() {
    let mut file = hexfile(&[(0x1000, 32, 1)]);
    file.split(16);
    let before = file.blocks();
    let pipeline = Pipeline {
        checksums: vec![ChecksumStage {
            options: ChecksumOptions::default(),
            placement: Some(Placement::Address(u32::MAX)),
        }],
        ..Default::default()
    };

    assert!(pipeline.run(&mut file).is_err());
    assert_eq!(file.blocks(), before);
}

#[test]
fn test_partially_failed_cipher_normalizes_replaced_blocks() {
    let mut file = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0; 32]).unwrap(),
        Segment::new(0x2000, vec![0xAA]).unwrap(),
    ]);
    file.split(16);
    let pipeline = Pipeline {
        data_processing: Some(DataProcessingStage {
            operation: DataProcessing::Encrypt {
                key: AesKey::new(&[0; 16]).unwrap(),
                mode: AesMode::Ecb,
                padding: None,
            },
            placement: None,
        }),
        ..Default::default()
    };

    assert!(pipeline.run(&mut file).is_err());
    let blocks = file.blocks();
    // AES-128 with an all-zero key and plaintext: the first two blocks were encrypted.
    let ciphertext = [
        0x66, 0xE9, 0x4B, 0xD4, 0xEF, 0x8A, 0x2C, 0x3B, 0x88, 0x4C, 0xFA, 0x59, 0xCA, 0x34, 0x2B,
        0x2E,
    ];
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].data(), ciphertext.repeat(2));
    assert_eq!(blocks[1].start_address(), 0x2000);
    assert_eq!(blocks[1].data(), [0xAA]);
}

#[test]
fn test_large_dword_swap_is_shared_by_direct_operations_and_pipeline() {
    for (length, expected_prefix, expected_sum) in [
        (
            0x100_0000,
            [3, 2, 1, 0, 7, 6, 5, 4, 7, 6, 5, 4, 7, 6, 5, 4],
            [0xFF, 0xF0],
        ),
        (
            0xFF_FFFC,
            [3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12],
            [0xFF, 0xCA],
        ),
    ] {
        let source = HexFile::with_segments(vec![
            Segment::new(0, (0..length).map(|i| (i % 16) as u8).collect()).unwrap(),
        ]);
        let mut direct = source.clone();
        direct.swap_bytes(SwapMode::DWord);

        let mut staged = source;
        let output = Pipeline {
            swap_dword: true,
            checksums: vec![ChecksumStage {
                options: ChecksumOptions::default(),
                placement: None,
            }],
            ..Default::default()
        }
        .run(&mut staged)
        .unwrap();

        assert_eq!(&direct.segments()[0].data()[..16], &expected_prefix);
        assert_eq!(&staged.segments()[0].data()[..16], &expected_prefix);
        assert_eq!(output.checksums, vec![expected_sum.to_vec()]);
    }
}

#[test]
fn test_large_dword_swap_resolves_overlaps_but_keeps_split_blocks() {
    let mut overlap = HexFile::with_segments(vec![
        Segment::new(0, vec![0x11; 0x90_0000]).unwrap(),
        Segment::new(0x70_0000, vec![0x22; 0x90_0000]).unwrap(),
    ]);
    overlap.swap_bytes(SwapMode::DWord);
    assert_eq!(overlap.read_byte(0xFF_FFFF), Some(0x11));

    let mut split = HexFile::with_segments(vec![
        Segment::new(0, vec![0x11; 0x80_0000]).unwrap(),
        Segment::new(0x80_0000, vec![0x22; 0x80_0000]).unwrap(),
    ]);
    split.swap_bytes(SwapMode::DWord);
    assert_eq!(split.read_byte(0xFF_FFFF), Some(0x22));
    assert_eq!(split.blocks().len(), 2);
}

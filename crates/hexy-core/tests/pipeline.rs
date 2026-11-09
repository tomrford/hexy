#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use hexy_core::{
    AddressRange, AesGcm, AesKey, AesMode, AesPadding, AlignOptions, ChecksumAlgorithm,
    ChecksumOptions, ChecksumStage, DataProcessing, DataProcessingStage, Fill, FillData, GcmTag,
    HexFile, HsmValidationOptions, HsmValidationStage, MacAlgorithm, MacKey, MacMethod, Merge,
    MergeMode, MergeOptions, Pipeline, Placement, Segment, SignatureMethod, SignatureScheme,
    SwapMode,
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
            address_alignment: 0x40,
            length_alignment: 0x40,
            fill_byte: 0x00,
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

/// HexView 1.15.2's `/vshsm` structure over bytes 0 to 15 at address 0.
const HSM_STRUCTURE: &str = "00000000000100000000000000100000be45cb2605bf36bebde684841a28f0fd43c69850a3dce5fedba69928ee3a8991";

fn hsm_pipeline(placement: Placement, signature: DataProcessing) -> (Pipeline, HexFile) {
    let pipeline = Pipeline {
        hsm_validation: Some(HsmValidationStage {
            options: HsmValidationOptions {
                group_id: 0,
                mode: 0,
                hash: ChecksumAlgorithm::Sha256,
            },
            placement: Some(placement),
            signature: Some(signature),
        }),
        ..Default::default()
    };
    let image = HexFile::with_segments(vec![Segment::new(0, (0..16).collect()).unwrap()]);
    (pipeline, image)
}

fn hex(text: &str) -> Vec<u8> {
    hexy_core::decode_hex_text(text.as_bytes()).unwrap()
}

/// HexView 1.15.2 `/vshsm:@append` with `SIGNATURE_METHOD=31` on a 16-byte image at 0:
/// the MAC covers the structure at the placement address, but with no room below that
/// address the MAC goes there and the structure follows it.
#[test]
fn test_hsm_signature_without_room_below_precedes_structure() {
    let mac = DataProcessing::Mac {
        method: MacMethod {
            algorithm: MacAlgorithm::HmacSha256,
            with_metadata: true,
        },
        key: MacKey::from_key_file(b"00112233445566778899AABBCCDDEEFF").unwrap(),
    };
    let (pipeline, mut image) = hsm_pipeline(Placement::Append, mac);

    pipeline.run(&mut image).unwrap();

    let signature = hex("a3b91176e3ad194b25232031fa216294bf175af211b068d14164afff5d35bd02");
    assert_eq!(image.read_bytes_contiguous(0x10, 32), Some(signature));
    assert_eq!(
        image.read_bytes_contiguous(0x30, 48),
        Some(hex(HSM_STRUCTURE))
    );
}

/// HexView 1.15.2 `/vshsm:@0x8000` with an RSA-PSS key too short to sign: the
/// structure is inserted unsigned and the stage fails.
#[test]
fn test_failed_hsm_signature_inserts_unsigned_structure() {
    let path = format!(
        "{}/tests/fixtures/keys/rsa_512_test.pem",
        env!("CARGO_MANIFEST_DIR")
    );
    let method = SignatureMethod {
        scheme: SignatureScheme::RsaPssSha256,
        with_metadata: false,
    };
    let sign = DataProcessing::Sign {
        method,
        key: method
            .scheme
            .signing_key(&std::fs::read(path).unwrap())
            .unwrap(),
        salt: None,
    };
    let (pipeline, mut image) = hsm_pipeline(Placement::Address(0x8000), sign);

    assert!(pipeline.run(&mut image).is_err());

    assert_eq!(
        image.read_bytes_contiguous(0x8000, 48),
        Some(hex(HSM_STRUCTURE))
    );
    assert_eq!(image.total_bytes(), 16 + 48);
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
fn test_failed_cipher_before_write_keeps_image() {
    let split = |start, len, size| {
        let mut file = hexfile(&[(start, len, 1)]);
        file.split(size);
        file
    };
    let key = AesKey::new(&[0; 16]).unwrap();
    let ecb = DataProcessing::Encrypt {
        key: key.clone(),
        mode: AesMode::Ecb,
        padding: None,
    };
    let gcm = AesGcm {
        key: key.clone(),
        nonce: vec![0; 12],
        aad: Vec::new(),
    };
    let cases = [
        (
            "unaligned",
            hexfile(&[(0x1000, 17, 1), (0x1004, 4, 2), (0x1011, 17, 3)]),
            ecb,
        ),
        (
            "short IV",
            split(0x1000, 16, 8),
            DataProcessing::Encrypt {
                key: key.clone(),
                mode: AesMode::Cbc { iv: None },
                padding: None,
            },
        ),
        (
            "empty nonce",
            split(0x1000, 32, 16),
            DataProcessing::EncryptGcm(AesGcm {
                nonce: Vec::new(),
                ..gcm.clone()
            }),
        ),
        (
            "tag location",
            split(0x1000, 32, 16),
            DataProcessing::DecryptGcm {
                gcm,
                tag: GcmTag::Image(range(0x1004, 0x1007)),
            },
        ),
        (
            "first output overflows",
            split(u32::MAX - 14, 15, 8),
            DataProcessing::Encrypt {
                key,
                mode: AesMode::Ecb,
                padding: Some(AesPadding::Pkcs7),
            },
        ),
    ];
    let mut changed = Vec::new();
    for (name, mut file, operation) in cases {
        let before = file.clone();
        let pipeline = Pipeline {
            data_processing: Some(DataProcessingStage {
                operation,
                placement: None,
            }),
            ..Default::default()
        };
        assert!(pipeline.run(&mut file).is_err(), "{name}");
        if file != before {
            changed.push(name);
        }
    }
    assert!(
        changed.is_empty(),
        "pre-write failures changed the image: {changed:?}"
    );
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
fn test_gcm_failure_after_write_normalizes_replaced_blocks() {
    let gcm = AesGcm {
        key: AesKey::new(&[0; 16]).unwrap(),
        nonce: vec![0; 12],
        aad: Vec::new(),
    };
    // NIST's zero-key, zero-nonce GCM vector, first plaintext/ciphertext block.
    let plain = [0; 16];
    let cipher = [
        0x03, 0x88, 0xDA, 0xCE, 0x60, 0xB6, 0xA3, 0x92, 0xF3, 0x28, 0xC2, 0xB9, 0x71, 0xB2, 0xFE,
        0x78,
    ];
    let cases = [
        (
            "tag mismatch",
            cipher,
            DataProcessing::DecryptGcm {
                gcm: gcm.clone(),
                tag: GcmTag::Bytes(vec![0; 16]),
            },
            plain,
        ),
        (
            "tag placement overflow",
            plain,
            DataProcessing::EncryptGcm(gcm),
            cipher,
        ),
    ];
    let mut unnormalized = Vec::new();
    for (name, input, operation, expected_prefix) in cases {
        let mut file = HexFile::with_segments(vec![Segment::new(0x1000, input.repeat(2)).unwrap()]);
        file.split(16);
        let pipeline = Pipeline {
            data_processing: Some(DataProcessingStage {
                operation,
                placement: Some(Placement::Address(u32::MAX)),
            }),
            ..Default::default()
        };
        assert!(pipeline.run(&mut file).is_err(), "{name}");
        assert_eq!(
            file.read_bytes_contiguous(0x1000, 16).unwrap(),
            expected_prefix,
            "{name}"
        );
        if file.blocks().len() != 1 {
            unnormalized.push(name);
        }
    }
    assert!(
        unnormalized.is_empty(),
        "post-write failures left split blocks: {unnormalized:?}"
    );
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

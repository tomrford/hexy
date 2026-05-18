mod common;

use common::{assert_success, run_hexy, temp_dir, write_file};
use hexy_core::{
    AddressRange, AlignOptions, BinaryWriteOptions, ChecksumAlgorithm, ChecksumOptions,
    ChecksumTarget, FillOptions, IntelHexWriteOptions, MergeMode, MergeOptions, SwapMode,
    parse_binary, write_binary, write_intel_hex,
};

#[test]
fn test_cli_pipeline_parity_basic_chain() {
    let dir = temp_dir("cli_pipeline_parity");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out_cli = dir.join("out.hex");

    write_file(&base, &[0x10, 0x11, 0x12, 0x13]);
    write_file(&merge, &[0xAA, 0xBB]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        "/FR:0x1000-0x100F".to_string(),
        "/FP:F0".to_string(),
        "/CR:0x1004-0x1005".to_string(),
        format!("/MT:{};0x1008", merge.display()),
        "/AR:0x1000-0x1010".to_string(),
        "/AF:00".to_string(),
        "/AD4".to_string(),
        "/AL".to_string(),
        "/SWAPWORD".to_string(),
        "/SB:4".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out_cli.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let cli_bytes = std::fs::read(&out_cli).unwrap();

    let mut hexfile = parse_binary(&[0x10, 0x11, 0x12, 0x13], 0x1000).unwrap();
    let merge_hex = parse_binary(&[0xAA, 0xBB], 0).unwrap();
    let fill_ranges = [AddressRange::from_start_end(0x1000, 0x100F).unwrap()];
    let cut_ranges = [AddressRange::from_start_end(0x1004, 0x1005).unwrap()];
    let filter_ranges = [AddressRange::from_start_end(0x1000, 0x1010).unwrap()];

    hexfile.fill_ranges(
        &fill_ranges,
        &FillOptions {
            pattern: vec![0xF0],
            overwrite: false,
        },
    );
    hexfile.cut_ranges(&cut_ranges);
    hexfile
        .merge(
            &merge_hex,
            &MergeOptions {
                mode: MergeMode::Preserve,
                offset: 0x1008,
                range: None,
            },
        )
        .unwrap();
    hexfile.filter_ranges(&filter_ranges);
    hexfile
        .align(&AlignOptions {
            alignment: 4,
            fill_byte: 0x00,
            align_length: true,
        })
        .unwrap();
    hexfile.split(4);
    hexfile.swap_bytes(SwapMode::Word).unwrap();

    let lib_bytes = write_intel_hex(&hexfile, &IntelHexWriteOptions::default());
    assert_eq!(cli_bytes, lib_bytes);
}

#[test]
fn test_cli_pipeline_parity_binary_order() {
    let dir = temp_dir("cli_pipeline_parity_xn");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out_cli = dir.join("out.bin");

    write_file(&base, &[0x01, 0x02]);
    write_file(&merge, &[0xAA, 0xBB]);

    let args = vec![
        format!("/IN:{};0x2000", base.display()),
        format!("/MT:{};0x1000", merge.display()),
        "/XN".to_string(),
        "-o".to_string(),
        out_cli.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let cli_bytes = std::fs::read(&out_cli).unwrap();

    let mut hexfile = parse_binary(&[0x01, 0x02], 0x2000).unwrap();
    let merge_hex = parse_binary(&[0xAA, 0xBB], 0).unwrap();
    hexfile
        .merge(
            &merge_hex,
            &MergeOptions {
                mode: MergeMode::Preserve,
                offset: 0x1000,
                range: None,
            },
        )
        .unwrap();

    let lib_bytes = write_binary(&hexfile, &BinaryWriteOptions::default());
    assert_eq!(cli_bytes, lib_bytes);
}

#[test]
fn test_cli_checksum_parity_begin() {
    let dir = temp_dir("cli_pipeline_parity_cs");
    let base = dir.join("base.bin");
    let out_cli = dir.join("out.hex");

    write_file(&base, &[0x01, 0x02, 0x03, 0x04]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        "/CS0:@BEGIN".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out_cli.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let cli_bytes = std::fs::read(&out_cli).unwrap();

    let mut hexfile = parse_binary(&[0x01, 0x02, 0x03, 0x04], 0x1000).unwrap();
    let start = hexfile.min_address().unwrap();
    let algorithm = ChecksumAlgorithm::from_index(0).unwrap();
    let _ = hexfile
        .checksum(
            &ChecksumOptions {
                algorithm,
                ..Default::default()
            },
            &ChecksumTarget::Address(start),
        )
        .unwrap();
    let lib_bytes = write_intel_hex(&hexfile, &IntelHexWriteOptions::default());

    assert_eq!(cli_bytes, lib_bytes);
}

#[test]
fn test_cli_checksum_parity_little_endian_file() {
    let dir = temp_dir("cli_pipeline_parity_csr");
    let base = dir.join("base.bin");
    let out_cli = dir.join("out.hex");
    let out_sum = dir.join("sum.txt");

    write_file(&base, &[0x10, 0x20, 0x30, 0x40]);

    let args = vec![
        format!("/IN:{};0x2000", base.display()),
        format!("/CSR0:{}", out_sum.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out_cli.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let cli_sum = std::fs::read_to_string(&out_sum).unwrap();

    let mut hexfile = parse_binary(&[0x10, 0x20, 0x30, 0x40], 0x2000).unwrap();
    let algorithm = ChecksumAlgorithm::from_index(0).unwrap();
    let bytes = hexfile
        .checksum(
            &ChecksumOptions {
                algorithm,
                little_endian_output: true,
                ..Default::default()
            },
            &ChecksumTarget::File(out_sum.clone()),
        )
        .unwrap();
    let lib_sum = bytes
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ");

    assert_eq!(cli_sum, lib_sum);
}

#[test]
fn test_cli_pipeline_parity_xsb_split() {
    let dir = temp_dir("cli_pipeline_parity_xsb");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out_cli = dir.join("out.bin");

    write_file(&base, &[0x01, 0x02]);
    write_file(&merge, &[0xAA]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x2000", merge.display()),
        "/XSB".to_string(),
        "-o".to_string(),
        out_cli.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let cli_a = std::fs::read(dir.join("out_1000.bin")).unwrap();
    let cli_b = std::fs::read(dir.join("out_2000.bin")).unwrap();

    let mut hexfile = parse_binary(&[0x01, 0x02], 0x1000).unwrap();
    let merge_hex = parse_binary(&[0xAA], 0).unwrap();
    hexfile
        .merge(
            &merge_hex,
            &MergeOptions {
                mode: MergeMode::Overwrite,
                offset: 0x2000,
                range: None,
            },
        )
        .unwrap();
    let mut segments = hexfile.normalized().into_segments();
    segments.sort_by_key(|s| s.start_address);

    assert_eq!(cli_a, segments[0].data);
    assert_eq!(cli_b, segments[1].data);
}

#[test]
fn test_cli_pipeline_parity_fa_fill_binary() {
    let dir = temp_dir("cli_pipeline_parity_fa");
    let base = dir.join("base.bin");
    let out_cli = dir.join("out.bin");

    write_file(&base, &[0xAA]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        "/AF:00".to_string(),
        "/FA".to_string(),
        "/XN".to_string(),
        "-o".to_string(),
        out_cli.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let cli_bytes = std::fs::read(&out_cli).unwrap();

    let mut hexfile = parse_binary(&[0xAA], 0x1000).unwrap();
    hexfile.fill_gaps(0x00);
    let lib_bytes = write_binary(
        &hexfile,
        &BinaryWriteOptions {
            fill_gaps: Some(0x00),
        },
    );

    assert_eq!(cli_bytes, lib_bytes);
}

mod common;
mod common_hex;

use common::{assert_success, run_hexy, temp_dir, write_file};
use common_hex::run_hex_output;

#[test]
fn test_cli_align_length_fill() {
    let dir = temp_dir("cli_align");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xA1, 0xA2, 0xA3, 0xA4, 0xA5]);

    let args = vec![
        format!("/IN:{};0x1001", input.display()),
        "/AF:0x00".to_owned(),
        "/AD4".to_owned(),
        "/AL".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0x1000);
    assert_eq!(
        norm.segments()[0].data(),
        vec![0x00, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x00, 0x00]
    );
}

#[test]
fn test_cli_cut_splits_block() {
    let dir = temp_dir("cli_cut");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0, 1, 2, 3, 4, 5, 6, 7]);

    let args = vec![
        format!("/IN:{};0x2000", input.display()),
        "/CR:0x2003,0x2".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let mut segments = hexfile.segments().to_vec();
    segments.sort_by_key(|s| s.start_address());
    assert_eq!(segments.len(), 2);
    assert_eq!(segments[0].start_address(), 0x2000);
    assert_eq!(segments[0].data(), vec![0, 1, 2]);
    assert_eq!(segments[1].start_address(), 0x2005);
    assert_eq!(segments[1].data(), vec![5, 6, 7]);
}

#[test]
fn test_cli_fill_region_pattern_preserves_data() {
    let dir = temp_dir("cli_fill");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0x11, 0x22]);

    let args = vec![
        format!("/IN:{};0x3002", input.display()),
        "/FR:0x3000,0x4".to_owned(),
        "/FP:AA55".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x3000, 4).unwrap(),
        vec![0xAA, 0x55, 0x11, 0x22]
    );
}

#[test]
fn test_cli_fill_region_without_pattern_random() {
    let dir = temp_dir("cli_fr_random");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0x11, 0x22]);

    let args = vec![
        format!("/IN:{};0x1002", input.display()),
        "/FR:0x1000,0x4".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    let data = norm.read_bytes_contiguous(0x1000, 4).unwrap();
    assert_eq!(data[2], 0x11);
    assert_eq!(data[3], 0x22);
}

#[test]
fn test_cli_threshold_options_noop() {
    let dir = temp_dir("cli_thresholds");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0x01, 0x02, 0x03, 0x04]);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        "/BHFCT=10".to_owned(),
        "/BTFST=0x20".to_owned(),
        "/BTBS=0b100".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
}

#[test]
fn test_cli_nested_chain_checksum() {
    let dir = temp_dir("cli_nested_chain");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.hex");
    write_file(&base, &[0x10, 0x11]);
    write_file(&merge, &[0xA0, 0xA1, 0xA2, 0xA3]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        "/FR:0x1000,0x6".to_owned(),
        "/FP:AA55".to_owned(),
        "/CR:0x1003,0x1".to_owned(),
        format!("/MO:{};0x1000:0x1,0x2", merge.display()),
        "/AR:0x1000-0x1004".to_owned(),
        "/AD4".to_owned(),
        "/AL".to_owned(),
        "/AF:0xEE".to_owned(),
        "/CS0:@append".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    let data = norm.read_bytes_contiguous(0x1000, 10).unwrap();
    assert_eq!(
        data,
        vec![0x10, 0xA1, 0xA2, 0xEE, 0xAA, 0xEE, 0xEE, 0xEE, 0x05, 0xB5]
    );
}

#[test]
fn test_cli_error_log_created_on_success() {
    let dir = temp_dir("cli_error_log_ok");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    let log = dir.join("err.log");
    write_file(&input, &[0x01, 0x02]);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        format!("/E:{}", log.display()),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let contents = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(contents.is_empty());
}

#[test]
fn test_cli_error_log_on_failure() {
    let dir = temp_dir("cli_error_log_fail");
    let input = dir.join("input.bin");
    let log = dir.join("err.log");
    write_file(&input, &[0x01, 0x02]);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        format!("/E:{}", log.display()),
        "/MT:dummy.bin".to_owned(),
        "/MO:dummy.bin".to_owned(),
    ];

    let output = run_hexy(&args);
    assert!(!output.status.success());
    let contents = std::fs::read_to_string(&log).unwrap_or_default();
    assert!(!contents.is_empty());
}

#[test]
fn test_cli_address_range_reduction() {
    let dir = temp_dir("cli_ar");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.hex");
    write_file(&base, &[0xAA, 0xAB, 0xAC, 0xAD]);
    write_file(&merge, &[0xBA, 0xBB, 0xBC, 0xBD]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x2000", merge.display()),
        "/AR:0x2000,0x4".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0x2000);
    assert_eq!(norm.segments()[0].data(), vec![0xBA, 0xBB, 0xBC, 0xBD]);
}

#[test]
fn test_cli_address_range_reduction_start_end() {
    let dir = temp_dir("cli_ar_start_end");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.hex");
    write_file(&base, &[0xAA, 0xAB, 0xAC, 0xAD]);
    write_file(&merge, &[0xBA, 0xBB, 0xBC, 0xBD]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x2000", merge.display()),
        "/AR:0x2000-0x2003".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0x2000);
    assert_eq!(norm.segments()[0].data(), vec![0xBA, 0xBB, 0xBC, 0xBD]);
}

#[test]
fn test_cli_address_range_full_span_keeps_u32_max_boundary() {
    let dir = temp_dir("cli_ar_full_span");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xFC, 0xFD, 0xFE, 0xFF]);

    let args = vec![
        format!("/IN:{};0xFFFFFFFC", input.display()),
        "/AR:0x00000000-0xFFFFFFFF".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0xFFFF_FFFC);
    assert_eq!(norm.segments()[0].data(), vec![0xFC, 0xFD, 0xFE, 0xFF]);
}

#[test]
fn test_cli_address_range_length_form_keeps_u32_max_boundary() {
    let dir = temp_dir("cli_ar_max_len");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xFC, 0xFD, 0xFE, 0xFF]);

    let args = vec![
        format!("/IN:{};0xFFFFFFFC", input.display()),
        "/AR:0xFFFFFFFC,0x4".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0xFFFF_FFFC);
    assert_eq!(norm.segments()[0].data(), vec![0xFC, 0xFD, 0xFE, 0xFF]);
}

/// HexView 1.15.2 ignores ranges reaching past the address space: /AR keeps all data
/// and /CR cuts nothing.
#[test]
fn test_cli_overflowing_ranges_are_ignored() {
    let dir = temp_dir("cli_range_overflow");
    let input = dir.join("input.bin");
    write_file(&input, &[0xFC, 0xFD, 0xFE, 0xFF]);
    for flag in ["/AR:0xFFFFFFFC,0x8", "/CR:0xFFFFFFFC,0x8"] {
        let out = dir.join("out.hex");
        let args = vec![
            format!("/IN:{};0xFFFFFFFC", input.display()),
            flag.to_owned(),
            "/XI".to_owned(),
            "-o".to_owned(),
            out.display().to_string(),
        ];
        let hexfile = run_hex_output(args, &out);
        assert_eq!(hexfile.normalized().total_bytes(), 4, "{flag}");
    }
}

/// HexView 1.15.2 `/SWAPLONG` repeats the second swapped word across a block of 16 MiB.
#[test]
fn test_cli_swaplong_large_block_repeats_second_word() {
    let dir = temp_dir("cli_swaplong_large");
    let input = dir.join("input.bin");
    let out = dir.join("out.bin");
    let data: Vec<u8> = (0..0x100_0000u32)
        .map(|i| (i * 7 + (i >> 8)) as u8)
        .collect();
    write_file(&input, &data);
    let args = vec![
        format!("/IN:{}", input.display()),
        "/SWAPLONG".to_owned(),
        "/XN".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];
    assert_success(&run_hexy(&args));
    let swapped = std::fs::read(&out).unwrap();
    assert_eq!(swapped.len(), data.len());
    assert_eq!(
        swapped[..12],
        [
            0x15, 0x0E, 0x07, 0x00, 0x31, 0x2A, 0x23, 0x1C, 0x31, 0x2A, 0x23, 0x1C
        ]
    );
    assert_eq!(swapped[swapped.len() - 4..], [0x31, 0x2A, 0x23, 0x1C]);
}

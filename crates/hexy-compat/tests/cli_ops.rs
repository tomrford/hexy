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
        "/AF:0x00".to_string(),
        "/AD4".to_string(),
        "/AL".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
fn test_cli_align_address_no_separator_semantics() {
    let dir = temp_dir("cli_ad_semantics");
    let input = dir.join("input.bin");
    let out_hex = dir.join("out_hex.hex");
    let out_dec = dir.join("out_dec.hex");
    write_file(&input, &[0x11, 0x22, 0x33]);

    let args_hex = vec![
        format!("/IN:{};0x1001", input.display()),
        "/AD10".to_string(),
        "/AL".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out_hex.display().to_string(),
    ];
    let hexfile_hex = run_hex_output(args_hex, &out_hex);

    let args_dec = vec![
        format!("/IN:{};0x1001", input.display()),
        "/AD:10".to_string(),
        "/AL".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out_dec.display().to_string(),
    ];
    let hexfile_dec = run_hex_output(args_dec, &out_dec);

    assert_ne!(
        hexfile_hex.normalized().segments()[0].data(),
        hexfile_dec.normalized().segments()[0].data()
    );
}

#[test]
fn test_cli_align_address_binary_separator() {
    let dir = temp_dir("cli_ad_bin");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0x11, 0x22, 0x33, 0x44]);

    let args = vec![
        format!("/IN:{};0x1001", input.display()),
        "/AD:0b100".to_string(),
        "/AL".to_string(),
        "/AF:0xEE".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments()[0].start_address(), 0x1001);
    assert_eq!(norm.segments()[0].data(), vec![0x11, 0x22, 0x33, 0x44]);
}

#[test]
fn test_cli_align_fill_separator_and_hex_forms() {
    let dir = temp_dir("cli_af_forms");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0x11, 0x22, 0x33]); // length 3 at 0x1001

    let args = vec![
        format!("/IN:{};0x1001", input.display()),
        "/AF:0b10101010".to_string(),
        "/AD4".to_string(),
        "/AL".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments()[0].start_address(), 0x1000);
    assert_eq!(norm.segments()[0].data(), vec![0xAA, 0x11, 0x22, 0x33]);
}

#[test]
fn test_cli_align_fill_no_separator_equivalence() {
    let dir = temp_dir("cli_af_equiv");
    let input = dir.join("input.bin");
    let out_hex = dir.join("out_hex.hex");
    let out_dec = dir.join("out_dec.hex");
    write_file(&input, &[0x11, 0x22, 0x33]);

    let args_hex = vec![
        format!("/IN:{};0x1001", input.display()),
        "/AFCD".to_string(),
        "/AD4".to_string(),
        "/AL".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out_hex.display().to_string(),
    ];
    let hexfile_hex = run_hex_output(args_hex, &out_hex);

    let args_dec = vec![
        format!("/IN:{};0x1001", input.display()),
        "/AF:0xCD".to_string(),
        "/AD4".to_string(),
        "/AL".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out_dec.display().to_string(),
    ];
    let hexfile_dec = run_hex_output(args_dec, &out_dec);

    assert_eq!(
        hexfile_hex.normalized().segments()[0].data(),
        hexfile_dec.normalized().segments()[0].data()
    );
}

#[test]
fn test_cli_align_fill_equal_separator() {
    let dir = temp_dir("cli_af_eq");
    let input = dir.join("input.bin");
    let out_colon = dir.join("out_colon.hex");
    let out_equal = dir.join("out_equal.hex");
    write_file(&input, &[0x11, 0x22, 0x33]);

    let args_colon = vec![
        format!("/IN:{};0x1001", input.display()),
        "/AF:0xCD".to_string(),
        "/AD4".to_string(),
        "/AL".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out_colon.display().to_string(),
    ];
    let hexfile_colon = run_hex_output(args_colon, &out_colon);

    let args_equal = vec![
        format!("/IN:{};0x1001", input.display()),
        "/AF=0xCD".to_string(),
        "/AD4".to_string(),
        "/AL".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out_equal.display().to_string(),
    ];
    let hexfile_equal = run_hex_output(args_equal, &out_equal);

    assert_eq!(
        hexfile_colon.normalized().segments()[0].data(),
        hexfile_equal.normalized().segments()[0].data()
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
        "/CR:0x2003,0x2".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        "/FR:0x3000,0x4".to_string(),
        "/FP:AA55".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        "/FR:0x1000,0x4".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        "/BHFCT=10".to_string(),
        "/BTFST=0x20".to_string(),
        "/BTBS=0b100".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        "/FR:0x1000,0x6".to_string(),
        "/FP:AA55".to_string(),
        "/CR:0x1003,0x1".to_string(),
        format!("/MO:{};0x1000:0x1,0x2", merge.display()),
        "/AR:0x1000-0x1004".to_string(),
        "/AD4".to_string(),
        "/AL".to_string(),
        "/AF:0xEE".to_string(),
        "/CS0:@append".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        "/XI".to_string(),
        "-o".to_string(),
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
        "/MT:dummy.bin".to_string(),
        "/MO:dummy.bin".to_string(),
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
        "/AR:0x2000,0x4".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        "/AR:0x2000-0x2003".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        "/AR:0x00000000-0xFFFFFFFF".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        "/AR:0xFFFFFFFC,0x4".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0xFFFF_FFFC);
    assert_eq!(norm.segments()[0].data(), vec![0xFC, 0xFD, 0xFE, 0xFF]);
}

#[test]
fn test_cli_address_range_overflowing_length_form_filters_to_u32_max() {
    let dir = temp_dir("cli_ar_overflow_len");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xFC, 0xFD, 0xFE, 0xFF]);

    let args = vec![
        format!("/IN:{};0xFFFFFFFC", input.display()),
        "/AR:0xFFFFFFFC,0x8".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0xFFFF_FFFC);
    assert_eq!(norm.segments()[0].data(), vec![0xFC, 0xFD, 0xFE, 0xFF]);
}

#[test]
fn test_cli_fill_rejects_range_past_u32_max() {
    let dir = temp_dir("cli_fr_overflow");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA]);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        "/FR:0xFFFFFFFC,0x8".to_string(),
        "/FP:FF".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("address overflow"));
}

#[test]
fn test_cli_address_range_multiple_ranges() {
    let dir = temp_dir("cli_ar_multi");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.hex");
    write_file(&base, &[0xAA, 0xAB, 0xAC, 0xAD]);
    write_file(&merge, &[0xBA, 0xBB, 0xBC, 0xBD]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x2000", merge.display()),
        "/AR:0x1000,0x2:0x2000,0x2".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let text = std::fs::read_to_string(&out).unwrap();
    assert_eq!(text.trim(), ":00000001FF");
}

#[test]
fn test_cli_address_range_repeated_last_wins() {
    let dir = temp_dir("cli_ar_last_wins");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.hex");
    write_file(&base, &[0xAA, 0xAB, 0xAC, 0xAD]);
    write_file(&merge, &[0xBA, 0xBB, 0xBC, 0xBD]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x2000", merge.display()),
        "/AR:0x1000,0x2".to_owned(),
        "/AR:0x2000,0x2".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0x2000);
    assert_eq!(norm.segments()[0].data(), vec![0xBA, 0xBB]);
}

#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

mod common;

use common::{assert_success, run_hexy, temp_dir, write_file};
use hexy_core::parse_intel_hex;

fn run_checksum_hex(input: &[u8], cs_arg: &str) -> hexy_core::HexFile {
    let dir = temp_dir("cli_checksum");
    let input_path = dir.join("input.bin");
    let out_path = dir.join("out.hex");
    write_file(&input_path, input);

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        cs_arg.to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out_path.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);

    let data = std::fs::read(&out_path).unwrap();
    parse_intel_hex(&data).unwrap()
}

#[test]
fn test_cli_checksum_append() {
    let hexfile = run_checksum_hex(&[0x01, 0x02, 0x03, 0x04], "/CS0:@append");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 6).unwrap(),
        vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x0A]
    );
}

#[test]
fn test_cli_checksum_without_target_leaves_data_unchanged() {
    let hexfile = run_checksum_hex(&[0x01, 0x02, 0x03, 0x04], "/CS0");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 4).unwrap(),
        vec![0x01, 0x02, 0x03, 0x04]
    );
    assert!(norm.read_bytes_contiguous(0x1004, 1).is_none());
}

#[test]
fn test_cli_checksum_upfront() {
    let hexfile = run_checksum_hex(&[0x01, 0x02, 0x03, 0x04], "/CS0:@upfront");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x0FFE, 6).unwrap(),
        vec![0x00, 0x0A, 0x01, 0x02, 0x03, 0x04]
    );
}

#[test]
fn test_cli_checksum_begin() {
    // @begin writes checksum at start of data (0x1000-0x1001), excluding those bytes
    // Sum of 0x03 + 0x04 = 0x07, BE format = [0x00, 0x07]
    let hexfile = run_checksum_hex(&[0x01, 0x02, 0x03, 0x04], "/CS0:@begin");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 4).unwrap(),
        vec![0x00, 0x07, 0x03, 0x04]
    );
}

#[test]
fn test_cli_checksum_overwrite_end() {
    // @end writes checksum at end of data (0x1002-0x1003), excluding those bytes
    // Sum of 0x01 + 0x02 = 0x03, BE format = [0x00, 0x03]
    let hexfile = run_checksum_hex(&[0x01, 0x02, 0x03, 0x04], "/CS0:@end");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 4).unwrap(),
        vec![0x01, 0x02, 0x00, 0x03]
    );
}

#[test]
fn test_cli_checksum_address() {
    // @0x1001 writes checksum at 0x1001-0x1002, excluding those bytes
    // Sum of 0x01 + 0x04 = 0x05, BE format = [0x00, 0x05]
    let hexfile = run_checksum_hex(&[0x01, 0x02, 0x03, 0x04], "/CS0:@0x1001");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 4).unwrap(),
        vec![0x01, 0x00, 0x05, 0x04]
    );
}

#[test]
fn test_cli_checksum_limited_range() {
    let hexfile = run_checksum_hex(&[0x01, 0x02, 0x03, 0x04], "/CS0:@append;0x1000-0x1001");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 6).unwrap(),
        vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x03]
    );
}

#[test]
fn test_cli_checksum_exclude_range() {
    let hexfile = run_checksum_hex(
        &[0x01, 0x02, 0x03, 0x04],
        "/CS0:@append;0x1000-0x1003/0x1001-0x1002",
    );
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 6).unwrap(),
        vec![0x01, 0x02, 0x03, 0x04, 0x00, 0x05]
    );
}

#[test]
fn test_cli_checksum_forced_range_fill() {
    let hexfile = run_checksum_hex(&[0x01, 0x02], "/CS0:@append;!0x1000-0x1003#FF");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 2).unwrap(),
        vec![0x01, 0x02]
    );
    assert_eq!(
        norm.read_bytes_contiguous(0x1002, 2).unwrap(),
        vec![0x00, 0x03]
    );
}

#[test]
fn test_cli_checksum_forced_range_uses_pattern_for_gaps() {
    let hexfile = run_checksum_hex(&[0x01, 0x02], "/CS0:@append;!0x1000-0x100F#FF");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1002, 2).unwrap(),
        vec![0x0B, 0xF7]
    );
}

#[test]
fn test_cli_checksum_forced_range_keeps_real_data_outside_range_virtual() {
    let dir = temp_dir("cli_checksum_forced_virtual");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out_path = dir.join("out.hex");
    write_file(&base, &[0x01]);
    write_file(&merge, &[0x02]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x2000", merge.display()),
        "/CS0:@append;!0x1000-0x1001#FF".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out_path.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);

    let data = std::fs::read(&out_path).unwrap();
    let hexfile = parse_intel_hex(&data).unwrap();
    let norm = hexfile.normalized();
    assert!(norm.read_bytes_contiguous(0x1001, 1).is_none());
    assert_eq!(
        norm.read_bytes_contiguous(0x2000, 3).unwrap(),
        vec![0x02, 0x01, 0x02]
    );
}

#[test]
fn test_cli_checksum_little_endian_output() {
    let hexfile = run_checksum_hex(&[0x01, 0x02, 0x03, 0x04], "/CSR0:@append");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 6).unwrap(),
        vec![0x01, 0x02, 0x03, 0x04, 0x0A, 0x00]
    );
}

#[test]
fn test_cli_checksum_file_output() {
    let dir = temp_dir("cli_checksum_file");
    let input_path = dir.join("input.bin");
    let out_path = dir.join("csum.txt");
    write_file(&input_path, &[0x01, 0x02, 0x03, 0x04]);

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        format!("/CS0:{}", out_path.display()),
    ];

    let output = run_hexy(&args);
    assert_success(&output);

    let text = std::fs::read_to_string(&out_path).unwrap();
    assert_eq!(text, "0x00, 0x0A");
}

#[test]
fn test_cli_checksum_sha256_file_output() {
    let dir = temp_dir("cli_checksum_file_sha256");
    let input_path = dir.join("input.bin");
    let out_path = dir.join("csum.txt");
    write_file(&input_path, b"abc");

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        format!("/CS20:{}", out_path.display()),
    ];

    let output = run_hexy(&args);
    assert_success(&output);

    let text = std::fs::read_to_string(&out_path).unwrap();
    assert_eq!(
        text,
        "0xBA, 0x78, 0x16, 0xBF, 0x8F, 0x01, 0xCF, 0xEA, 0x41, 0x41, 0x40, 0xDE, 0x5D, 0xAE, 0x22, 0x23, 0xB0, 0x03, 0x61, 0xA3, 0x96, 0x17, 0x7A, 0x9C, 0xB4, 0x10, 0xFF, 0x61, 0xF2, 0x00, 0x15, 0xAD"
    );
}

#[test]
fn test_cli_checksum_prepend_alias() {
    let hexfile = run_checksum_hex(&[0x01, 0x02], "/CS0:@prepend");
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x0000, 2).unwrap(),
        vec![0x00, 0x03]
    );
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 2).unwrap(),
        vec![0x01, 0x02]
    );
}

#[test]
fn test_cli_checksum_invalid_forced_pattern() {
    let dir = temp_dir("cli_checksum_bad");
    let input_path = dir.join("input.bin");
    write_file(&input_path, &[0x01, 0x02]);

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        "/CS0:@append;!0x1000-0x1001#F".to_owned(),
    ];

    let output = run_hexy(&args);
    assert!(!output.status.success());
}

#[test]
fn test_cli_checksum_multi_sequential_dependency() {
    let dir = temp_dir("cli_checksum_multi_seq");
    let input_path = dir.join("input.bin");
    let out_path = dir.join("out.hex");
    write_file(&input_path, &[0x01, 0x02, 0x03, 0x04]);

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        "/CSM0:@0x1000".to_owned(),
        "/CSM0:@append".to_owned(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out_path.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let data = std::fs::read(&out_path).unwrap();
    let hexfile = parse_intel_hex(&data).unwrap();
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 6).unwrap(),
        vec![0x00, 0x07, 0x03, 0x04, 0x00, 0x0E]
    );
}

#[test]
fn test_cli_checksum_multi_mixed_targets_with_file() {
    let dir = temp_dir("cli_checksum_multi_file");
    let input_path = dir.join("input.bin");
    let out_path = dir.join("out.hex");
    let csum_path = dir.join("csum.txt");
    write_file(&input_path, &[0x01, 0x02, 0x03, 0x04]);

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        "/CSM0:@0x1000".to_owned(),
        "/CSM0:@append".to_owned(),
        format!("/CSMR0:{}", csum_path.display()),
        "/XI".to_owned(),
        "-o".to_owned(),
        out_path.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let data = std::fs::read(&out_path).unwrap();
    let hexfile = parse_intel_hex(&data).unwrap();
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x1000, 6).unwrap(),
        vec![0x00, 0x07, 0x03, 0x04, 0x00, 0x0E]
    );
    let text = std::fs::read_to_string(&csum_path).unwrap();
    assert_eq!(text, "0x1C, 0x00");
}

#[test]
fn test_cli_checksum_file_survives_a_later_stage_error() {
    for (checksum_flag, later_flag) in [("CSM0", "/CSM23"), ("CS0", "/SV4:missing-key.pem!0xF")] {
        let dir = temp_dir("cli_checksum_before_error");
        let input = dir.join("input.bin");
        let checksum = dir.join("checksum.txt");
        let out = dir.join("out.hex");
        write_file(&input, &[1, 2, 3, 4]);

        let output = run_hexy(&[
            format!("/IN:{};0x1000", input.display()),
            format!("/{checksum_flag}:{}", checksum.display()),
            later_flag.to_owned(),
            "/XI".to_owned(),
            "-o".to_owned(),
            out.display().to_string(),
        ]);

        assert!(!output.status.success());
        assert_eq!(std::fs::read_to_string(checksum).unwrap(), "0x00, 0x0A");
        assert!(!out.exists());
    }
}

#[test]
fn test_cli_checksum_reject_mix_legacy_and_multi() {
    let dir = temp_dir("cli_checksum_mix_reject");
    let input_path = dir.join("input.bin");
    write_file(&input_path, &[0x01, 0x02, 0x03, 0x04]);

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        "/CS0:@append".to_owned(),
        "/CSM0:@append".to_owned(),
    ];
    let output = run_hexy(&args);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid option"));
    assert!(stderr.contains("/CSM0:@append"));
}

fn run_in(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    std::process::Command::new(env!("CARGO_BIN_EXE_hexy"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap()
}

/// HexView 1.15.2 reports a failed checksum but still runs the export.
#[test]
fn test_cli_failed_checksum_still_exports() {
    let dir = temp_dir("cli_checksum_failed");
    write_file(&dir.join("in.bin"), &[0x01, 0x08, 0x0F]);
    let output = run_in(
        &dir,
        &["/IN:in.bin;0x1000", "/CS12:@append", "/XI", "-o", "out.hex"],
    );
    assert!(!output.status.success());
    assert_eq!(
        std::fs::read(dir.join("out.hex")).unwrap(),
        b":0310000001080FD5\r\n:00000001FF\r\n"
    );
}

/// HexView 1.15.2 checksums nothing when the limiting range is invalid.
#[test]
fn test_cli_checksum_invalid_limit_range_covers_nothing() {
    let file = run_checksum_hex(&[0x01, 0x02, 0x03, 0x04], "/CS0:@0x3000;0x1003-0x1000");
    assert_eq!(
        file.read_bytes_contiguous(0x3000, 2),
        Some(vec![0x00, 0x00])
    );
}

/// HexView 1.15.2 `/CS16` reads `[constant]` from expdatproc.ini in the working directory.
#[test]
fn test_cli_constant_checksum_reads_expdatproc_ini() {
    let dir = temp_dir("cli_checksum_constant");
    write_file(&dir.join("in.bin"), &[0x01]);
    let constant = |ini: &str, flag: &str| {
        write_file(&dir.join("expdatproc.ini"), ini.as_bytes());
        assert_success(&run_in(&dir, &["/IN:in.bin", flag]));
        std::fs::read_to_string(dir.join("cs.txt")).unwrap()
    };
    assert_eq!(
        constant(
            "[CONSTANT]\r\nnumbytes=0x4\r\nHexDataString=0123456789ABCDEF\r\n",
            "/CS16:cs.txt"
        ),
        "0x01, 0x23, 0x45, 0x67"
    );
    assert_eq!(
        constant(
            "[constant]\r\nNumBytes=2\r\nHexDataString=123\r\n",
            "/CSR16:cs.txt"
        ),
        "0x03, 0x12"
    );
    assert_eq!(
        constant("[other]\r\nNumBytes=4\r\n", "/CS16:cs.txt"),
        "0x08, 0x15"
    );
}

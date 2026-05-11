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
        cs_arg.to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        vec![0x02, 0x01]
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
    assert_eq!(text, "00,0A");
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
        "BA,78,16,BF,8F,01,CF,EA,41,41,40,DE,5D,AE,22,23,B0,03,61,A3,96,17,7A,9C,B4,10,FF,61,F2,00,15,AD"
    );
}

#[test]
fn test_cli_checksum_invalid_forced_pattern() {
    let dir = temp_dir("cli_checksum_bad");
    let input_path = dir.join("input.bin");
    write_file(&input_path, &[0x01, 0x02]);

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        "/CS0:@append;!0x1000-0x1001#F".to_string(),
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
        "/CSM0:@0x1000".to_string(),
        "/CSM0:@append".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
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
        "/CSM0:@0x1000".to_string(),
        "/CSM0:@append".to_string(),
        format!("/CSMR0:{}", csum_path.display()),
        "/XI".to_string(),
        "-o".to_string(),
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
    assert_eq!(text, "1C,00");
}

#[test]
fn test_cli_checksum_reject_mix_legacy_and_multi() {
    let dir = temp_dir("cli_checksum_mix_reject");
    let input_path = dir.join("input.bin");
    write_file(&input_path, &[0x01, 0x02, 0x03, 0x04]);

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        "/CS0:@append".to_string(),
        "/CSM0:@append".to_string(),
    ];
    let output = run_hexy(&args);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid option"));
    assert!(stderr.contains("/CSM0:@append"));
}

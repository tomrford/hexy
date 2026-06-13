mod common;
mod common_hex;

use common::{assert_success, run_hexy, temp_dir, write_file};
use common_hex::run_hex_output;
use hexy_core::{HexFile, IntelHexMode, IntelHexWriteOptions, Segment, write_intel_hex};

#[test]
fn test_cli_cut_multiple_ranges_one_arg() {
    let dir = temp_dir("cli_cut_multi");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0, 1, 2, 3, 4, 5, 6, 7]);

    let args = vec![
        format!("/IN:{};0x5000", input.display()),
        "/CR:0x5001,0x1:0x5005-0x5006".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let mut segments = hexfile.segments().to_vec();
    segments.sort_by_key(|s| s.start_address());
    assert_eq!(segments.len(), 3);
    assert_eq!(segments[0].start_address(), 0x5000);
    assert_eq!(segments[0].data(), vec![0]);
    assert_eq!(segments[1].start_address(), 0x5002);
    assert_eq!(segments[1].data(), vec![2, 3, 4]);
    assert_eq!(segments[2].start_address(), 0x5007);
    assert_eq!(segments[2].data(), vec![7]);
}

#[test]
fn test_cli_merge_transparent_range_offset() {
    let dir = temp_dir("cli_mt");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.hex");
    write_file(&base, &[0x40, 0x41, 0x42, 0x43]);
    write_file(&merge, &[0xA0, 0xA1, 0xA2, 0xA3]);

    let args = vec![
        format!("/IN:{};0x4000", base.display()),
        format!("/MT:{};0x4000:0x0,0x4", merge.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x4000, 4).unwrap(),
        vec![0x40, 0x41, 0x42, 0x43]
    );
}

#[test]
fn test_cli_merge_opaque_range_offset() {
    let dir = temp_dir("cli_mo");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.hex");
    write_file(&base, &[0x40, 0x41, 0x42, 0x43]);
    write_file(&merge, &[0xA0, 0xA1, 0xA2, 0xA3]);

    let args = vec![
        format!("/IN:{};0x4000", base.display()),
        format!("/MO:{};0x4000:0x0,0x4", merge.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(
        norm.read_bytes_contiguous(0x4000, 4).unwrap(),
        vec![0xA0, 0xA1, 0xA2, 0xA3]
    );
}

#[test]
fn test_cli_mt_mo_conflict() {
    let dir = temp_dir("cli_mt_mo_conflict");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.hex");
    write_file(&base, &[0x00, 0x01]);
    write_file(&merge, &[0x10, 0x11]);

    let args = vec![
        format!("/IN:{};0x0", base.display()),
        format!("/MT:{};0x0", merge.display()),
        format!("/MO:{};0x0", merge.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert!(!output.status.success());
}

#[test]
fn test_cli_remap_s08map_conflict() {
    let dir = temp_dir("cli_remap_s08");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA; 4]);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        "/REMAP:0x0-0xFF,0x1000,0x100,0x100".to_string(),
        "/S08MAP".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("S08MAP"),
        "error should mention S08MAP: {stderr}"
    );
}

#[test]
fn test_cli_log_file_open_is_rejected_for_export() {
    let dir = temp_dir("cli_log_open_rejected");
    let input = dir.join("input.bin");
    let log = dir.join("commands.log");
    let out = dir.join("out.hex");
    write_file(&input, &[0xDE, 0xAD, 0xBE, 0xEF]);
    write_file(&log, format!("FileOpen {}", input.display()).as_bytes());

    let args = vec![
        format!("/L:{}", log.display()),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("FileOpen"));
    assert!(stderr.contains(&input.display().to_string()));
    assert!(!out.exists());
}

#[test]
fn test_cli_log_file_open_relative_path_is_rejected_with_raw_path() {
    let dir = temp_dir("cli_log_open_relative_rejected");
    let log = dir.join("commands.log");
    let out = dir.join("out.hex");
    write_file(&log, b"FileOpen relative/input.bin");

    let args = vec![
        format!("/L:{}", log.display()),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("FileOpen"));
    assert!(stderr.contains("relative/input.bin"));
    assert!(!out.exists());
}

#[test]
fn test_cli_log_file_new_clears_data() {
    let dir = temp_dir("cli_log_new");
    let input = dir.join("input.bin");
    let log = dir.join("commands.log");
    let out = dir.join("out.hex");
    write_file(&input, &[0x01, 0x02, 0x03]);
    write_file(&log, b"FileNew");

    let args = vec![
        format!("/IN:{};0x1000", input.display()),
        format!("/L:{}", log.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    assert!(hexfile.segments().is_empty());
}

#[test]
fn test_cli_log_file_invalid_command() {
    let dir = temp_dir("cli_log_invalid");
    let input = dir.join("input.bin");
    let log = dir.join("commands.log");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA]);
    write_file(&log, b"BogusCommand");

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        format!("/L:{}", log.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert!(!output.status.success());
}

#[test]
fn test_cli_version_string_written_to_error_log() {
    let dir = temp_dir("cli_version_log");
    let input = dir.join("input.bin");
    let err = dir.join("error.log");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA, 0xBB]);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        format!("/E:{}", err.display()),
        "/V".to_string(),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let log = std::fs::read_to_string(&err).unwrap();
    assert_eq!(log, format!("hexy V{}", env!("CARGO_PKG_VERSION")));
}

#[test]
fn test_cli_import_i16_scales_addresses() {
    let dir = temp_dir("cli_i16_import");
    let input = dir.join("input.hex");
    let out = dir.join("out.hex");
    let hex = b":02000100AABB98\n:00000001FF\n";
    write_file(&input, hex);

    let args = vec![
        format!("/II2={}", input.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0x0002);
    assert_eq!(norm.segments()[0].data(), vec![0xAA, 0xBB]);
}

#[test]
fn test_cli_merge_opaque_without_input_starts_empty() {
    let dir = temp_dir("cli_merge_no_input");
    let merge = dir.join("merge.hex");
    let out = dir.join("out.hex");
    let hex = b":02000100AABB98\n:00000001FF\n";
    write_file(&merge, hex);

    let args = vec![
        format!("/MO:{};0x1000", merge.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let norm = hexfile.normalized();
    assert_eq!(norm.segments().len(), 1);
    assert_eq!(norm.segments()[0].start_address(), 0x1001);
    assert_eq!(norm.segments()[0].data(), vec![0xAA, 0xBB]);
}

#[test]
fn test_cli_s08map_examples() {
    let dir = temp_dir("cli_s08map");
    let input = dir.join("input.hex");
    let out = dir.join("out.hex");
    let hexfile = HexFile::with_segments(vec![
        Segment::new(0x4000, vec![0xAA]),
        Segment::new(0x028000, vec![0xBB]),
    ]);
    let data = write_intel_hex(&hexfile, &IntelHexWriteOptions::default()).unwrap();
    write_file(&input, &data);

    let args = vec![
        input.display().to_string(),
        "/S08MAP".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let mut segments = hexfile.segments().to_vec();
    segments.sort_by_key(|s| s.start_address());
    assert_eq!(segments[0].start_address(), 0x104000);
    assert_eq!(segments[1].start_address(), 0x108000);
}

#[test]
fn test_cli_dspic_expand_default_target() {
    let dir = temp_dir("cli_cdspx");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA, 0xBB, 0xCC, 0xDD]);

    let args = vec![
        format!("/IN:{};0x1000", input.display()),
        "/CDSPX:0x1000,0x4".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let out_bytes = hexfile.read_bytes_contiguous(0x2000, 8).unwrap();
    assert_eq!(
        out_bytes,
        vec![0xAA, 0xBB, 0x00, 0x00, 0xCC, 0xDD, 0x00, 0x00]
    );
}

#[test]
fn test_cli_dspic_expand_explicit_target_colon() {
    let dir = temp_dir("cli_cdspx_target_colon");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA, 0xBB, 0xCC, 0xDD]);

    let args = vec![
        format!("/IN:{};0x1000", input.display()),
        "/CDSPX:0x1000,0x4:0x4000".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    assert_eq!(
        hexfile.read_bytes_contiguous(0x1000, 4).unwrap(),
        vec![0xAA, 0xBB, 0xCC, 0xDD]
    );
    assert_eq!(
        hexfile.read_bytes_contiguous(0x2000, 8).unwrap(),
        vec![0xAA, 0xBB, 0x00, 0x00, 0xCC, 0xDD, 0x00, 0x00]
    );
}

#[test]
fn test_cli_dspic_expand_explicit_target_semicolon() {
    let dir = temp_dir("cli_cdspx_target_semicolon");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA, 0xBB, 0xCC, 0xDD]);

    let args = vec![
        format!("/IN:{};0x1000", input.display()),
        "/CDSPX:0x1000,0x4;0x4000".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    assert_eq!(
        hexfile.read_bytes_contiguous(0x4000, 8).unwrap(),
        vec![0xAA, 0xBB, 0x00, 0x00, 0xCC, 0xDD, 0x00, 0x00]
    );
}

#[test]
fn test_cli_dspic_shrink_default_target() {
    let dir = temp_dir("cli_cdsps");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);

    let args = vec![
        format!("/IN:{};0x2000", input.display()),
        "/CDSPS:0x2000,0x8".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let out_bytes = hexfile.read_bytes_contiguous(0x1000, 4).unwrap();
    assert_eq!(out_bytes, vec![0x11, 0x22, 0x55, 0x66]);
}

#[test]
fn test_cli_dspic_clear_ghost() {
    let dir = temp_dir("cli_cdspg");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0x01, 0x02, 0x03, 0xFF, 0x10, 0x11, 0x12, 0xEE]);

    let args = vec![
        format!("/IN:{};0x3000", input.display()),
        "/CDSPG:0x3000,0x8".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let out_bytes = hexfile.read_bytes_contiguous(0x3000, 8).unwrap();
    assert_eq!(
        out_bytes,
        vec![0x01, 0x02, 0x03, 0x00, 0x10, 0x11, 0x12, 0x00]
    );
}

#[test]
fn test_cli_hex_ascii_single_digit_tokens() {
    let dir = temp_dir("cli_hex_ascii_tokens");
    let input = dir.join("input.txt");
    let out = dir.join("out.hex");
    write_file(&input, b"A B C");

    let args = vec![
        format!("/IA:{}", input.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let out_bytes = hexfile.read_bytes_contiguous(0x0, 3).unwrap();
    assert_eq!(out_bytes, vec![0x0A, 0x0B, 0x0C]);
}

#[test]
fn test_cli_auto_detect_binary_on_non_ascii() {
    let dir = temp_dir("cli_auto_bin");
    let input = dir.join("input.dat");
    let out = dir.join("out.bin");
    write_file(&input, &[0xFF, 0x00, 0x01]);

    let args = vec![
        input.display().to_string(),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let data = std::fs::read(&out).unwrap();
    assert_eq!(data, vec![0xFF, 0x00, 0x01]);
}

#[test]
fn test_cli_auto_detect_binary_on_ascii_without_markers() {
    let dir = temp_dir("cli_auto_ascii_bin");
    let input = dir.join("input.txt");
    let out = dir.join("out.bin");
    let data = b"HELLO\nWORLD\n";
    write_file(&input, data);

    let args = vec![
        input.display().to_string(),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let written = std::fs::read(&out).unwrap();
    assert_eq!(written, data);
}

#[test]
fn test_cli_auto_detect_ihex_after_blank_lines() {
    let dir = temp_dir("cli_auto_ihex_blanks");
    let input = dir.join("input.hex");
    let out = dir.join("out.bin");
    let data = b"\n\n:020000040000FA\n:020000000102FB\n:00000001FF\n";
    write_file(&input, data);

    let args = vec![
        input.display().to_string(),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);
    let data = std::fs::read(&out).unwrap();
    assert_eq!(data, vec![0x01, 0x02]);
}

#[test]
fn test_cli_auto_detect_header_then_ihex_exports_ihex_data()
-> Result<(), Box<dyn std::error::Error>> {
    let dir = temp_dir("cli_auto_ihex_header");
    let input = dir.join("input.txt");
    let out = dir.join("out.hex");
    let content = "HEADER\n:020000000102FB\n:00000001FF\n";
    write_file(&input, content.as_bytes());

    let args = vec![
        input.display().to_string(),
        "/XI".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let text = std::fs::read_to_string(&out)?;
    assert_eq!(text, ":020000000102FB\n:00000001FF\n".replace('\n', "\r\n"));
    Ok(())
}

#[test]
fn test_cli_auto_detect_ignores_ihex_after_25_lines() {
    let dir = temp_dir("cli_auto_ihex_after_25");
    let input = dir.join("input.txt");
    let out = dir.join("out.bin");
    let mut content = String::new();
    for _ in 0..25 {
        content.push_str("HELLO\n");
    }
    content.push_str(":00000001FF\n");
    write_file(&input, content.as_bytes());

    let args = vec![
        input.display().to_string(),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert_success(&output);
    let written = std::fs::read(&out).unwrap();
    assert_eq!(written, content.as_bytes());
}

#[test]
fn test_cli_auto_detect_srec_after_blank_lines() {
    let dir = temp_dir("cli_auto_srec_blanks");
    let input = dir.join("input.s19");
    let out = dir.join("out.bin");
    let data = b"\n\nS10500000102F7\nS9030000FC\n";
    write_file(&input, data);

    let args = vec![
        input.display().to_string(),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);
    let data = std::fs::read(&out).unwrap();
    assert_eq!(data, vec![0x01, 0x02]);
}

#[test]
fn test_cli_auto_detect_srec_lowercase() {
    let dir = temp_dir("cli_auto_srec_lower");
    let input = dir.join("input.s19");
    let out = dir.join("out.bin");
    let data = b"s10500000102f7\ns9030000fc\n";
    write_file(&input, data);

    let args = vec![
        input.display().to_string(),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);
    let data = std::fs::read(&out).unwrap();
    assert_eq!(data, vec![0x01, 0x02]);
}

#[test]
fn test_cli_hex_ascii_overlap_ignores_input() {
    let dir = temp_dir("cli_hex_ascii_overlap");
    let input = dir.join("input.hex");
    let ascii = dir.join("ascii.txt");
    let out = dir.join("out.bin");
    write_file(&input, b":01000000AA55\n:00000001FF\n");
    write_file(&ascii, b"01 02");

    let args = vec![
        input.display().to_string(),
        format!("/IA:{}", ascii.display()),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);
    let data = std::fs::read(&out).unwrap();
    assert_eq!(data, vec![0x01, 0x02]);
}

#[test]
fn test_cli_remap_basic() {
    let dir = temp_dir("cli_remap");
    let input = dir.join("input.hex");
    let out = dir.join("out.hex");
    let hexfile = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0xAA]),
        Segment::new(0x018000, vec![0x01, 0x02]),
        Segment::new(0x028000, vec![0x03]),
    ]);
    let data = write_intel_hex(
        &hexfile,
        &IntelHexWriteOptions {
            bytes_per_line: 16,
            mode: IntelHexMode::ExtendedLinear,
        },
    )
    .unwrap();
    write_file(&input, &data);

    let args = vec![
        input.display().to_string(),
        "/remap:0x018000-0x02BFFF,0x008000,0x4000,0x010000".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let mut segments = hexfile.segments().to_vec();
    segments.sort_by_key(|s| s.start_address());
    assert_eq!(segments.len(), 3);
    assert_eq!(segments[0].start_address(), 0x1000);
    assert_eq!(segments[1].start_address(), 0x008000);
    assert_eq!(segments[2].start_address(), 0x00C000);
}

#[test]
fn test_cli_remap_invalid_size() {
    let dir = temp_dir("cli_remap_invalid");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA]);

    let args = vec![
        format!("/IN:{};0x018000", input.display()),
        "/remap:0x018000-0x01BFFF,0x0,0x0,0x010000".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let output = run_hexy(&args);
    assert!(!output.status.success());
}

#[test]
fn test_cli_s12map_basic() {
    let dir = temp_dir("cli_s12map");
    let input = dir.join("input.hex");
    let out = dir.join("out.hex");
    let hexfile = HexFile::with_segments(vec![
        Segment::new(0x4000, vec![0xAA]),
        Segment::new(0xC000, vec![0xBB]),
        Segment::new(0x308000, vec![0x01]),
        Segment::new(0x318000, vec![0x02]),
    ]);
    let data = write_intel_hex(
        &hexfile,
        &IntelHexWriteOptions {
            bytes_per_line: 16,
            mode: IntelHexMode::ExtendedLinear,
        },
    )
    .unwrap();
    write_file(&input, &data);

    let args = vec![
        input.display().to_string(),
        "/s12map".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let mut segments = hexfile.segments().to_vec();
    segments.sort_by_key(|s| s.start_address());
    assert_eq!(segments.len(), 4);
    assert_eq!(segments[0].start_address(), 0x0C0000);
    assert_eq!(segments[1].start_address(), 0x0C4000);
    assert_eq!(segments[2].start_address(), 0x0F8000);
    assert_eq!(segments[3].start_address(), 0x0FC000);
}

#[test]
fn test_cli_s12xmap_basic() {
    let dir = temp_dir("cli_s12xmap");
    let input = dir.join("input.hex");
    let out = dir.join("out.hex");
    let hexfile = HexFile::with_segments(vec![
        Segment::new(0x4000, vec![0xAA]),
        Segment::new(0xC000, vec![0xBB]),
        Segment::new(0xE08000, vec![0x01]),
        Segment::new(0xE18000, vec![0x02]),
    ]);
    let data = write_intel_hex(
        &hexfile,
        &IntelHexWriteOptions {
            bytes_per_line: 16,
            mode: IntelHexMode::ExtendedLinear,
        },
    )
    .unwrap();
    write_file(&input, &data);

    let args = vec![
        input.display().to_string(),
        "/s12xmap".to_string(),
        "/XI".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];

    let hexfile = run_hex_output(args, &out);
    let mut segments = hexfile.segments().to_vec();
    segments.sort_by_key(|s| s.start_address());
    assert_eq!(segments.len(), 4);
    assert_eq!(segments[0].start_address(), 0x780000);
    assert_eq!(segments[1].start_address(), 0x784000);
    assert_eq!(segments[2].start_address(), 0x7F4000);
    assert_eq!(segments[3].start_address(), 0x7FC000);
}

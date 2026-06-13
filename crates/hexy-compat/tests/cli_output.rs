mod common;
mod common_lines;

use common::{assert_success, run_hexy, temp_dir, write_file};
use common_lines::read_nonempty_lines;

fn parse_hex_pairs(line: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let pair = &line[i..i + 2];
        if let Ok(b) = u8::from_str_radix(pair, 16) {
            out.push(b);
            i += 2;
        } else {
            break;
        }
    }
    out
}

#[test]
fn test_cli_hex_ascii_basic() {
    let dir = temp_dir("cli_xa_basic");
    let input = dir.join("input.bin");
    let out = dir.join("out.txt");
    let data: Vec<u8> = (0u8..32).collect();
    write_file(&input, &data);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        "/XA:16".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let lines = read_nonempty_lines(&out);
    assert_eq!(lines.len(), 2);
    for (idx, line) in lines.iter().enumerate() {
        assert_eq!(line.len(), 32);
        let parsed = parse_hex_pairs(line);
        assert_eq!(parsed.len(), 16);
        let expected = &data[idx * 16..(idx + 1) * 16];
        assert_eq!(parsed, expected);
    }
}

#[test]
fn test_cli_hex_ascii_separator() {
    let dir = temp_dir("cli_xa_sep");
    let input = dir.join("input.bin");
    let out = dir.join("out.txt");
    let data: Vec<u8> = (0u8..16).collect();
    write_file(&input, &data);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        "/XA:16:, ".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let lines = read_nonempty_lines(&out);
    assert_eq!(lines.len(), 1);
    let parts: Vec<&str> = lines[0].split(", ").collect();
    assert_eq!(parts.len(), 16);
    assert!(!lines[0].ends_with(", "));
    let parsed: Vec<u8> = parts
        .iter()
        .map(|p| u8::from_str_radix(p, 16).unwrap())
        .collect();
    assert_eq!(parsed, data);
}

#[test]
fn test_cli_hex_ascii_long_line() {
    let dir = temp_dir("cli_xa_long");
    let input = dir.join("input.bin");
    let out = dir.join("out.txt");
    let data: Vec<u8> = (0u8..32).collect();
    write_file(&input, &data);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        "/XA:0xffffffff".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let lines = read_nonempty_lines(&out);
    assert_eq!(lines.len(), 1);
}

#[test]
fn test_cli_intel_hex_reclen() {
    let dir = temp_dir("cli_xi_reclen");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    let data: Vec<u8> = (0u8..32).collect();
    write_file(&input, &data);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        "/XI:16".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let lines = read_nonempty_lines(&out);
    for line in lines {
        if line.starts_with(':') && line.len() >= 11 {
            let count = u8::from_str_radix(&line[1..3], 16).unwrap();
            let rectype = &line[7..9];
            if rectype == "00" {
                assert_eq!(count, 0x10);
            }
        }
    }
}

#[test]
fn test_cli_intel_hex_reclen_zero_defaults() {
    let dir = temp_dir("cli_xi_reclen_zero");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    let data: Vec<u8> = (0u8..20).collect();
    write_file(&input, &data);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        "/XI:0".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let lines = read_nonempty_lines(&out);
    for line in lines {
        if line.starts_with(':') && line.len() >= 11 {
            let count = u8::from_str_radix(&line[1..3], 16).unwrap();
            let rectype = &line[7..9];
            if rectype == "00" {
                assert_eq!(count, 0x10);
                break;
            }
        }
    }
}

#[test]
fn test_cli_intel_hex_forced_modes() {
    let dir = temp_dir("cli_xi_modes");
    let input = dir.join("input.bin");
    let out_linear = dir.join("out_linear.hex");
    let out_segment = dir.join("out_segment.hex");
    write_file(&input, &[0xAA, 0xBB]);

    let args_linear = vec![
        format!("/IN:{};0x12000", input.display()),
        "/XI:16:1".to_string(),
        "-o".to_string(),
        out_linear.display().to_string(),
    ];
    let output = run_hexy(&args_linear);
    assert_success(&output);
    let text = std::fs::read_to_string(&out_linear).unwrap();
    assert!(text.contains(":02000004"));

    let args_segment = vec![
        format!("/IN:{};0x12000", input.display()),
        "/XI:16:2".to_string(),
        "-o".to_string(),
        out_segment.display().to_string(),
    ];
    let output = run_hexy(&args_segment);
    assert_success(&output);
    let text = std::fs::read_to_string(&out_segment).unwrap();
    assert!(text.contains(":02000002"));
}

#[test]
fn test_cli_intel_hex_auto_modes() {
    let dir = temp_dir("cli_xi_auto");
    let input_seg = dir.join("input_seg.bin");
    let input_lin = dir.join("input_lin.bin");
    let out_seg = dir.join("out_seg.hex");
    let out_lin = dir.join("out_lin.hex");
    write_file(&input_seg, &[0xAA, 0xBB]);
    write_file(&input_lin, &[0xCC, 0xDD]);

    let args_seg = vec![
        format!("/IN:{};0x12000", input_seg.display()),
        "/XI:16".to_string(),
        "-o".to_string(),
        out_seg.display().to_string(),
    ];
    let output = run_hexy(&args_seg);
    assert_success(&output);
    let text = std::fs::read_to_string(&out_seg).unwrap();
    assert!(text.contains(":02000002"));

    let args_lin = vec![
        format!("/IN:{};0x120000", input_lin.display()),
        "/XI:16".to_string(),
        "-o".to_string(),
        out_lin.display().to_string(),
    ];
    let output = run_hexy(&args_lin);
    assert_success(&output);
    let text = std::fs::read_to_string(&out_lin).unwrap();
    assert!(text.contains(":02000004"));
}

#[test]
fn test_cli_srec_auto_and_forced() {
    let dir = temp_dir("cli_xs");
    let input_small = dir.join("input_small.bin");
    let input_mid = dir.join("input_mid.bin");
    let input_large = dir.join("input_large.bin");
    let out_small = dir.join("out_small.s19");
    let out_mid = dir.join("out_mid.s19");
    let out_large = dir.join("out_large.s19");
    write_file(&input_small, &[0x01, 0x02]);
    write_file(&input_mid, &[0x03, 0x04]);
    write_file(&input_large, &[0x05, 0x06]);

    let args_small = vec![
        format!("/IN:{};0x0100", input_small.display()),
        "/XS:16".to_string(),
        "-o".to_string(),
        out_small.display().to_string(),
    ];
    let output = run_hexy(&args_small);
    assert_success(&output);
    let line = read_nonempty_lines(&out_small)[0].clone();
    assert!(line.starts_with("S1"));

    let args_mid = vec![
        format!("/IN:{};0x10000", input_mid.display()),
        "/XS:16".to_string(),
        "-o".to_string(),
        out_mid.display().to_string(),
    ];
    let output = run_hexy(&args_mid);
    assert_success(&output);
    let line = read_nonempty_lines(&out_mid)[0].clone();
    assert!(line.starts_with("S2"));

    let args_large = vec![
        format!("/IN:{};0x1000000", input_large.display()),
        "/XS:16".to_string(),
        "-o".to_string(),
        out_large.display().to_string(),
    ];
    let output = run_hexy(&args_large);
    assert_success(&output);
    let line = read_nonempty_lines(&out_large)[0].clone();
    assert!(line.starts_with("S3"));

    let forced_s1 = vec![
        format!("/IN:{};0x0100", input_small.display()),
        "/XS:16:0".to_string(),
        "-o".to_string(),
        out_mid.display().to_string(),
    ];
    let output = run_hexy(&forced_s1);
    assert_success(&output);
    let line = read_nonempty_lines(&out_mid)[0].clone();
    assert!(line.starts_with("S1"));
}

#[test]
fn test_cli_srec_reclen() {
    let dir = temp_dir("cli_xs_reclen");
    let input = dir.join("input.bin");
    let out = dir.join("out.s19");
    let data: Vec<u8> = (0u8..16).collect();
    write_file(&input, &data);

    let args = vec![
        format!("/IN:{};0x0100", input.display()),
        "/XS:8".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let lines = read_nonempty_lines(&out);
    for line in lines {
        if !line.starts_with('S') || line.len() < 4 {
            continue;
        }
        let record_type = line.chars().nth(1).unwrap_or('0');
        if record_type == '1' || record_type == '2' || record_type == '3' {
            let count = u8::from_str_radix(&line[2..4], 16).unwrap() as usize;
            let addr_len = match record_type {
                '1' => 4,
                '2' => 6,
                _ => 8,
            };
            let data_len = count - (addr_len / 2) - 1;
            assert_eq!(data_len, 8);
        }
    }
}

#[test]
fn test_cli_srec_rectype_without_reclen_uses_default_length() {
    let dir = temp_dir("cli_xs_rectype_reclen");
    let input = dir.join("input.bin");
    let out = dir.join("out.s19");
    let data: Vec<u8> = (0u8..32).collect();
    write_file(&input, &data);

    let args = vec![
        format!("/IN:{};0x01000000", input.display()),
        "/XS:16:2".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);
    let lines = read_nonempty_lines(&out);
    assert_eq!(lines[0], "S31501000000000102030405060708090A0B0C0D0E0F71");
    assert_eq!(lines[1], "S31501000010101112131415161718191A1B1C1D1E1F61");

    let args_alias = vec![
        format!("/IN:{};0x01000000", input.display()),
        "/XS:16:3".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args_alias);
    assert_success(&output);
    let lines = read_nonempty_lines(&out);
    assert_eq!(lines[0], "S31501000000000102030405060708090A0B0C0D0E0F71");
}

#[test]
fn test_cli_intel_hex_rectype_requires_reclen() {
    let dir = temp_dir("cli_xi_rectype_reclen");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA, 0xBB]);

    let args = vec![
        format!("/IN:{};0x0100", input.display()),
        "/XI::2".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert!(!output.status.success());
}

#[test]
fn test_cli_srec_reclen_zero_defaults() {
    let dir = temp_dir("cli_xs_reclen_zero");
    let input = dir.join("input.bin");
    let out = dir.join("out.s19");
    let data: Vec<u8> = (0u8..20).collect();
    write_file(&input, &data);

    let args = vec![
        format!("/IN:{};0x0100", input.display()),
        "/XS:0".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let lines = read_nonempty_lines(&out);
    let data_lines: Vec<&str> = lines
        .iter()
        .filter(|l| l.starts_with("S1") || l.starts_with("S2") || l.starts_with("S3"))
        .map(|s| s.as_str())
        .collect();
    assert!(!data_lines.is_empty());
    let line = data_lines[0];
    let count = u8::from_str_radix(&line[2..4], 16).unwrap() as usize;
    let data_len = count - 2 - 1; // S1 address length
    assert_eq!(data_len, 20);
}

#[test]
fn test_cli_binary_and_separate_binary() {
    let dir = temp_dir("cli_xn_xsb");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.bin");
    write_file(&base, &[0x01, 0x02]);
    write_file(&merge, &[0x03, 0x04]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x2000", merge.display()),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);
    let data = std::fs::read(&out).unwrap();
    assert_eq!(data, vec![0x01, 0x02, 0x03, 0x04]);

    let out_sep = dir.join("sep.bin");
    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x2000", merge.display()),
        "/XSB".to_string(),
        "-o".to_string(),
        out_sep.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);
    let file1 = dir.join("sep_1000.bin");
    let file2 = dir.join("sep_2000.bin");
    assert_eq!(std::fs::read(file1).unwrap(), vec![0x01, 0x02]);
    assert_eq!(std::fs::read(file2).unwrap(), vec![0x03, 0x04]);

    let out_sep_dat = dir.join("sep.dat");
    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x2000", merge.display()),
        "/XSB".to_string(),
        "-o".to_string(),
        out_sep_dat.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);
    let file1 = dir.join("sep_1000.dat");
    let file2 = dir.join("sep_2000.dat");
    assert_eq!(std::fs::read(file1).unwrap(), vec![0x01, 0x02]);
    assert_eq!(std::fs::read(file2).unwrap(), vec![0x03, 0x04]);
}

#[test]
fn test_cli_separate_binary_preserves_split_blocks() -> std::io::Result<()> {
    let dir = temp_dir("cli_xsb_split");
    let input = dir.join("input.bin");
    let out = dir.join("out.bin");
    write_file(&input, &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);

    let args = vec![
        format!("/IN:{};0x1000", input.display()),
        "/SB:4".to_owned(),
        "/XSB".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    assert_eq!(
        std::fs::read(dir.join("out_1000.bin"))?,
        vec![0x00, 0x01, 0x02, 0x03]
    );
    assert_eq!(
        std::fs::read(dir.join("out_1004.bin"))?,
        vec![0x04, 0x05, 0x06, 0x07]
    );
    Ok(())
}

#[test]
fn test_cli_binary_address_order() {
    let dir = temp_dir("cli_xn_order");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.bin");
    write_file(&base, &[0x01]);
    write_file(&merge, &[0x02]);

    let args = vec![
        format!("/IN:{};0x2000", base.display()),
        format!("/MO:{};0x1000", merge.display()),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);
    let data = std::fs::read(&out).unwrap();
    assert_eq!(data, vec![0x02, 0x01]);
}

#[test]
fn test_cli_porsche_requires_checksum_without_partial_output() {
    let dir = temp_dir("cli_xp_requires_cs");
    let input = dir.join("input.bin");
    let out = dir.join("out.bin");
    write_file(&input, &[0x01, 0x02]);

    let args = vec![
        format!("/IN:{};0x1000", input.display()),
        "/XP".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("/XP requires /CS or /CSR"));
    assert!(!out.exists());
}

#[test]
fn test_cli_porsche_appends_selected_checksum_over_dense_filled_output() {
    let dir = temp_dir("cli_xp_checksum");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.bin");
    write_file(&base, &[0x01, 0x02]);
    write_file(&merge, &[0x03]);

    let args = vec![
        format!("/IN:{};0x1000", base.display()),
        format!("/MO:{};0x1004", merge.display()),
        "/AF:00".to_string(),
        "/CS0".to_string(),
        "/XP".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let data = std::fs::read(&out).unwrap();
    assert_eq!(data, vec![0x01, 0x02, 0x00, 0x00, 0x03, 0x00, 0x06]);
}

#[test]
fn test_cli_porsche_rejects_large_sparse_span_without_partial_output() {
    let dir = temp_dir("cli_xp_large_sparse");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.bin");
    write_file(&base, &[0x01]);
    write_file(&merge, &[0x02]);

    let args = vec![
        format!("/IN:{};0x0", base.display()),
        format!("/MO:{};0x20000000", merge.display()),
        "/CS0".to_string(),
        "/XP".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("dense materialization span too large"));
    assert!(!out.exists());
}

#[test]
fn test_cli_fill_all_rejects_large_sparse_span_without_partial_output() {
    let dir = temp_dir("cli_fa_large_sparse");
    let base = dir.join("base.bin");
    let merge = dir.join("merge.bin");
    let out = dir.join("out.bin");
    write_file(&base, &[0x01]);
    write_file(&merge, &[0x02]);

    let args = vec![
        format!("/IN:{};0x0", base.display()),
        format!("/MO:{};0x20000000", merge.display()),
        "/FA".to_string(),
        "/XN".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("/FA"));
    assert!(stderr.contains("dense materialization span too large"));
    assert!(!out.exists());
}

#[test]
fn test_cli_output_option_exclusive() {
    let dir = temp_dir("cli_xx_excl");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0x01, 0x02]);

    let args = vec![
        format!("/IN:{};0x0", input.display()),
        "/XA:16".to_string(),
        "/XI:16".to_string(),
        "-o".to_string(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert!(!output.status.success());
}

#[test]
fn test_cli_unsupported_output_rejected_without_output_file() {
    let dir = temp_dir("cli_xv_unsupported");
    let input = dir.join("input.bin");
    write_file(&input, &[0x01, 0x02]);

    let args = vec![format!("/IN:{};0x0", input.display()), "/XV".to_string()];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid option: /XV"));
}

#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

mod common;

use common::{assert_success, run_hexy, temp_dir, write_file};
use ed25519_dalek::SigningKey as EdSigningKey;
use ed25519_dalek::pkcs8::EncodePrivateKey as EdEncodePrivateKey;

fn write_ed25519_private_key(dir: &std::path::Path, prefix: &str) -> std::path::PathBuf {
    let secret = [0x42u8; 32];
    let signing = EdSigningKey::from_bytes(&secret);
    let private_path = dir.join(format!("{prefix}_private.der"));
    let private_der = signing.to_pkcs8_der().unwrap();
    write_file(&private_path, private_der.as_bytes());
    private_path
}

#[test]
fn test_cli_intel_hex_forced_extended_segment_rejects_high_address() {
    let dir = temp_dir("cli_xi_segment_high_address");
    let input = dir.join("input.bin");
    let out = dir.join("out.hex");
    write_file(&input, &[0xAA]);

    let args = vec![
        format!("/IN:{};0x100000", input.display()),
        "/XI:16:2".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("extended segment"));
}

/// Contiguous records split by extended address records, then blocks of 8 and 7 bytes.
const BLOCKS_HEX: &str = ":020000040000FA\r\n:10100000000102030405060708090A0B0C0D0E0F68\r\n\
:020000040000FA\r\n:041010001011121396\r\n:020000040000FA\r\n:081100000000000000000000E7\r\n\
:020000040000FA\r\n:0712000000000000000000E7\r\n:00000001FF\r\n";

fn run_in(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_hexy"))
        .current_dir(dir)
        .args(args)
        .output()
        .unwrap();
    assert_success(&output);
    output
}

/// HexView 1.15.2 writes the separator verbatim after every byte that does not end a line.
#[test]
fn test_cli_hex_ascii_matches_hexview() {
    let dir = temp_dir("cli_xa_hexview");
    write_file(&dir.join("in.bin"), &[0x01, 0x08, 0x0F, 0x16, 0x1D, 0x24]);
    run_in(&dir, &["/IN:in.bin", "/XA:4:, ", "-o", "out.asc"]);
    assert_eq!(
        std::fs::read(dir.join("out.asc")).unwrap(),
        b"01, 08, 0F, 16\r\n1D, 24, "
    );
}

/// HexView 1.15.2: an unknown S-Record type selects records automatically, and a record
/// length of 0 writes no data records.
#[test]
fn test_cli_srec_parameters_match_hexview() {
    let dir = temp_dir("cli_xs_hexview");
    write_file(
        &dir.join("in.bin"),
        &[0x01, 0x08, 0x0F, 0x16, 0x1D, 0x24, 0x2B, 0x32],
    );
    run_in(&dir, &["/IN:in.bin;0x1000", "/XS:16:3", "-o", "auto.s19"]);
    run_in(&dir, &["/IN:in.bin;0x1000", "/XS:0:2", "-o", "empty.s19"]);
    assert_eq!(
        std::fs::read(dir.join("auto.s19")).unwrap(),
        b"S10B100001080F161D242B3218\r\nS9030000FC\r\n"
    );
    assert_eq!(
        std::fs::read(dir.join("empty.s19")).unwrap(),
        b"S70500000000FA\r\n"
    );
}

/// HexView 1.15.2 writes nothing without an export flag, and exports to the input name
/// with the format's extension without `-o`.
#[test]
fn test_cli_output_file_follows_export_flag() {
    let dir = temp_dir("cli_output_name");
    write_file(&dir.join("in.hex"), BLOCKS_HEX.as_bytes());
    run_in(&dir, &["in.hex", "-o", "out.hex"]);
    assert!(!dir.join("out.hex").exists());
    run_in(&dir, &["in.hex", "/XS"]);
    run_in(&dir, &["in.hex", "/XA"]);
    assert!(dir.join("in.s19").exists());
    assert!(dir.join("in.asc").exists());
}

/// HexView 1.15.2: records that continue each other form one block, and `/RB` removes the
/// blocks shorter than its value.
#[test]
fn test_cli_remove_small_blocks_matches_hexview() {
    let dir = temp_dir("cli_rb_hexview");
    write_file(&dir.join("in.hex"), BLOCKS_HEX.as_bytes());
    run_in(&dir, &["in.hex", "/RB=8", "/XI:16", "-o", "out.hex"]);
    assert_eq!(
        std::fs::read_to_string(dir.join("out.hex")).unwrap(),
        ":10100000000102030405060708090A0B0C0D0E0F68\r\n:041010001011121396\r\n\
         :081100000000000000000000E7\r\n:00000001FF\r\n"
    );
    run_in(&dir, &["in.hex", "/XSB", "-o", "out"]);
    assert_eq!(std::fs::read(dir.join("out_1000")).unwrap().len(), 0x14);
}

/// HexView 1.15.2 removes split pieces below the `/RB` size; `/SB` under 0x100 is ignored.
#[test]
fn test_cli_remove_small_blocks_after_split() {
    let dir = temp_dir("cli_rb_split");
    write_file(&dir.join("in.bin"), &[0xAA; 0x300]);
    run_in(
        &dir,
        &[
            "/IN:in.bin;0x1000",
            "/SB:0x100",
            "/RB=0x101",
            "/XI",
            "-o",
            "split.hex",
        ],
    );
    run_in(
        &dir,
        &[
            "/IN:in.bin;0x1000",
            "/SB:0xFF",
            "/RB=0x101",
            "/XN",
            "-o",
            "kept.bin",
        ],
    );
    assert_eq!(
        std::fs::read(dir.join("split.hex")).unwrap(),
        b":00000001FF\r\n"
    );
    assert_eq!(std::fs::read(dir.join("kept.bin")).unwrap().len(), 0x300);
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
        "/XN".to_owned(),
        "-o".to_owned(),
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
        "/XSB".to_owned(),
        "-o".to_owned(),
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
        "/XSB".to_owned(),
        "-o".to_owned(),
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
        "/XN".to_owned(),
        "-o".to_owned(),
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
        "/XP".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("/XP requires /CS or /CSR"));
    assert!(!out.exists());
}

#[test]
fn test_cli_porsche_rejects_checksum_multi_before_signature_sidecar() {
    let dir = temp_dir("cli_xp_csm_preflight");
    let input = dir.join("input.bin");
    let out = dir.join("out.bin");
    let signature = dir.join("sig.bin");
    let private_key = write_ed25519_private_key(&dir, "ed");
    write_file(&input, &[0x01, 0x02]);

    let args = vec![
        format!("/IN:{};0x1000", input.display()),
        "/XP".to_owned(),
        "/CSM0:@append".to_owned(),
        format!("/DP46:{};{}", private_key.display(), signature.display()),
        "-o".to_owned(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("/CSM is not supported for /XP"));
    assert!(!signature.exists());
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
        "/AF:00".to_owned(),
        "/CS0".to_owned(),
        "/XP".to_owned(),
        "-o".to_owned(),
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
        "/CS0".to_owned(),
        "/XP".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("dense span"));
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
        "/FA".to_owned(),
        "/XN".to_owned(),
        "-o".to_owned(),
        out.display().to_string(),
    ];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("/FA"));
    assert!(stderr.contains("dense span"));
    assert!(!out.exists());
}

#[test]
fn test_cli_unsupported_output_rejected_without_output_file() {
    let dir = temp_dir("cli_xv_unsupported");
    let input = dir.join("input.bin");
    write_file(&input, &[0x01, 0x02]);

    let args = vec![format!("/IN:{};0x0", input.display()), "/XV".to_owned()];
    let output = run_hexy(&args);

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid option: /XV"));
}

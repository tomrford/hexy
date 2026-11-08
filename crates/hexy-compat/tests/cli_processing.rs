#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

//! `/DP` and `/SV` against HexView 1.15.2 behaviour, with the hexy-core key fixtures
//! and the image their pinned signatures cover.

mod common;

use std::path::{Path, PathBuf};

use common::{assert_success, run_hexy, temp_dir, write_file};
use hexy_core::{
    HexFile, IntelHexWriteOptions, Segment, decode_hex_text, parse_intel_hex, write_intel_hex,
};

/// HexView's `/DP33` output text for `rsa_his_private.txt` over [`input`].
const RSA_METADATA: &str = "a699f342ff9fccb1d2874797cb78b069a535ecc983fcca83cd317640fa7ab725f7d0d9423f9aae0d44434e22c8589ea8a073038ea46094da2a7a07570e7c7fcc4d12974f94a1fcfd4c0e8535a2701476aabae9868948f91248b99f9ebf74b59f1577f394e9652626e2e0a41db94b03ea0b694c8dd83e966243137633ecfe2c78";
/// HexView's `/DP32` signature.
const RSA_DATA: &str = "41350b17ea084b17eaaa4296a855b28bd6361c70a6996ea4e8e61ae113f4e93580446fca0b2ec193ff7cdea4e7e8d2ce4743e171cdf1ba077e0a8c9d78884bcdf6270926b7a364e0a4a1611eeeb9babad060ba1133c9cba837db7eccba0851d9638d2fcdb4b09c31bdce3ecb1c9ea29d8b4b8f27f4e7b80521b16accd1669ac6";

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../hexy-core/tests/fixtures/keys/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(path).unwrap()
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add((i * 7) as u8)).collect()
}

/// `in.hex` in a new folder, holding the image the pinned signatures cover.
fn input(prefix: &str) -> (PathBuf, PathBuf) {
    let dir = temp_dir(prefix);
    let image = HexFile::with_segments(vec![
        Segment::new(0x1000, pattern(0x30, 1)).unwrap(),
        Segment::new(0x2000, pattern(0x10, 2)).unwrap(),
    ]);
    let input = dir.join("in.hex");
    write_file(
        &input,
        &write_intel_hex(&image, &IntelHexWriteOptions::default()).unwrap(),
    );
    (dir, input)
}

/// `/DP` output text as HexView writes it.
fn output_text(hex: &str) -> String {
    let bytes = decode_hex_text(hex.as_bytes()).unwrap();
    let items: Vec<String> = bytes.iter().map(|b| format!("0x{b:02X}")).collect();
    items.join(" ,")
}

fn run(input: &Path, flags: &[&str]) -> std::process::Output {
    let mut args = vec![input.display().to_string()];
    args.extend(flags.iter().map(|flag| (*flag).to_owned()));
    run_hexy(&args)
}

/// Relative key paths and the default output file resolve against the input folder.
#[test]
fn test_dp_resolves_files_against_input_folder() {
    let (dir, input) = input("dp_relative");
    std::fs::create_dir(dir.join("keys")).unwrap();
    write_file(&dir.join("keys/rsa.txt"), &fixture("rsa_his_private.txt"));

    assert_success(&run(&input, &["/DP33:keys/rsa.txt"]));
    let text = std::fs::read_to_string(dir.join("SignDAL_SHA256.RSA")).unwrap();
    assert_eq!(text, output_text(RSA_METADATA));
}

/// `file,section,key` reads the key from an INI file; `/SV` reads the `/DP` output.
#[test]
fn test_dp_ini_key_and_sv_of_dp_output() {
    let (dir, input) = input("dp_ini");
    let key = String::from_utf8(fixture("rsa_his_private.txt")).unwrap();
    write_file(
        &dir.join("keys.ini"),
        format!("[Keys]\r\nPrivate='{key}'\r\n").as_bytes(),
    );
    write_file(&dir.join("pub.txt"), &fixture("rsa_his_public.txt"));

    assert_success(&run(
        &input,
        &[
            "/SV4:pub.txt!sig.txt",
            "/DP32:keys.ini,keys,private;sig.txt",
        ],
    ));
    let text = std::fs::read_to_string(dir.join("sig.txt")).unwrap();
    assert_eq!(text, output_text(RSA_DATA));
}

/// `/SV` runs after `/DP` places its output, and neither failure stops the export.
#[test]
fn test_sv_sees_placed_output_and_failures_still_export() {
    let (dir, input) = input("dp_place_sv");
    write_file(&dir.join("rsa.txt"), &fixture("rsa_his_private.txt"));
    write_file(&dir.join("pub.txt"), &fixture("rsa_his_public.txt"));
    let out = dir.join("out.hex");
    let out_arg = out.display().to_string();

    let sv = format!("/SV4:pub.txt!{RSA_DATA}");
    let output = run(
        &input,
        &["/DP32:@append:rsa.txt", &sv, "/XI", "-o", &out_arg],
    );
    assert!(!output.status.success());
    let image = parse_intel_hex(&std::fs::read(&out).unwrap()).unwrap();
    let signature = decode_hex_text(RSA_DATA.as_bytes()).unwrap();
    assert_eq!(image.read_bytes_contiguous(0x2010, 128), Some(signature));
    assert!(dir.join("SignD_SHA256.RSA").exists());

    for dp in ["/DP32:missing.pem", "/DP99:rsa.txt", "/DP32"] {
        std::fs::remove_file(&out).unwrap();
        let output = run(&input, &[dp, "/XI", "-o", &out_arg]);
        assert!(!output.status.success(), "{dp}");
        assert!(out.exists(), "{dp}");
    }
}

#[test]
fn test_unimplemented_methods_rejected_before_outputs() {
    let (dir, input) = input("dp_unsupported");
    let out = dir.join("out.hex");
    let out_arg = out.display().to_string();
    for flag in [
        "/DP2:00112233445566778899AABBCCDDEEFF",
        "/SV0:pub.txt!00",
        "/DP38:k.pem#SALT=00",
    ] {
        let output = run(&input, &[flag, "/XI", "-o", &out_arg]);
        assert!(!output.status.success(), "{flag}");
        assert!(!out.exists(), "{flag}");
    }
}

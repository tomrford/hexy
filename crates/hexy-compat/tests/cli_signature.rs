mod common;

use common::{assert_success, run_hexy, temp_dir, write_file};
use ed25519_dalek::SigningKey as EdSigningKey;
use ed25519_dalek::pkcs8::{
    EncodePrivateKey as EdEncodePrivateKey, EncodePublicKey as EdEncodePublicKey,
};
use hexy_core::parse_intel_hex;
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};

fn write_rsa_keys(dir: &std::path::Path, prefix: &str) -> (std::path::PathBuf, std::path::PathBuf) {
    let mut rng = OsRng;
    let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public = RsaPublicKey::from(&private);
    let private_path = dir.join(format!("{prefix}_private.der"));
    let public_path = dir.join(format!("{prefix}_public.der"));
    let private_der = private.to_pkcs8_der().unwrap();
    let public_der = public.to_public_key_der().unwrap();
    write_file(&private_path, private_der.as_bytes());
    write_file(&public_path, public_der.as_bytes());
    (private_path, public_path)
}

fn write_ed25519_keys(
    dir: &std::path::Path,
    prefix: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let secret = [0x42u8; 32];
    let signing = EdSigningKey::from_bytes(&secret);
    let verifying = signing.verifying_key();
    let private_path = dir.join(format!("{prefix}_private.der"));
    let public_path = dir.join(format!("{prefix}_public.der"));
    let private_der = signing.to_pkcs8_der().unwrap();
    let public_der = verifying.to_public_key_der().unwrap();
    write_file(&private_path, private_der.as_bytes());
    write_file(&public_path, public_der.as_bytes());
    (private_path, public_path)
}

#[test]
fn test_cli_dp_sv_rsa_pkcs1_success() {
    let dir = temp_dir("cli_sig_rsa_ok");
    let input_path = dir.join("input.bin");
    let sig_path = dir.join("sig.bin");
    write_file(&input_path, b"hello-signature");
    let (private_path, public_path) = write_rsa_keys(&dir, "rsa_ok");

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        format!("/DP32:{};{}", private_path.display(), sig_path.display()),
        format!("/SV4:{}!{}", public_path.display(), sig_path.display()),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let signature = std::fs::read(&sig_path).unwrap();
    assert_eq!(signature.len(), 256);
}

#[test]
fn test_cli_sv_fails_with_wrong_key() {
    let dir = temp_dir("cli_sig_rsa_fail");
    let input_path = dir.join("input.bin");
    let sig_path = dir.join("sig.bin");
    write_file(&input_path, b"hello-signature");
    let (private_path, _) = write_rsa_keys(&dir, "rsa_sign");
    let (_, wrong_public_path) = write_rsa_keys(&dir, "rsa_wrong");

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        format!("/DP32:{};{}", private_path.display(), sig_path.display()),
        format!(
            "/SV4:{}!{}",
            wrong_public_path.display(),
            sig_path.display()
        ),
    ];
    let output = run_hexy(&args);
    assert!(!output.status.success());
}

#[test]
fn test_cli_dp_sv_ed25519_success() {
    let dir = temp_dir("cli_sig_ed_ok");
    let input_path = dir.join("input.bin");
    let sig_path = dir.join("sig.bin");
    write_file(&input_path, b"ed25519");
    let (private_path, public_path) = write_ed25519_keys(&dir, "ed_ok");

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        format!("/DP46:{};{}", private_path.display(), sig_path.display()),
        format!("/SV8:{}!{}", public_path.display(), sig_path.display()),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let signature = std::fs::read(&sig_path).unwrap();
    assert_eq!(signature.len(), 64);
}

#[test]
fn test_cli_dp_placement_append_writes_signature_to_data() {
    let dir = temp_dir("cli_sig_dp_place");
    let input_path = dir.join("input.bin");
    let out_hex = dir.join("out.hex");
    write_file(&input_path, &[0x10, 0x20, 0x30, 0x40]);
    let (private_path, _) = write_ed25519_keys(&dir, "ed_place");

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        format!("/DP46:@append:{}", private_path.display()),
        "/XI".to_string(),
        "-o".to_string(),
        out_hex.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let encoded = std::fs::read(&out_hex).unwrap();
    let parsed = parse_intel_hex(&encoded).unwrap();
    let normalized = parsed.normalized();
    let bytes = normalized.read_bytes_contiguous(0x1000, 4 + 64).unwrap();
    assert_eq!(&bytes[..4], &[0x10, 0x20, 0x30, 0x40]);
}

fn assert_dp_placement_empty_input_noop(target: &str) {
    let dir = temp_dir("cli_sig_dp_place_empty");
    let input_path = dir.join("input.bin");
    let sig_path = dir.join("sig.bin");
    let out_hex = dir.join("out.hex");
    write_file(&input_path, &[]);
    let (private_path, _) = write_ed25519_keys(&dir, "ed_place_empty");

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        format!(
            "/DP46:{target}:{};{}",
            private_path.display(),
            sig_path.display()
        ),
        "/XI".to_string(),
        "-o".to_string(),
        out_hex.display().to_string(),
    ];
    let output = run_hexy(&args);
    assert_success(&output);

    let signature = std::fs::read(&sig_path).unwrap();
    assert_eq!(signature.len(), 64);

    let encoded = std::fs::read(&out_hex).unwrap();
    let parsed = parse_intel_hex(&encoded).unwrap();
    assert!(parsed.normalized().segments().is_empty());
}

#[test]
fn test_cli_dp_placement_append_on_empty_input_is_noop() {
    assert_dp_placement_empty_input_noop("@append");
}

#[test]
fn test_cli_dp_placement_upfront_on_empty_input_is_noop() {
    assert_dp_placement_empty_input_noop("@upfront");
}

#[test]
fn test_cli_dp_placement_end_on_empty_input_is_noop() {
    assert_dp_placement_empty_input_noop("@end");
}

#[test]
fn test_cli_dp_missing_windows_style_key_path_is_file_error() {
    let dir = temp_dir("cli_sig_missing_key");
    let input_path = dir.join("input.bin");
    write_file(&input_path, b"hello-signature");

    let args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        "/DP32:C:\\temp\\missing-private-key.pem".to_string(),
    ];
    let output = run_hexy(&args);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No such file or directory") || stderr.contains("os error 2"));
}

#[test]
fn test_cli_sv_missing_windows_style_signature_path_is_file_error() {
    let dir = temp_dir("cli_sig_missing_sig");
    let input_path = dir.join("input.bin");
    write_file(&input_path, b"hello-signature");
    let (private_path, public_path) = write_rsa_keys(&dir, "rsa_missing_sig");
    let sig_path = dir.join("sig.bin");

    let sign_args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        format!("/DP32:{};{}", private_path.display(), sig_path.display()),
    ];
    let sign_output = run_hexy(&sign_args);
    assert_success(&sign_output);

    let verify_args = vec![
        format!("/IN:{};0x1000", input_path.display()),
        format!(
            "/SV4:{}!C:\\temp\\missing-signature.bin",
            public_path.display()
        ),
    ];
    let verify_output = run_hexy(&verify_args);
    assert!(!verify_output.status.success());
    let stderr = String::from_utf8_lossy(&verify_output.stderr);
    assert!(stderr.contains("No such file or directory") || stderr.contains("os error 2"));
}

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey as EdSigningKey;
use ed25519_dalek::pkcs8::{
    EncodePrivateKey as EdEncodePrivateKey, EncodePublicKey as EdEncodePublicKey,
};
use hexy_core::{
    HexFile, Segment, SignatureBytesSource, SignatureKeySource, SignatureMethod,
    SignaturePlacement, SignatureSignOptions, SignatureVerifyOptions,
};
use rsa::rand_core::OsRng;
use rsa::{RsaPrivateKey, RsaPublicKey};

static UNIQUE_ID: AtomicU64 = AtomicU64::new(0);

fn rsa_keypair() -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let private = RsaPrivateKey::new(&mut rng, 2048).unwrap();
    let public = RsaPublicKey::from(&private);
    let private_der = private.to_pkcs8_der().unwrap();
    let public_der = public.to_public_key_der().unwrap();
    (
        private_der.as_bytes().to_vec(),
        public_der.as_bytes().to_vec(),
    )
}

fn ed25519_keypair() -> (Vec<u8>, Vec<u8>) {
    let secret = [0x42u8; 32];
    let signing = EdSigningKey::from_bytes(&secret);
    let verifying = signing.verifying_key();
    let private_der = signing.to_pkcs8_der().unwrap();
    let public_der = verifying.to_public_key_der().unwrap();
    (
        private_der.as_bytes().to_vec(),
        public_der.as_bytes().to_vec(),
    )
}

fn temp_dir(name: &str) -> PathBuf {
    let id = UNIQUE_ID.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "hexy-core-signature-{name}-{}-{id}",
        std::process::id()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[test]
fn test_sign_and_verify_rsa_pkcs1() {
    let (private_key, public_key) = rsa_keypair();
    let mut hexfile = HexFile::with_segments(vec![Segment::new(0x1000, b"hello-signature".into())]);
    let sign = SignatureSignOptions {
        method: SignatureMethod::RsaPkcs1v15Sha256 {
            with_metadata: false,
        },
        key_source: SignatureKeySource::Bytes(&private_key),
        placement: None,
    };
    let signature = hexfile.sign(&sign).unwrap();
    assert_eq!(signature.len(), 256);

    let verify = SignatureVerifyOptions {
        method: SignatureMethod::RsaPkcs1v15Sha256 {
            with_metadata: false,
        },
        key_source: SignatureKeySource::Bytes(&public_key),
        signature_source: SignatureBytesSource::Bytes(&signature),
    };
    hexfile.verify_signature(&verify).unwrap();
}

#[test]
fn test_sign_and_verify_ed25519() {
    let (private_key, public_key) = ed25519_keypair();
    let mut hexfile = HexFile::with_segments(vec![Segment::new(0x1000, b"ed25519".into())]);
    let sign = SignatureSignOptions {
        method: SignatureMethod::Ed25519Ph {
            with_metadata: false,
        },
        key_source: SignatureKeySource::Bytes(&private_key),
        placement: None,
    };
    let signature = hexfile.sign(&sign).unwrap();
    assert_eq!(signature.len(), 64);

    let verify = SignatureVerifyOptions {
        method: SignatureMethod::Ed25519Ph {
            with_metadata: false,
        },
        key_source: SignatureKeySource::Bytes(&public_key),
        signature_source: SignatureBytesSource::Bytes(&signature),
    };
    hexfile.verify_signature(&verify).unwrap();
}

#[test]
fn test_sign_append_places_signature_in_data() {
    let (private_key, _) = ed25519_keypair();
    let mut hexfile =
        HexFile::with_segments(vec![Segment::new(0x1000, vec![0x10, 0x20, 0x30, 0x40])]);
    let sign = SignatureSignOptions {
        method: SignatureMethod::Ed25519Ph {
            with_metadata: false,
        },
        key_source: SignatureKeySource::Bytes(&private_key),
        placement: Some(SignaturePlacement::Append),
    };
    let signature = hexfile.sign(&sign).unwrap();

    let normalized = hexfile.normalized();
    let bytes = normalized
        .read_bytes_contiguous(0x1000, 4 + signature.len())
        .unwrap();
    assert_eq!(&bytes[..4], &[0x10, 0x20, 0x30, 0x40]);
    assert_eq!(&bytes[4..], signature.as_slice());
}

#[test]
fn test_sign_append_on_empty_input_is_noop() {
    let (private_key, _) = ed25519_keypair();
    let mut hexfile = HexFile::new();
    let sign = SignatureSignOptions {
        method: SignatureMethod::Ed25519Ph {
            with_metadata: false,
        },
        key_source: SignatureKeySource::Bytes(&private_key),
        placement: Some(SignaturePlacement::Append),
    };
    let signature = hexfile.sign(&sign).unwrap();

    assert_eq!(signature.len(), 64);
    assert!(hexfile.normalized().segments().is_empty());
}

#[test]
fn test_sign_and_verify_with_auto_file_and_hex_sources() {
    let dir = temp_dir("auto");
    let (private_key, public_key) = rsa_keypair();
    let private_path = dir.join("rsa_private.der");
    let public_path = dir.join("rsa_public.der");
    std::fs::write(&private_path, &private_key).unwrap();
    std::fs::write(&public_path, &public_key).unwrap();
    let private_source = private_path.display().to_string();
    let public_source = public_path.display().to_string();

    let mut hexfile = HexFile::with_segments(vec![Segment::new(0x1000, b"auto-sources".into())]);
    let sign = SignatureSignOptions {
        method: SignatureMethod::RsaPkcs1v15Sha256 {
            with_metadata: false,
        },
        key_source: SignatureKeySource::Auto(&private_source),
        placement: None,
    };
    let signature = hexfile.sign(&sign).unwrap();
    let signature_hex = hex_encode(&signature);

    let verify = SignatureVerifyOptions {
        method: SignatureMethod::RsaPkcs1v15Sha256 {
            with_metadata: false,
        },
        key_source: SignatureKeySource::Auto(&public_source),
        signature_source: SignatureBytesSource::Auto(&signature_hex),
    };
    hexfile.verify_signature(&verify).unwrap();
}

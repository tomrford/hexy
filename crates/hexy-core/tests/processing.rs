#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

//! Signatures pinned to HexView 1.15.2 output: `/DP32`, `/DP33`, `/DP46` and `/DP47`
//! over [`image`] with the keys in `tests/fixtures/keys`.

use hexy_core::{
    DataProcessing, HexFile, Placement, ProcessingError, Segment, SignatureMethod, SignatureScheme,
};

const RSA_DATA: &str = "41350b17ea084b17eaaa4296a855b28bd6361c70a6996ea4e8e61ae113f4e93580446fca0b2ec193ff7cdea4e7e8d2ce4743e171cdf1ba077e0a8c9d78884bcdf6270926b7a364e0a4a1611eeeb9babad060ba1133c9cba837db7eccba0851d9638d2fcdb4b09c31bdce3ecb1c9ea29d8b4b8f27f4e7b80521b16accd1669ac6";
const RSA_METADATA: &str = "a699f342ff9fccb1d2874797cb78b069a535ecc983fcca83cd317640fa7ab725f7d0d9423f9aae0d44434e22c8589ea8a073038ea46094da2a7a07570e7c7fcc4d12974f94a1fcfd4c0e8535a2701476aabae9868948f91248b99f9ebf74b59f1577f394e9652626e2e0a41db94b03ea0b694c8dd83e966243137633ecfe2c78";
const ED25519PH_DATA: &str = "2e69c17677e0d935fb9174bfe70081fb7c0ec3f861ee538aebb077587ab11ed656e118ad3a209fe51d9e0d4f581d516e4b9d636982c8cd3abfb6a67098e9b505";
const ED25519PH_METADATA: &str = "662deb899d97fe479bbee0ea568f43ccbf1ec99b09a7972c468f6a5d3e30b7817b730c7afb02f0f008922d79a54fb5559fd970d823c8d603a80929b67ed0770f";

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add((i * 7) as u8)).collect()
}

fn image() -> HexFile {
    HexFile::with_segments(vec![
        Segment::new(0x1000, pattern(0x30, 1)).unwrap(),
        Segment::new(0x2000, pattern(0x10, 2)).unwrap(),
    ])
}

fn key(name: &str) -> Vec<u8> {
    let path = format!("{}/tests/fixtures/keys/{name}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(path).unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    hexy_core::decode_hex_text(text.as_bytes()).unwrap()
}

fn method(scheme: SignatureScheme, with_metadata: bool) -> SignatureMethod {
    SignatureMethod {
        scheme,
        with_metadata,
    }
}

fn sign(method: SignatureMethod, key_file: &str) -> Result<Vec<u8>, ProcessingError> {
    let key = method.scheme.signing_key(&key(key_file))?;
    let output = image().process_data(&DataProcessing::Sign { method, key }, None)?;
    Ok(output.unwrap())
}

/// Every key format HexView reads gives HexView's signature.
#[test]
fn test_signatures_match_hexview() {
    let cases = [
        (
            SignatureScheme::RsaPkcs1v15Sha256,
            "rsa_his_private.txt",
            RSA_DATA,
            RSA_METADATA,
        ),
        (
            SignatureScheme::RsaPkcs1v15Sha256,
            "rsa_pkcs8.pem",
            RSA_DATA,
            RSA_METADATA,
        ),
        (
            SignatureScheme::RsaPkcs1v15Sha256,
            "rsa_pkcs1.txt",
            RSA_DATA,
            RSA_METADATA,
        ),
        (
            SignatureScheme::Ed25519Ph,
            "ed25519_seed.txt",
            ED25519PH_DATA,
            ED25519PH_METADATA,
        ),
        (
            SignatureScheme::Ed25519Ph,
            "ed25519_hexview.pem",
            ED25519PH_DATA,
            ED25519PH_METADATA,
        ),
    ];
    for (scheme, key_file, data, metadata) in cases {
        assert_eq!(
            sign(method(scheme, false), key_file).unwrap(),
            hex(data),
            "{key_file}"
        );
        assert_eq!(
            sign(method(scheme, true), key_file).unwrap(),
            hex(metadata),
            "{key_file}"
        );
    }
}

#[test]
fn test_verifies_hexview_signatures() {
    let cases = [
        (
            SignatureScheme::RsaPkcs1v15Sha256,
            "rsa_his_public.txt",
            RSA_METADATA,
        ),
        (
            SignatureScheme::RsaPkcs1v15Sha256,
            "rsa_his_private.txt",
            RSA_METADATA,
        ),
        (
            SignatureScheme::RsaPkcs1v15Sha256,
            "rsa_spki.txt",
            RSA_METADATA,
        ),
        (
            SignatureScheme::RsaPkcs1v15Sha256,
            "rsa_pkcs8.pem",
            RSA_METADATA,
        ),
        (
            SignatureScheme::Ed25519Ph,
            "ed25519_public.txt",
            ED25519PH_METADATA,
        ),
        (
            SignatureScheme::Ed25519Ph,
            "ed25519_hexview.pem",
            ED25519PH_METADATA,
        ),
    ];
    for (scheme, key_file, signature) in cases {
        let key = scheme.verifying_key(&key(key_file)).unwrap();
        let method = method(scheme, true);
        image()
            .verify_signature(method, &key, &hex(signature))
            .unwrap_or_else(|e| panic!("{key_file}: {e}"));
        let mut tampered = hex(signature);
        tampered[0] ^= 1;
        assert!(matches!(
            image().verify_signature(method, &key, &tampered),
            Err(ProcessingError::VerificationFailed)
        ));
    }
}

/// HexView rejects a HIS public key (`7F49`) for signing.
#[test]
fn test_signing_rejects_public_his_key() {
    let method = method(SignatureScheme::RsaPkcs1v15Sha256, false);
    assert!(matches!(
        sign(method, "rsa_his_public.txt"),
        Err(ProcessingError::InvalidKey(_))
    ));
}

#[test]
fn test_placement_writes_output_into_image() {
    let method = method(SignatureScheme::Ed25519Ph, false);
    let key = method.scheme.signing_key(&key("ed25519_seed.txt")).unwrap();
    let mut hexfile = image();
    let output = hexfile
        .process_data(
            &DataProcessing::Sign { method, key },
            Some(Placement::Append),
        )
        .unwrap()
        .unwrap();
    assert_eq!(output, hex(ED25519PH_DATA));
    assert_eq!(
        hexfile.read_bytes_contiguous(0x2010, output.len()),
        Some(output)
    );
}

#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

//! Data processing pinned to HexView 1.15.2 output over [`image`] with the keys in
//! `tests/fixtures/keys`.

use hexy_core::{
    DataProcessing, HexFile, Placement, ProcessingError, RsaPadding, RsaPrivateKey, RsaPublicKey,
    Segment, SignatureMethod, SignatureScheme,
};

const RSA_DATA: &str = "41350b17ea084b17eaaa4296a855b28bd6361c70a6996ea4e8e61ae113f4e93580446fca0b2ec193ff7cdea4e7e8d2ce4743e171cdf1ba077e0a8c9d78884bcdf6270926b7a364e0a4a1611eeeb9babad060ba1133c9cba837db7eccba0851d9638d2fcdb4b09c31bdce3ecb1c9ea29d8b4b8f27f4e7b80521b16accd1669ac6";
const RSA_METADATA: &str = "a699f342ff9fccb1d2874797cb78b069a535ecc983fcca83cd317640fa7ab725f7d0d9423f9aae0d44434e22c8589ea8a073038ea46094da2a7a07570e7c7fcc4d12974f94a1fcfd4c0e8535a2701476aabae9868948f91248b99f9ebf74b59f1577f394e9652626e2e0a41db94b03ea0b694c8dd83e966243137633ecfe2c78";
/// `/DP28`, `/DP9`, `/DP10` and `/DP15`.
const RSA_RIPEMD160_DATA: &str = "a3c8321352a6ef684dd5bc0362113222ab140d3c5c308bab14e886512050c7d2fa385bf30d33d2249068a4d386698601ed5b83586461ee17caa0323c0dc9b4f6c57586bb621438210cf951279b5e28b740b74f6b5be10b74b0b45d32526660b8c3ab638f5cbbfb5f30401133ae24e062e54c0b2a2752ac91f2308b9fe2f5471f";
const RSA_RIPEMD160_METADATA: &str = "b5156a1017cb30298947ef0a6fa283af3827f14be7ff30c5d59eca841d17773cf98b3cc0ac65b9ba8f5b69bbb4b302514c5f4abda2a72793ca007fd99705381834f89097cc04563cd56e5cb443787cd4e3425333dba68851e231da732cd6d55316ffc5481230f2ae49af10cc8d1683e01d10e211a4529679e3d0ed6c15c2e280";
const RSA_SHA1_METADATA: &str = "17b36b616653289e290fac5ca252131621479ae8c45194c6414e07c3d30cc3bfd31be2fb8873533eecbd6f1b774b1195bfc03cccbe715c3ea512e6f2dd7e7c522cc89965f02cda3371e3f77665fa033312a7f303281a8bf11e750438b97bb7428671d5c86b832a1069398a9640de255f8ae5f34e003d0086f0b53c55bff1b6fa";
const RSA_MD5_DATA: &str = "b77ea3626513a7fe65bb6e220a00fa76989c06eedb663bdbec174867415809f912986b3f921bd1165069bd8545a88fc311fce47377630dc9b5ce62ef2a48ffbfd8f0a7eacbacabbb104a797cbe5669631420136c5d7c2b5a830ad3af361454e45eb17ec7514e260ae35d4902b5a2a5d93174485c92661b72560bb5f23661ab40";
/// `/DP38:...#SALT=0102030405`.
const RSA_PSS_SALT_DATA: &str = "3691474c28b262479c3c5caf207dbcba11e84a76f40a52d6734250738b25dc41b9d65d1464255adf684f0d16b87408d05216b4972d9ff766ac39c2d6b98b81dea02293ef316049275831c1d1531f95a88d82de0d5c0ed2167a9f090b413abd634588bf7d01ac0db404ee0dfc15460a6d2a65637f14cb55c150149851ec2d8a74";
const ED25519PH_DATA: &str = "2e69c17677e0d935fb9174bfe70081fb7c0ec3f861ee538aebb077587ab11ed656e118ad3a209fe51d9e0d4f581d516e4b9d636982c8cd3abfb6a67098e9b505";
const ED25519PH_METADATA: &str = "662deb899d97fe479bbee0ea568f43ccbf1ec99b09a7972c468f6a5d3e30b7817b730c7afb02f0f008922d79a54fb5559fd970d823c8d603a80929b67ed0770f";
/// `/DP48` and `/DP49`.
const ED25519PH_SHA512_DATA: &str = "4461b57de6c357df54473f1f4452915195a15746d51d7fd50c9026324a8054f05c19908d10f27b19da77586d7a5af299e2bf1ed9e9fb6230d7d7cee17368e506";
const ED25519PH_SHA512_METADATA: &str = "430f9c3685b5f72ff62d6d3326d19af2735e118d3e8b40ac0591d5ced7702f3a0be6c2d48547b0cfd92c1420cd0824d8bf0a78eacb429adbf72cb11d622de903";
/// `/DP52` over the first block of [`image`].
const ED25519_FIRST_BLOCK: &str = "3f3a9c269b127cabe2edb3118a43d0e3890a0577b452ce04d0c4dcbe93dc691430b6e29d21d6ba43904228de54c218cf1005a72a863d65c51da8cf6ac7fe2f04";
/// `/DP50` and `/DP51`: HexView signs with the same nonce every time.
const P256_DATA: &str = "c912e18658b5e0501952f3ee09c5fd1ca282085b04924ab0b6f67e011bcf3d078ba3ae25cc71f49e98f5a7106140bfe1e408517573807090bb3be966427b53f3";
const P256_METADATA: &str = "c912e18658b5e0501952f3ee09c5fd1ca282085b04924ab0b6f67e011bcf3d0782f3de727791833e5698b3a467f958f0ff92bf13c139055574bf1136617bc3e0";

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| seed.wrapping_add((i * 7) as u8)).collect()
}

fn image() -> HexFile {
    HexFile::with_segments(vec![
        Segment::new(0x1000, pattern(0x30, 1)).unwrap(),
        Segment::new(0x2000, pattern(0x10, 2)).unwrap(),
    ])
}

fn single_block(data: Vec<u8>) -> HexFile {
    HexFile::with_segments(vec![Segment::new(0x1000, data).unwrap()])
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

fn sign_with(
    mut hexfile: HexFile,
    method: SignatureMethod,
    key_file: &str,
    salt: Option<Vec<u8>>,
) -> Result<Vec<u8>, ProcessingError> {
    let key = method.scheme.signing_key(&key(key_file))?;
    let output = hexfile.process_data(&DataProcessing::Sign { method, key, salt }, None)?;
    Ok(output.unwrap())
}

fn sign(method: SignatureMethod, key_file: &str) -> Result<Vec<u8>, ProcessingError> {
    sign_with(image(), method, key_file, None)
}

/// Every key format HexView reads gives HexView's signature.
#[test]
fn test_signatures_match_hexview() {
    use SignatureScheme::{
        Ed25519Ph, Ed25519PhSha512, RsaPkcs1v15Md5, RsaPkcs1v15Ripemd160, RsaPkcs1v15Sha1,
        RsaPkcs1v15Sha256,
    };
    let cases = [
        (RsaPkcs1v15Sha256, false, "rsa_his_private.txt", RSA_DATA),
        (RsaPkcs1v15Sha256, true, "rsa_his_private.txt", RSA_METADATA),
        (RsaPkcs1v15Sha256, false, "rsa_pkcs8.pem", RSA_DATA),
        (RsaPkcs1v15Sha256, true, "rsa_pkcs1.txt", RSA_METADATA),
        (
            RsaPkcs1v15Ripemd160,
            false,
            "rsa_pkcs1.txt",
            RSA_RIPEMD160_DATA,
        ),
        (
            RsaPkcs1v15Ripemd160,
            true,
            "rsa_pkcs1.txt",
            RSA_RIPEMD160_METADATA,
        ),
        (RsaPkcs1v15Sha1, true, "rsa_pkcs1.txt", RSA_SHA1_METADATA),
        (RsaPkcs1v15Md5, false, "rsa_pkcs1.txt", RSA_MD5_DATA),
        (Ed25519Ph, false, "ed25519_seed.txt", ED25519PH_DATA),
        (Ed25519Ph, true, "ed25519_hexview.pem", ED25519PH_METADATA),
        (
            Ed25519PhSha512,
            false,
            "ed25519_seed.txt",
            ED25519PH_SHA512_DATA,
        ),
        (
            Ed25519PhSha512,
            true,
            "ed25519_hexview.pem",
            ED25519PH_SHA512_METADATA,
        ),
    ];
    for (scheme, with_metadata, key_file, expected) in cases {
        assert_eq!(
            sign(method(scheme, with_metadata), key_file).unwrap(),
            hex(expected),
            "{scheme:?} {with_metadata} {key_file}"
        );
    }
}

/// `/DP38` with `#SALT` uses it as the PSS salt.
#[test]
fn test_rsa_pss_salt_matches_hexview() {
    let method = method(SignatureScheme::RsaPssSha256, false);
    let salt = Some(hex("0102030405"));
    assert_eq!(
        sign_with(image(), method, "rsa_pkcs8.pem", salt).unwrap(),
        hex(RSA_PSS_SALT_DATA)
    );
    let ed25519 = self::method(SignatureScheme::Ed25519Ph, false);
    assert!(matches!(
        sign_with(image(), ed25519, "ed25519_seed.txt", Some(vec![1])),
        Err(ProcessingError::UnusedSalt(_))
    ));
}

/// `/DP52` signs a single block without pre-hash and fails on more blocks.
#[test]
fn test_ed25519_signs_a_single_block() {
    let method = method(SignatureScheme::Ed25519, false);
    assert_eq!(
        sign_with(
            single_block(pattern(0x30, 1)),
            method,
            "ed25519_seed.txt",
            None
        )
        .unwrap(),
        hex(ED25519_FIRST_BLOCK)
    );
    assert!(matches!(
        sign(method, "ed25519_seed.txt"),
        Err(ProcessingError::MultipleBlocks(2))
    ));
}

#[test]
fn test_verifies_hexview_signatures() {
    use SignatureScheme::{
        EcdsaP256Sha256, Ed25519Ph, Ed25519PhSha512, RsaPkcs1v15Sha1, RsaPkcs1v15Sha256,
        RsaPssSha256,
    };
    let cases = [
        (RsaPkcs1v15Sha256, true, "rsa_his_public.txt", RSA_METADATA),
        (RsaPkcs1v15Sha256, true, "rsa_his_private.txt", RSA_METADATA),
        (RsaPkcs1v15Sha256, true, "rsa_spki.txt", RSA_METADATA),
        (RsaPkcs1v15Sha256, true, "rsa_pkcs8.pem", RSA_METADATA),
        (
            RsaPkcs1v15Sha1,
            true,
            "rsa_his_public.txt",
            RSA_SHA1_METADATA,
        ),
        (RsaPssSha256, false, "rsa_his_public.txt", RSA_PSS_SALT_DATA),
        (Ed25519Ph, true, "ed25519_public.txt", ED25519PH_METADATA),
        (Ed25519Ph, true, "ed25519_hexview.pem", ED25519PH_METADATA),
        (
            Ed25519PhSha512,
            true,
            "ed25519_public.txt",
            ED25519PH_SHA512_METADATA,
        ),
        (EcdsaP256Sha256, false, "p256_sec1.pem", P256_DATA),
        (EcdsaP256Sha256, true, "p256_sec1.pem", P256_METADATA),
    ];
    for (scheme, with_metadata, key_file, signature) in cases {
        let key = scheme.verifying_key(&key(key_file)).unwrap();
        let method = method(scheme, with_metadata);
        image()
            .verify_signature(method, &key, &hex(signature))
            .unwrap_or_else(|e| panic!("{scheme:?} {key_file}: {e}"));
        let mut tampered = hex(signature);
        tampered[1] ^= 1;
        assert!(matches!(
            image().verify_signature(method, &key, &tampered),
            Err(ProcessingError::VerificationFailed)
        ));
    }
}

/// hexy's ECDSA signatures are deterministic (RFC 6979), not HexView's fixed nonce, so
/// they are checked by verification.
#[test]
fn test_p256_signatures_verify() {
    let method = method(SignatureScheme::EcdsaP256Sha256, true);
    let signature = sign(method, "p256_sec1.pem").unwrap();
    assert_eq!(signature.len(), 64);
    assert_eq!(sign(method, "p256_sec1.pem").unwrap(), signature);
    let key = method.scheme.verifying_key(&key("p256_sec1.pem")).unwrap();
    image().verify_signature(method, &key, &signature).unwrap();
}

/// HexView's `/DP18` unpads PKCS #1 v1.5, decrypts other single key lengths without
/// padding, and `/DP43` removes OAEP SHA-256 padding.
#[test]
fn test_rsa_decryption_matches_hexview() {
    const PKCS1: &str = "65516cdd56811d7e544e4b30c2f7879370c3cf0f600ca843cada086e1000d768090a4b0984860ccb86837a75cb0d38bf4dc76b0e58860505fb7023377770fb36babd1a498bb7167e9827c7116e0e15305068e4efb6a028222de916181ed8c0df999fb5bc09a4ae04b1c5d831f3a9244fb3102008ee33f12f871e6b0803d87309";
    const OAEP_SHA256: &str = "6a220a83fa912ac1c82a94a22cbe3e5917a4abcc716ca6aa87ee756d7e417b26cb41623cf88d1022ef7d50bc5606f274548e880fcebf5bc2d5e7f8eedf9e1120cb56f17c9272d369df8609b7fa78c77f9b24933d87b4e90707c099f0c077448d0bd837d7ea484afbb938adfcf8c486b24230ed5cb0b48984e98c57c2a8943c25";
    const OAEP_SHA256_RAW: &str = "00e93aab0650d630961d4094cef6d8e1ba807dce0e1de3860da70213ae2abd3e63031ed46d5f97d183bd9b973b15a53410c8f53a22cea18d73c4cd260c29f44aa5bf73a47a95481f6e217edfa1980e4eb86f47c23a11dfca4dd19d255565c36b8e82fdd392323651320219e86233d8bc5fd00c6b5d3f31ba09f1eec83551ad85";
    let key = RsaPrivateKey::from_key_file(&key("rsa_pkcs8.pem")).unwrap();
    for (ciphertext, padding, expected) in [
        (PKCS1, RsaPadding::Pkcs1v15, pattern(0x20, 1)),
        (OAEP_SHA256, RsaPadding::OaepSha256, pattern(0x20, 1)),
        (OAEP_SHA256, RsaPadding::Pkcs1v15, hex(OAEP_SHA256_RAW)),
    ] {
        let mut hexfile = single_block(hex(ciphertext));
        let decrypt = DataProcessing::RsaDecrypt {
            key: key.clone(),
            padding,
        };
        hexfile.process_data(&decrypt, None).unwrap();
        assert_eq!(hexfile.blocks()[0].data(), expected, "{padding:?}");
    }
    let decrypt = DataProcessing::RsaDecrypt {
        key,
        padding: RsaPadding::OaepSha256,
    };
    assert!(matches!(
        single_block(hex(&PKCS1[2..])).process_data(&decrypt, None),
        Err(ProcessingError::RsaDataLength(128))
    ));
}

/// Each block is encrypted on its own: padded, or without padding when it is a whole
/// number of key lengths.
#[test]
fn test_rsa_encryption_round_trips_per_block() {
    let public = RsaPublicKey::from_key_file(&key("rsa_his_public.txt")).unwrap();
    let private = RsaPrivateKey::from_key_file(&key("rsa_pkcs8.pem")).unwrap();
    for padding in [
        RsaPadding::Pkcs1v15,
        RsaPadding::OaepSha1,
        RsaPadding::OaepSha256,
    ] {
        let mut hexfile = image();
        let encrypt = DataProcessing::RsaEncrypt {
            key: public.clone(),
            padding,
        };
        hexfile.process_data(&encrypt, None).unwrap();
        let lengths: Vec<usize> = hexfile.blocks().iter().map(|b| b.len()).collect();
        assert_eq!(lengths, [128, 128], "{padding:?}");
        let decrypt = DataProcessing::RsaDecrypt {
            key: private.clone(),
            padding,
        };
        hexfile.process_data(&decrypt, None).unwrap();
        assert_eq!(hexfile.blocks(), image().blocks(), "{padding:?}");
    }
    let mut raw = single_block(pattern(0x100, 1));
    let encrypt = DataProcessing::RsaEncrypt {
        key: public,
        padding: RsaPadding::Pkcs1v15,
    };
    raw.process_data(&encrypt, None).unwrap();
    let decrypt = DataProcessing::RsaDecrypt {
        key: private,
        padding: RsaPadding::Pkcs1v15,
    };
    raw.process_data(&decrypt, None).unwrap();
    assert_eq!(raw.blocks()[0].data(), pattern(0x100, 1));
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
fn test_empty_ed25519_key_material_is_rejected() {
    for scheme in [SignatureScheme::Ed25519Ph, SignatureScheme::Ed25519PhSha512] {
        for content in [b"".as_slice(), b" \r\n,", b"0x"] {
            assert!(matches!(
                scheme.signing_key(content),
                Err(ProcessingError::InvalidKey(_))
            ));
            assert!(matches!(
                scheme.verifying_key(content),
                Err(ProcessingError::InvalidKey(_))
            ));
        }
        // A deliberately supplied short seed still takes the documented zero padding.
        let method = method(scheme, false);
        let short = scheme.signing_key(b"00").unwrap();
        let full = scheme.signing_key("00".repeat(32).as_bytes()).unwrap();
        assert_eq!(
            image()
                .process_data(&DataProcessing::Sign { method, key: short, salt: None }, None)
                .unwrap(),
            image()
                .process_data(&DataProcessing::Sign { method, key: full, salt: None }, None)
                .unwrap()
        );
    }
}

#[test]
fn test_placement_writes_output_into_image() {
    let method = method(SignatureScheme::Ed25519Ph, false);
    let key = method.scheme.signing_key(&key("ed25519_seed.txt")).unwrap();
    let mut hexfile = image();
    let output = hexfile
        .process_data(
            &DataProcessing::Sign {
                method,
                key,
                salt: None,
            },
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

#[test]
fn test_invalid_his_zero_modulus_returns_error() {
    let key = hex("FF490A81008203010001910101");
    assert!(matches!(
        RsaPrivateKey::from_his_bytes(&key),
        Err(ProcessingError::InvalidKey(_))
    ));
}

#[test]
fn test_invalid_his_zero_private_exponent_returns_error() {
    assert!(matches!(
        RsaPrivateKey::from_key_file(b"FF490C810301080782030100019100"),
        Err(ProcessingError::InvalidKey(_))
    ));
}

#[test]
fn test_invalid_pss_key_size_returns_error_without_changing_image() {
    // This valid 512-bit key cannot fit SHA-256 and PSS's 32-byte salt.
    let method = method(SignatureScheme::RsaPssSha256, false);
    let key = method.scheme.signing_key(&key("rsa_512_test.pem")).unwrap();
    let mut image = image();
    let original = image.clone();

    assert!(matches!(
        image.process_data(
            &DataProcessing::Sign { method, key, salt: None },
            Some(Placement::Append)
        ),
        Err(ProcessingError::Crypto(_))
    ));
    assert_eq!(image, original);
}

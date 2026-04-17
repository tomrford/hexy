use super::super::types::ChecksumTarget;
use super::*;

#[test]
fn test_output_record_type_requires_length() {
    let mut args = Args::default();
    let result = parse_option(&mut args, "XS::2");
    assert!(result.is_err());
}

#[test]
fn test_parse_ad_no_separator_hex() {
    let mut args = Args::default();
    parse_option(&mut args, "AD10").unwrap();
    assert_eq!(args.align_address, Some(0x10));
}

#[test]
fn test_parse_af_no_separator_hex() {
    let mut args = Args::default();
    parse_option(&mut args, "AF0A").unwrap();
    assert_eq!(args.align_fill, 0x0A);
}

#[test]
fn test_parse_checksum_without_target_defaults_append() {
    let mut args = Args::default();
    parse_option(&mut args, "CS0").unwrap();
    let checksum = args.checksum.expect("checksum parsed");
    assert_eq!(checksum.algorithm, 0);
    assert!(matches!(checksum.target, ChecksumTarget::Append));
}

#[test]
fn test_parse_checksum_reverse_without_target_defaults_append() {
    let mut args = Args::default();
    parse_option(&mut args, "CSR9").unwrap();
    let checksum = args.checksum.expect("checksum parsed");
    assert_eq!(checksum.algorithm, 9);
    assert!(checksum.little_endian);
    assert!(matches!(checksum.target, ChecksumTarget::Append));
}

#[test]
fn test_parse_dp_signature_subset_option() {
    let mut args = Args::default();
    parse_option(&mut args, "DP32:@append:key.pem;sig.bin").unwrap();
    let dp = args.data_processing.expect("data processing parsed");
    assert_eq!(dp.method, 32);
    assert!(matches!(dp.placement, Some(ChecksumTarget::Append)));
    assert_eq!(dp.key_info, "key.pem");
}

#[test]
fn test_parse_sv_option() {
    let mut args = Args::default();
    parse_option(&mut args, "SV4:pub.pem!sig.bin").unwrap();
    let sv = args
        .signature_verify
        .expect("signature verification parsed");
    assert_eq!(sv.method, 4);
    assert_eq!(sv.key_info, "pub.pem");
    assert_eq!(sv.signature_info, "sig.bin");
}

#[test]
fn test_parse_unsupported_output_option_rejected() {
    let mut args = Args::default();
    let err = parse_option(&mut args, "XV").unwrap_err();
    assert_eq!(err.to_string(), "invalid option: /XV not yet implemented");
}

#[test]
fn test_parse_checksum_multi_repeated() {
    let mut args = Args::default();
    parse_option(&mut args, "CSM0:@append").unwrap();
    parse_option(&mut args, "CSMR9:@0x1000").unwrap();
    assert_eq!(args.checksum_multi.len(), 2);
    assert!(matches!(
        args.checksum_multi[0].target,
        ChecksumTarget::Append
    ));
    assert!(args.checksum_multi[1].little_endian);
    assert!(matches!(
        args.checksum_multi[1].target,
        ChecksumTarget::Address(0x1000)
    ));
}

#[test]
fn test_parse_checksum_multi_without_target_defaults_append() {
    let mut args = Args::default();
    parse_option(&mut args, "CSM9").unwrap();
    assert_eq!(args.checksum_multi.len(), 1);
    assert_eq!(args.checksum_multi[0].algorithm, 9);
    assert!(matches!(
        args.checksum_multi[0].target,
        ChecksumTarget::Append
    ));
}

#[test]
fn test_parse_checksum_mixed_legacy_then_multi_rejected() {
    let mut args = Args::default();
    parse_option(&mut args, "CS0:@append").unwrap();
    assert!(parse_option(&mut args, "CSM0:@append").is_err());
}

#[test]
fn test_parse_checksum_mixed_multi_then_legacy_rejected() {
    let mut args = Args::default();
    parse_option(&mut args, "CSM0:@append").unwrap();
    assert!(parse_option(&mut args, "CS0:@append").is_err());
}

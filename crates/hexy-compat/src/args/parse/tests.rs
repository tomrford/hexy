use super::super::types::ChecksumTarget;
use super::*;

#[test]
fn test_output_record_type_requires_length() {
    let mut args = Args::default();
    let result = parse_option(&mut args, "XI::2");
    assert!(result.is_err());

    let mut args = Args::default();
    parse_option(&mut args, "XS::3").unwrap();
    assert!(matches!(
        args.output_format,
        Some(OutputFormat::SRecord {
            record_type: Some(3)
        })
    ));
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
fn test_parse_checksum_without_target_defaults_none() {
    let mut args = Args::default();
    parse_option(&mut args, "CS0").unwrap();
    let checksum = args.checksum.expect("checksum parsed");
    assert_eq!(checksum.algorithm, 0);
    assert!(matches!(checksum.target, ChecksumTarget::None));
}

#[test]
fn test_parse_checksum_reverse_without_target_defaults_none() {
    let mut args = Args::default();
    parse_option(&mut args, "CSR9").unwrap();
    let checksum = args.checksum.expect("checksum parsed");
    assert_eq!(checksum.algorithm, 9);
    assert!(checksum.little_endian);
    assert!(matches!(checksum.target, ChecksumTarget::None));
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
fn test_parse_i16_option_with_windows_absolute_path() {
    let mut args = Args::default();
    parse_option(&mut args, r"II2=C:\temp\input.hex").unwrap();
    assert_eq!(args.import_i16, Some(PathBuf::from(r"C:\temp\input.hex")));
}

#[test]
fn test_parse_in_option_with_windows_absolute_path() {
    let mut args = Args::default();
    parse_option(&mut args, r"IN:C:\temp\input.bin;0x1000").unwrap();
    let import = args.import_binary.expect("binary import parsed");
    assert_eq!(import.file, PathBuf::from(r"C:\temp\input.bin"));
    assert_eq!(import.offset, 0x1000);
}

#[test]
fn test_parse_ia_option_with_windows_drive_and_forward_slashes() {
    let mut args = Args::default();
    parse_option(&mut args, "IA:C:/temp/input.txt;0x1000").unwrap();
    let import = args.import_hex_ascii.expect("hex ascii import parsed");
    assert_eq!(import.file, PathBuf::from("C:/temp/input.txt"));
    assert_eq!(import.offset, 0x1000);
}

#[test]
fn test_parse_mt_option_with_windows_absolute_path_and_range() {
    let mut args = Args::default();
    parse_option(&mut args, r"MT:C:\temp\merge.hex;0x1000:0x0,0x4").unwrap();
    assert_eq!(args.merge_transparent.len(), 1);
    let merge = &args.merge_transparent[0];
    assert_eq!(merge.file, PathBuf::from(r"C:\temp\merge.hex"));
    assert_eq!(merge.offset, Some(0x1000));
    assert_eq!(
        merge.range,
        Some(AddressRange::from_start_length(0x0, 0x4).unwrap())
    );
}

#[test]
fn test_parse_error_log_option_with_windows_absolute_path() {
    let mut args = Args::default();
    parse_option(&mut args, r"E=C:\temp\error.log").unwrap();
    assert_eq!(args.error_log, Some(PathBuf::from(r"C:\temp\error.log")));
}

#[test]
fn test_parse_log_file_option_with_windows_absolute_path() {
    let mut args = Args::default();
    parse_option(&mut args, r"L:C:\temp\commands.log").unwrap();
    assert_eq!(args.log_file, Some(PathBuf::from(r"C:\temp\commands.log")));
}

#[test]
fn test_parse_ini_file_option_with_windows_absolute_path() {
    let mut args = Args::default();
    parse_option(&mut args, r"P:C:\temp\hexy.ini").unwrap();
    assert_eq!(args.ini_file, Some(PathBuf::from(r"C:\temp\hexy.ini")));
}

#[test]
fn test_parse_postbuild_option_with_windows_absolute_path() {
    let mut args = Args::default();
    parse_option(&mut args, r"PB:C:\temp\postbuild.bat").unwrap();
    assert_eq!(
        args.postbuild,
        Some(PathBuf::from(r"C:\temp\postbuild.bat"))
    );
}

#[test]
fn test_parse_checksum_file_target_with_windows_absolute_path() {
    let mut args = Args::default();
    parse_option(&mut args, r"CS0:C:\temp\checksum.bin").unwrap();
    let checksum = args.checksum.expect("checksum parsed");
    assert!(matches!(
        checksum.target,
        ChecksumTarget::File(ref path) if path == &PathBuf::from(r"C:\temp\checksum.bin")
    ));
}

#[test]
fn test_parse_data_processing_paths_with_windows_absolute_paths() {
    let mut args = Args::default();
    parse_option(&mut args, r"DP32:C:\temp\key.pem;D:\temp\sig.bin").unwrap();
    let dp = args.data_processing.expect("data processing parsed");
    assert_eq!(dp.key_info, r"C:\temp\key.pem");
    assert_eq!(dp.output_file, Some(PathBuf::from(r"D:\temp\sig.bin")));
}

#[test]
fn test_parse_signature_verify_paths_with_windows_absolute_paths() {
    let mut args = Args::default();
    parse_option(&mut args, r"SV4:C:\temp\pub.pem!D:\temp\sig.bin").unwrap();
    let sv = args
        .signature_verify
        .expect("signature verification parsed");
    assert_eq!(sv.key_info, r"C:\temp\pub.pem");
    assert_eq!(sv.signature_info, r"D:\temp\sig.bin");
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
fn test_parse_checksum_multi_without_target_defaults_none() {
    let mut args = Args::default();
    parse_option(&mut args, "CSM9").unwrap();
    assert_eq!(args.checksum_multi.len(), 1);
    assert_eq!(args.checksum_multi[0].algorithm, 9);
    assert!(matches!(
        args.checksum_multi[0].target,
        ChecksumTarget::None
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

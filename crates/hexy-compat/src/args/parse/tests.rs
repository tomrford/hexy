use super::super::processing::ParamSource;
use super::super::types::ChecksumTarget;
use super::*;
use crate::{AddressRange, MergeMode, Placement};
use std::path::PathBuf;

use super::super::types::ImportKind;

/// HexView 1.15.2 reads /Xx parameters as lenient integers, falls back to auto record
/// selection for unknown types and lets the last /Xx flag win.
#[test]
fn test_output_params_follow_hexview() {
    let mut args = Args::default();
    for opt in ["XI:16:1", "XS:10h:3"] {
        parse_option(&mut args, opt).unwrap();
    }
    let Some(OutputFormat::SRecord(options)) = args.output_format.take() else {
        panic!("last /Xx flag wins");
    };
    assert_eq!(options.bytes_per_line, 10);
    assert_eq!(options.record_type, None);

    parse_option(&mut args, "XI::x").unwrap();
    let Some(OutputFormat::IntelHex(options)) = args.output_format else {
        panic!("/XI parsed");
    };
    assert_eq!(options.bytes_per_line, 32);
    assert_eq!(options.mode, crate::IntelHexMode::Auto);
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

/// HexView 1.15.2 keeps the intersection of the valid /AR ranges, skips empty and
/// overflowing ranges, stops reading at a reversed range, and applies the last /AR.
#[test]
fn test_parse_ar_matches_hexview() -> Result<(), Box<dyn std::error::Error>> {
    let ar = |value: &str| {
        let mut args = Args::default();
        parse_option(&mut args, &format!("AR:{value}")).map(|_| args.address_range)
    };
    assert_eq!(
        ar("0x1000-0x1007:0x1004-0x100B")?,
        Some(vec![AddressRange::from_start_end(0x1004, 0x1007)?])
    );
    assert_eq!(ar("0x1000,0x8:0x2000,0x4")?, Some(vec![]));
    assert_eq!(
        ar("0xFFFFFFF0,0x20:0x1000-0x1007:")?,
        Some(vec![AddressRange::from_start_end(0x1000, 0x1007)?])
    );
    assert_eq!(ar("0x1000,0:0x1008-0x1007:0x1000-0x1007")?, None);
    assert_eq!(ar("x")?, None);
    assert_eq!(ar("0x1000é")?, None);

    let mut args = Args::default();
    parse_option(&mut args, "AR:0x1000,0x2")?;
    parse_option(&mut args, "AR:0x2000,0x2")?;
    assert_eq!(
        args.address_range,
        Some(vec![AddressRange::from_start_length(0x2000, 0x2)?])
    );
    Ok(())
}

#[test]
fn test_parse_i16_option_with_windows_absolute_path() {
    let mut args = Args::default();
    parse_option(&mut args, r"II2=C:\temp\input.hex").unwrap();
    let import = args.import.expect("16-bit import parsed");
    assert_eq!(import.kind, ImportKind::IntelHex16);
    assert_eq!(import.file, PathBuf::from(r"C:\temp\input.hex"));
}

#[test]
fn test_parse_in_option_with_windows_absolute_path() {
    let mut args = Args::default();
    parse_option(&mut args, r"IN:C:\temp\input.bin;0x1000").unwrap();
    let import = args.import.expect("binary import parsed");
    assert_eq!(import.kind, ImportKind::Binary);
    assert_eq!(import.file, PathBuf::from(r"C:\temp\input.bin"));
    assert_eq!(import.offset, 0x1000);
}

#[test]
fn test_parse_ia_option_with_windows_drive_and_forward_slashes() {
    let mut args = Args::default();
    parse_option(&mut args, "IA:C:/temp/input.txt;0x1000").unwrap();
    let import = args.import.expect("hex ascii import parsed");
    assert_eq!(import.kind, ImportKind::HexAscii);
    assert_eq!(import.file, PathBuf::from("C:/temp/input.txt"));
    assert_eq!(import.offset, 0x1000);
}

#[test]
fn test_parse_mt_option_with_windows_absolute_path_and_range() {
    let mut args = Args::default();
    parse_option(&mut args, r"MT:C:\temp\merge.hex;0x1000:0x0,0x4").unwrap();
    let spec = args.merge.expect("merge parsed");
    assert_eq!(spec.mode, MergeMode::Preserve);
    let merge = &spec.files[0];
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
fn test_parse_dp_and_sv_windows_absolute_paths() {
    let mut args = Args::default();
    parse_option(&mut args, r"DP32:@append:C:\temp\key.pem;D:\temp\sig.bin").unwrap();
    parse_option(&mut args, r"SV4:C:\temp\pub.pem!D:\temp\sig.bin").unwrap();
    let dp = args.data_processing.expect("data processing parsed");
    assert_eq!(dp.method, 32);
    assert_eq!(dp.placement, Some(Placement::Append));
    assert_eq!(
        dp.source,
        ParamSource::File(PathBuf::from(r"C:\temp\key.pem"))
    );
    assert_eq!(dp.param4.as_deref(), Some(r"D:\temp\sig.bin"));
    let sv = args
        .signature_verify
        .expect("signature verification parsed");
    assert_eq!(sv.method, 4);
    assert_eq!(sv.key, ParamSource::File(PathBuf::from(r"C:\temp\pub.pem")));
    assert_eq!(sv.signature.as_deref(), Some(r"D:\temp\sig.bin"));
}

/// Options HexView knows but hexy does not reproduce are rejected; options HexView
/// does not know are left to the caller to report.
#[test]
fn test_parse_unsupported_and_unknown_options() {
    let mut args = Args::default();
    for option in [
        "XV",
        "XGC:0x1000",
        "XGC_APP_SIGN",
        "PB:x.xml",
        "expdat:x.dll",
    ] {
        assert!(parse_option(&mut args, option).is_err(), "{option}");
    }
    for option in ["FOO", "RB:8", "S08", "CSX9:c.txt", "tms570-ECC"] {
        assert!(!parse_option(&mut args, option).unwrap(), "{option}");
    }
    assert!(parse_option(&mut args, "XGACSWIL").unwrap());
}

/// HexView 1.15.2 uses the last /IN, /IA or /II2, and only the last /MO or /MT.
#[test]
fn test_parse_last_import_and_merge_win() {
    let mut args = Args::default();
    for option in ["IN:b.bin;0x10", "IA:a.asc;-0x10", "MO:a.hex", "MT:b.hex"] {
        parse_option(&mut args, option).unwrap();
    }
    let import = args.import.expect("import parsed");
    assert_eq!(import.kind, ImportKind::HexAscii);
    assert_eq!(import.offset, 0xFFFF_FFF0);
    let merge = args.merge.expect("merge parsed");
    assert_eq!(merge.mode, MergeMode::Preserve);
    assert_eq!(merge.files.len(), 1);
}

/// HexView 1.15.2 ignores /CR= and /FR=, reads /FP like HEX ASCII data and ignores
/// `,target` after a /CDSPX range.
#[test]
fn test_parse_range_options_match_hexview() {
    let mut args = Args::default();
    for option in [
        "CR=0x1000,4",
        "FR=0x1000,4",
        "FP:0xABC",
        "CDSPX:0x1000,8,0x6000",
    ] {
        parse_option(&mut args, option).unwrap();
    }
    assert!(args.cut_ranges.is_empty());
    assert!(args.fill_ranges.is_empty());
    assert_eq!(args.fill_pattern, Some(vec![0xAB, 0x0C]));
    assert_eq!(args.dspic_expand.len(), 1);
    assert_eq!(args.dspic_expand[0].target, None);
    parse_option(&mut args, "FP:XYZ").unwrap();
    assert_eq!(args.fill_pattern, None);
}

#[test]
fn test_parse_checksum_multi_repeated() {
    let mut args = Args::default();
    parse_option(&mut args, "CSM0:@append").unwrap();
    parse_option(&mut args, "CSMR9:@0x1000").unwrap();
    assert_eq!(args.checksum_multi.len(), 2);
    assert!(matches!(
        args.checksum_multi[0].target,
        ChecksumTarget::Place(Placement::Append)
    ));
    assert!(args.checksum_multi[1].little_endian);
    assert!(matches!(
        args.checksum_multi[1].target,
        ChecksumTarget::Place(Placement::Address(0x1000))
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

use std::path::PathBuf;

use crate::AddressRange;

use super::types::{
    ChecksumParams, ChecksumTarget, DataProcessingParams, DspicOp, ForcedRange, ImportParam,
    MergeParam, ParseArgError, RemapParams, SignatureVerifyParams,
};

pub(super) fn split_option(opt: &str) -> Option<(&str, &str)> {
    match (opt.find(':'), opt.find('=')) {
        (Some(colon), Some(equal)) if colon < equal => Some((&opt[..colon], &opt[colon + 1..])),
        (Some(_), Some(equal)) => Some((&opt[..equal], &opt[equal + 1..])),
        (Some(colon), None) => Some((&opt[..colon], &opt[colon + 1..])),
        (None, Some(equal)) => Some((&opt[..equal], &opt[equal + 1..])),
        (None, None) => None,
    }
}

pub(super) fn strip_quotes(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

pub(super) fn parse_compat_ranges(s: &str) -> Result<Vec<AddressRange>, ParseArgError> {
    crate::parse_compat_ranges(s).map_err(|e| ParseArgError::InvalidRange(e.to_string()))
}

fn parse_single_compat_range(s: &str, context: &str) -> Result<AddressRange, ParseArgError> {
    let ranges = parse_compat_ranges(s)?;
    match ranges.as_slice() {
        [range] => Ok(*range),
        [] => Err(ParseArgError::InvalidRange(s.to_owned())),
        _ => Err(ParseArgError::InvalidOption(format!(
            "{context} requires exactly one range"
        ))),
    }
}

pub(super) fn parse_hex_bytes(s: &str) -> Result<Vec<u8>, ParseArgError> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err(ParseArgError::InvalidNumber(format!(
            "odd-length hex string: {s}"
        )));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| ParseArgError::InvalidNumber(s[i..i + 2].to_string()))
        })
        .collect()
}

pub(super) fn parse_number(s: &str) -> Result<u32, ParseArgError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ParseArgError::InvalidNumber("empty".to_owned()));
    }

    let s = s.trim_end_matches(['u', 'U', 'l', 'L']).trim();
    if s.is_empty() {
        return Err(ParseArgError::InvalidNumber("empty".to_owned()));
    }

    let (radix, digits) = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (16, hex)
    } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        (2, bin)
    } else if let Some(bin) = s.strip_suffix('b').or_else(|| s.strip_suffix('B')) {
        (2, bin)
    } else if let Some(hex) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        (16, hex)
    } else if s.chars().all(|c| c.is_ascii_hexdigit()) && s.chars().any(|c| c.is_ascii_alphabetic())
    {
        (16, s)
    } else {
        (10, s)
    };

    let cleaned: String = digits.chars().filter(|c| *c != '.' && *c != '_').collect();
    if cleaned.is_empty() {
        return Err(ParseArgError::InvalidNumber("empty".to_owned()));
    }

    u32::from_str_radix(&cleaned, radix).map_err(|e| ParseArgError::InvalidNumber(e.to_string()))
}

pub(super) fn parse_signed_number(s: &str) -> Result<i64, ParseArgError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(ParseArgError::InvalidNumber("empty".to_owned()));
    }
    let (sign, digits) = if let Some(rest) = s.strip_prefix('-') {
        (-1i64, rest)
    } else {
        (1i64, s)
    };
    let value = parse_number(digits)? as i64;
    Ok(sign * value)
}

pub(super) fn parse_merge_param(s: &str) -> Result<MergeParam, ParseArgError> {
    let s = strip_quotes(s);
    let (file_and_offset, range) = split_merge_range(s)?;

    let (file, offset) = if let Some((file, offset_str)) = file_and_offset.split_once(';') {
        let offset = parse_signed_number(offset_str)?;
        (file, Some(offset))
    } else {
        (file_and_offset, None)
    };

    Ok(MergeParam {
        file: PathBuf::from(file),
        offset,
        range,
    })
}

pub(super) fn parse_merge_params(value: &str) -> Result<Vec<MergeParam>, ParseArgError> {
    let mut params = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;

    for ch in value.chars() {
        match ch {
            '\'' if !in_double => {
                in_single = !in_single;
                current.push(ch);
            }
            '"' if !in_single => {
                in_double = !in_double;
                current.push(ch);
            }
            '+' if !in_single && !in_double => {
                if !current.trim().is_empty() {
                    params.push(parse_merge_param(current.trim())?);
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        params.push(parse_merge_param(current.trim())?);
    }

    Ok(params)
}

fn split_merge_range(s: &str) -> Result<(&str, Option<AddressRange>), ParseArgError> {
    let Some(colon_pos) = s.rfind(':') else {
        return Ok((s, None));
    };
    let left = &s[..colon_pos];
    let right = &s[colon_pos + 1..];

    match parse_single_compat_range(right, "merge range") {
        Ok(range) => Ok((left, Some(range))),
        Err(err) if merge_range_delimiter_is_unambiguous(s, colon_pos) => Err(err),
        Err(_) => Ok((s, None)),
    }
}

fn merge_range_delimiter_is_unambiguous(s: &str, colon_pos: usize) -> bool {
    if let Some(semicolon_pos) = s.rfind(';') {
        return colon_pos > semicolon_pos;
    }

    !looks_like_windows_drive_colon(s, colon_pos)
}

fn looks_like_windows_drive_colon(s: &str, colon_pos: usize) -> bool {
    colon_pos == 1 && s.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
}

pub(super) fn parse_import_param(value: &str) -> Result<ImportParam, ParseArgError> {
    let value = strip_quotes(value);
    let (file, offset) = if let Some((file, offset_str)) = value.split_once(';') {
        (file, parse_number(offset_str)?)
    } else {
        (value, 0)
    };

    Ok(ImportParam {
        file: PathBuf::from(file),
        offset,
    })
}

pub(super) fn parse_remap(s: &str) -> Result<RemapParams, ParseArgError> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 4 {
        return Err(ParseArgError::InvalidOption(format!(
            "remap requires 4 parameters: {s}"
        )));
    }

    let (start_str, end_str) = parts[0].split_once('-').ok_or_else(|| {
        ParseArgError::InvalidOption(format!("remap range invalid: {}", parts[0]))
    })?;

    Ok(RemapParams {
        start: parse_number(start_str)?,
        end: parse_number(end_str)?,
        linear: parse_number(parts[1])?,
        size: parse_number(parts[2])?,
        inc: parse_number(parts[3])?,
    })
}

pub(super) fn parse_checksum(
    algo: &str,
    target: &str,
    little_endian: bool,
) -> Result<ChecksumParams, ParseArgError> {
    let algorithm = if algo.is_empty() {
        0
    } else {
        algo.parse::<u8>()
            .map_err(|_| ParseArgError::InvalidNumber(algo.to_owned()))?
    };

    let mut parts = target.split(';');
    let target_str = parts.next().unwrap_or_default();
    let mut range = None;
    let mut forced_range = None;
    let mut exclude_ranges = Vec::new();

    for part in parts {
        if part.is_empty() {
            continue;
        }
        if let Some(forced) = part.strip_prefix('!') {
            if forced_range.is_some() {
                return Err(ParseArgError::InvalidOption(
                    "multiple forced ranges".to_owned(),
                ));
            }
            let (range_str, pattern_str) = if let Some((r, p)) = forced.split_once('#') {
                (r, Some(p))
            } else {
                (forced, None)
            };
            let range = parse_single_compat_range(range_str, "forced checksum range")?;
            let pattern = if let Some(pattern_str) = pattern_str {
                let pattern_str = pattern_str.trim();
                let pattern_str = pattern_str
                    .strip_prefix("0x")
                    .or_else(|| pattern_str.strip_prefix("0X"))
                    .unwrap_or(pattern_str);
                if pattern_str.is_empty() {
                    vec![0xFF]
                } else {
                    parse_hex_bytes(pattern_str)?
                }
            } else {
                vec![0xFF]
            };
            forced_range = Some(ForcedRange { range, pattern });
            continue;
        }

        if range.is_some() {
            return Err(ParseArgError::InvalidOption(
                "multiple checksum ranges".to_owned(),
            ));
        }

        let mut pieces = part.split('/');
        let range_part = pieces.next().unwrap_or_default();
        if !range_part.is_empty() {
            range = Some(parse_single_compat_range(range_part, "checksum range")?);
        }
        for exclude in pieces {
            if exclude.is_empty() {
                continue;
            }
            let ranges = parse_compat_ranges(exclude)?;
            exclude_ranges.extend(ranges);
        }
    }

    let target = if target_str.is_empty() {
        ChecksumTarget::None
    } else if let Some(stripped) = target_str.strip_prefix('@') {
        parse_placement_target(stripped)?
    } else {
        ChecksumTarget::File(PathBuf::from(target_str))
    };

    Ok(ChecksumParams {
        algorithm,
        target,
        little_endian,
        range,
        forced_range,
        exclude_ranges,
    })
}

fn parse_placement_target(target: &str) -> Result<ChecksumTarget, ParseArgError> {
    let target_upper = target.to_ascii_uppercase();
    match target_upper.as_str() {
        "APPEND" => Ok(ChecksumTarget::Append),
        "BEGIN" => Ok(ChecksumTarget::Begin),
        "UPFRONT" => Ok(ChecksumTarget::Prepend),
        "PREPEND" => Ok(ChecksumTarget::Address(0)),
        "END" => Ok(ChecksumTarget::OverwriteEnd),
        _ => Ok(ChecksumTarget::Address(parse_number(target)?)),
    }
}

pub(super) fn parse_data_processing_params(
    method: u8,
    value: &str,
) -> Result<DataProcessingParams, ParseArgError> {
    let (params_part, output_file) = if let Some((left, right)) = value.split_once(';') {
        let output = strip_quotes(right).trim();
        let output_file = if output.is_empty() {
            None
        } else {
            Some(PathBuf::from(output))
        };
        (left, output_file)
    } else {
        (value, None)
    };

    let (placement, key_and_meta) = if let Some(rest) = params_part.strip_prefix('@') {
        let (placement_raw, right) = rest.split_once(':').ok_or_else(|| {
            ParseArgError::InvalidOption("data processing placement missing ':'".to_owned())
        })?;
        (Some(parse_placement_target(placement_raw)?), right)
    } else {
        (None, params_part)
    };

    let key_info = strip_quotes(key_and_meta)
        .split(',')
        .next()
        .map(str::trim)
        .unwrap_or_default()
        .to_owned();
    if key_info.is_empty() {
        return Err(ParseArgError::MissingValue(format!("/DP{method} keyinfo")));
    }

    Ok(DataProcessingParams {
        method,
        placement,
        key_info,
        output_file,
    })
}

pub(super) fn parse_signature_verify_params(
    method: u8,
    value: &str,
) -> Result<SignatureVerifyParams, ParseArgError> {
    let (key_raw, signature_raw) = value.split_once('!').ok_or_else(|| {
        ParseArgError::InvalidOption("signature verification requires keyinfo!signatureinfo".into())
    })?;
    let key_info = strip_quotes(key_raw).trim().to_owned();
    let signature_info = strip_quotes(signature_raw).trim().to_owned();
    if key_info.is_empty() {
        return Err(ParseArgError::MissingValue(format!("/SV{method} keyinfo")));
    }
    if signature_info.is_empty() {
        return Err(ParseArgError::MissingValue(format!(
            "/SV{method} signatureinfo"
        )));
    }
    Ok(SignatureVerifyParams {
        method,
        key_info,
        signature_info,
    })
}

pub(super) fn parse_dspic_op(s: &str) -> Result<DspicOp, ParseArgError> {
    let s = strip_quotes(s);
    if let Some((range_str, target_str)) = s.split_once(';').or_else(|| s.rsplit_once(':')) {
        let target = parse_number(target_str)?;
        Ok(DspicOp {
            range: parse_single_compat_range(range_str, "dsPIC range")?,
            target: Some(target),
        })
    } else {
        Ok(DspicOp {
            range: parse_single_compat_range(s, "dsPIC range")?,
            target: None,
        })
    }
}

pub(super) fn parse_output_params(s: &str) -> Result<(Option<u8>, Option<u8>), ParseArgError> {
    if s.is_empty() {
        return Ok((None, None));
    }

    let parts: Vec<&str> = s.split(':').collect();
    let len = if let Some(part) = parts.first().copied() {
        if part.is_empty() {
            None
        } else {
            let value = parse_number(part)?;
            if value > u8::MAX as u32 {
                return Err(ParseArgError::InvalidNumber(part.to_owned()));
            }
            Some(value as u8)
        }
    } else {
        None
    };

    let rec_type = if let Some(part) = parts.get(1).copied() {
        if part.is_empty() {
            None
        } else {
            let value = parse_number(part)?;
            if value > u8::MAX as u32 {
                return Err(ParseArgError::InvalidNumber(part.to_owned()));
            }
            Some(value as u8)
        }
    } else {
        None
    };

    Ok((len, rec_type))
}

pub(super) fn parse_hex_ascii_params(
    value: &str,
) -> Result<(Option<u32>, Option<String>), ParseArgError> {
    if value.is_empty() {
        return Ok((None, None));
    }

    let mut parts = value.splitn(2, ':');
    let len_part = parts.next().unwrap_or_default();
    let sep_part = parts.next();

    let line_length = if len_part.is_empty() {
        None
    } else {
        Some(parse_number(len_part)?)
    };

    let separator = sep_part.map(|s| strip_quotes(s).to_owned());

    Ok((line_length, separator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_signed_number_negative_hex() {
        assert_eq!(parse_signed_number("-0x10").unwrap(), -16);
        assert_eq!(parse_signed_number("0x10").unwrap(), 16);
    }

    #[test]
    fn test_parse_number_with_dots() {
        assert_eq!(parse_number("0x10.0F").unwrap(), 0x100F);
        assert_eq!(parse_number("1.024").unwrap(), 1024);
    }

    #[test]
    fn test_parse_number_with_hex_suffix() {
        assert_eq!(parse_number("10h").unwrap(), 0x10);
        assert_eq!(parse_number("0fH").unwrap(), 0x0F);
    }

    #[test]
    fn test_parse_number_with_c_suffixes() {
        assert_eq!(parse_number("0x10u").unwrap(), 0x10);
        assert_eq!(parse_number("0x10UL").unwrap(), 0x10);
        assert_eq!(parse_number("255u").unwrap(), 255);
    }

    #[test]
    fn test_parse_merge_params_with_range() {
        let params = parse_merge_params("cal1.hex;-0x10:0x1000-0x10FF+cal2.s19;128").unwrap();
        assert_eq!(params.len(), 2);
        assert_eq!(params[0].offset, Some(-0x10));
        assert!(params[0].range.is_some());
        assert_eq!(params[1].offset, Some(128));
    }

    #[test]
    fn test_split_option_prefers_earliest_separator() {
        let (key, value) = split_option(r"II2=C:\temp\input.hex").unwrap();
        assert_eq!(key, "II2");
        assert_eq!(value, r"C:\temp\input.hex");
    }

    #[test]
    fn test_parse_merge_params_windows_path_with_range() {
        let params = parse_merge_params(r"C:\temp\merge.hex:0x1000-0x10FF").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].file, PathBuf::from(r"C:\temp\merge.hex"));
        assert_eq!(
            params[0].range,
            Some(AddressRange::from_start_end(0x1000, 0x10FF).unwrap())
        );
    }

    #[test]
    fn test_parse_merge_params_windows_path_with_offset_and_range() {
        let params = parse_merge_params(r"C:\temp\merge.hex;0x1000:0x0,0x4").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].file, PathBuf::from(r"C:\temp\merge.hex"));
        assert_eq!(params[0].offset, Some(0x1000));
        assert_eq!(
            params[0].range,
            Some(AddressRange::from_start_length(0x0, 0x4).unwrap())
        );
    }

    #[test]
    fn test_parse_merge_params_windows_path_with_dash_and_offset() {
        let params = parse_merge_params(r"C:\temp\foo-bar.hex;0x0").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].file, PathBuf::from(r"C:\temp\foo-bar.hex"));
        assert_eq!(params[0].offset, Some(0));
        assert_eq!(params[0].range, None);
    }

    #[test]
    fn test_parse_merge_params_windows_forward_slash_path_with_dash_and_offset() {
        let params = parse_merge_params("C:/temp/foo-bar.hex;0x0").unwrap();
        assert_eq!(params.len(), 1);
        assert_eq!(params[0].file, PathBuf::from("C:/temp/foo-bar.hex"));
        assert_eq!(params[0].offset, Some(0));
        assert_eq!(params[0].range, None);
    }

    #[test]
    fn test_parse_import_param_with_offset() {
        let param = parse_import_param("file.bin;0x1000").unwrap();
        assert_eq!(param.offset, 0x1000);
    }

    #[test]
    fn test_parse_import_param_invalid_offset() {
        let result = parse_import_param("file.bin;0xZZ");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_merge_params_invalid_range() {
        let result = parse_merge_params("file.hex:0x2000-0x1000");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_output_params_hex() {
        let (len, rec_type) = parse_output_params("0x20:0x2").unwrap();
        assert_eq!(len, Some(32));
        assert_eq!(rec_type, Some(2));
    }

    #[test]
    fn test_parse_checksum_forced_range_with_pattern() {
        let params = parse_checksum("0", "@append;!0x1000-0x1003#AABB", false).unwrap();
        assert!(params.forced_range.is_some());
        let forced = params.forced_range.unwrap();
        assert_eq!(forced.range.start(), 0x1000);
        assert_eq!(forced.range.end(), 0x1003);
        assert_eq!(forced.pattern, vec![0xAA, 0xBB]);
        assert!(params.range.is_none());
    }

    #[test]
    fn test_parse_checksum_exclude_ranges() {
        let params = parse_checksum("0", "@append;0x1000-0x1003/0x1001-0x1001", false).unwrap();
        assert!(params.range.is_some());
        assert_eq!(params.exclude_ranges.len(), 1);
        assert_eq!(params.exclude_ranges[0].start(), 0x1001);
        assert_eq!(params.exclude_ranges[0].end(), 0x1001);
    }

    #[test]
    fn test_parse_checksum_forced_invalid_pattern() {
        let result = parse_checksum("0", "@append;!0x1000-0x1001#F", false);
        assert!(result.is_err());
    }
    #[test]
    fn test_parse_checksum_empty_target_defaults_none() {
        let params = parse_checksum("0", ";0x1000-0x1003", false).unwrap();
        assert!(matches!(params.target, ChecksumTarget::None));
        assert_eq!(params.range.unwrap().start(), 0x1000);
    }

    #[test]
    fn test_parse_checksum_forced_multi_range_rejected() {
        let result = parse_checksum("0", "@append;!0x1000-0x1001:0x2000-0x2001#AA", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_checksum_multi_range_rejected() {
        let result = parse_checksum("0", "@append;0x1000-0x1001:0x2000-0x2001", false);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_data_processing_params_with_placement_and_output() {
        let params = parse_data_processing_params(32, "@append:key.pem;sig.bin").unwrap();
        assert!(matches!(params.placement, Some(ChecksumTarget::Append)));
        assert_eq!(params.key_info, "key.pem");
        assert_eq!(params.output_file, Some(PathBuf::from("sig.bin")));
    }

    #[test]
    fn test_parse_signature_verify_params() {
        let params = parse_signature_verify_params(4, "pub.pem!sig.bin").unwrap();
        assert_eq!(params.key_info, "pub.pem");
        assert_eq!(params.signature_info, "sig.bin");
    }

    #[test]
    fn test_parse_dspic_op_multi_range_rejected() {
        let result = parse_dspic_op("0x1000-0x1001:0x2000-0x2001;0x3000");
        assert!(result.is_err());
    }
}

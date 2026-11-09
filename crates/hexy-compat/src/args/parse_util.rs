use std::path::PathBuf;

use crate::{AddressRange, AddressRangeError, DspicOp, ForcedRange, Placement, RemapOptions};

use super::types::{ChecksumParams, ChecksumTarget, Import, ImportKind, MergeParam, ParseArgError};

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

/// A range as HexView reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RangeText {
    Valid(AddressRange),
    /// Empty, or reaching past the address space: HexView skips it.
    Skipped,
    /// Reversed or unreadable: HexView stops reading a range list there.
    Invalid,
}

/// A range as HexView reads it (see `AddressRange`'s `FromStr`).
pub(super) fn parse_range(s: &str) -> RangeText {
    match strip_quotes(s).parse() {
        Ok(range) => RangeText::Valid(range),
        Err(AddressRangeError::ZeroLength { .. } | AddressRangeError::PastAddressSpace { .. }) => {
            RangeText::Skipped
        }
        Err(_) => RangeText::Invalid,
    }
}

/// `:`-separated ranges as HexView reads them: skipped ranges are left out, and an
/// invalid range ends the list.
pub(super) fn parse_ranges(s: &str) -> Vec<AddressRange> {
    let mut ranges = Vec::new();
    for part in strip_quotes(s).split(':').filter(|part| !part.is_empty()) {
        match parse_range(part) {
            RangeText::Valid(range) => ranges.push(range),
            RangeText::Skipped => {}
            RangeText::Invalid => break,
        }
    }
    ranges
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
    let (file_and_offset, range) = split_merge_range(s);

    let (file, offset) = if let Some((file, offset_str)) = file_and_offset.split_once(';') {
        let offset = parse_signed_number(offset_str)?;
        (file, Some(offset))
    } else {
        (file_and_offset, None)
    };

    Ok(MergeParam {
        file: PathBuf::from(file),
        offset,
        range: match range {
            Some(RangeText::Valid(range)) => Some(range),
            _ => None,
        },
        invalid_range: range == Some(RangeText::Invalid),
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

/// The file part and the range after the last `:`, unless that `:` belongs to a
/// Windows drive or, with an offset, comes before it.
fn split_merge_range(s: &str) -> (&str, Option<RangeText>) {
    let Some(colon_pos) = s.rfind(':') else {
        return (s, None);
    };
    match parse_range(&s[colon_pos + 1..]) {
        RangeText::Invalid if !merge_range_delimiter_is_unambiguous(s, colon_pos) => (s, None),
        range => (&s[..colon_pos], Some(range)),
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

/// `file[;offset]` of `/IN` and `/IA`. HexView reads the offset as a signed lenient
/// number and wraps it into the address space.
pub(super) fn parse_import(kind: ImportKind, value: &str) -> Import {
    let value = strip_quotes(value);
    let (file, offset) = value.split_once(';').unwrap_or((value, ""));
    let offset = match offset.trim().strip_prefix('-') {
        Some(magnitude) => parse_lenient_number(magnitude).wrapping_neg(),
        None => parse_lenient_number(offset.trim()),
    };
    Import {
        kind,
        file: PathBuf::from(file),
        offset,
    }
}

pub(super) fn parse_remap(s: &str) -> Result<RemapOptions, ParseArgError> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() != 4 {
        return Err(ParseArgError::InvalidOption(format!(
            "remap requires 4 parameters: {s}"
        )));
    }

    let (start_str, end_str) = parts[0].split_once('-').ok_or_else(|| {
        ParseArgError::InvalidOption(format!("remap range invalid: {}", parts[0]))
    })?;

    Ok(RemapOptions {
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
            let RangeText::Valid(range) = parse_range(range_str) else {
                continue;
            };
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
            match parse_range(range_part) {
                RangeText::Valid(limit) => range = Some(limit),
                // HexView checksums nothing when the limiting range is invalid.
                _ => exclude_ranges.extend(AddressRange::from_start_end(0, u32::MAX).ok()),
            }
        }
        for exclude in pieces {
            exclude_ranges.extend(parse_ranges(exclude));
        }
    }

    let target = if target_str.is_empty() {
        ChecksumTarget::None
    } else if let Some(stripped) = target_str.strip_prefix('@') {
        ChecksumTarget::Place(parse_placement_target(stripped)?)
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

pub(super) fn parse_placement_target(target: &str) -> Result<Placement, ParseArgError> {
    let target_upper = target.to_ascii_uppercase();
    match target_upper.as_str() {
        "APPEND" => Ok(Placement::Append),
        "BEGIN" => Ok(Placement::Begin),
        "UPFRONT" => Ok(Placement::Prepend),
        "PREPEND" => Ok(Placement::Address(0)),
        "END" => Ok(Placement::OverwriteEnd),
        _ => Ok(Placement::Address(parse_number(target)?)),
    }
}

/// `/CDSPX` and `/CDSPS` items `range[;target]`, separated by `:`; text after a range,
/// such as `,target`, is ignored and an invalid range ends the list, as in HexView.
pub(super) fn parse_dspic_ops(value: &str) -> Result<Vec<DspicOp>, ParseArgError> {
    let mut ops = Vec::new();
    for item in strip_quotes(value)
        .split(':')
        .filter(|item| !item.is_empty())
    {
        let (range, target) = match item.split_once(';') {
            Some((range, target)) => (range, Some(parse_number(target)?)),
            None => (item, None),
        };
        match parse_range(range) {
            RangeText::Valid(range) => ops.push(DspicOp { range, target }),
            RangeText::Skipped => {}
            RangeText::Invalid => break,
        }
    }
    Ok(ops)
}

/// HexView's lenient integer: `0x`-prefixed hex or decimal digits, read up to the first
/// other character; no digits reads as 0.
pub(super) fn parse_lenient_number(s: &str) -> u32 {
    let (digits, radix) = match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (s, 10),
    };
    digits
        .chars()
        .map_while(|c| c.to_digit(radix))
        .fold(0u32, |acc, digit| {
            acc.saturating_mul(radix).saturating_add(digit)
        })
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

    /// HexView 1.15.2 merges the whole file when the /MT range is reversed, and fails.
    #[test]
    fn test_parse_merge_params_reversed_range_is_invalid() {
        let params = parse_merge_params("file.hex:0x2000-0x1000").unwrap();
        assert_eq!(params[0].file, PathBuf::from("file.hex"));
        assert!(params[0].range.is_none());
        assert!(params[0].invalid_range);
    }

    /// HexView 1.15.2 skips an empty range and stops a range list at an invalid one.
    #[test]
    fn test_parse_ranges_matches_hexview() {
        assert_eq!(
            parse_ranges("0x1000-0x1003q:0x1010,4:0x1018,:x:0x1020,4"),
            [0x1000, 0x1010].map(|start| AddressRange::from_start_length(start, 4).unwrap())
        );
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
}

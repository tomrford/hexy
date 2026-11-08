use std::path::PathBuf;

use crate::{
    DEFAULT_INTEL_HEX_BYTES_PER_LINE, DEFAULT_SREC_BYTES_PER_LINE, HexAsciiWriteOptions,
    IntelHexMode, IntelHexWriteOptions, MergeMode, Placement, SRecordType, SRecordWriteOptions,
};

use super::parse_util::{
    parse_checksum, parse_dspic_ops, parse_import, parse_lenient_number, parse_merge_params,
    parse_number, parse_ranges, parse_remap, split_option, strip_quotes,
};
use super::processing::{parse_data_processing, parse_signature_verify};
use super::types::{Args, Import, ImportKind, MergeSpec, OutputFormat, ParseArgError};

type ValueParser = fn(&mut Args, &str, &str) -> Result<bool, ParseArgError>;

fn parse_hex_no_sep(raw: &str) -> Result<u32, ParseArgError> {
    let stripped = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    u32::from_str_radix(stripped, 16).map_err(|_| ParseArgError::InvalidNumber(raw.to_owned()))
}

/// HexView options with an effect hexy does not reproduce: OEM containers, GM headers,
/// external DLLs and VBF tools.
fn reject_unsupported(key_upper: &str) -> Result<(), ParseArgError> {
    let unsupported = matches!(
        key_upper,
        "PB" | "EXPDAT" | "MVBF" | "XVBFSUBST" | "XFCA_SIGN" | "XV" | "XVBF" | "XB"
    ) || (key_upper.starts_with("XG") && key_upper != "XGACSWIL");
    if unsupported {
        return Err(ParseArgError::InvalidOption(format!(
            "/{key_upper} is not supported"
        )));
    }
    Ok(())
}

fn parse_simple_flag(args: &mut Args, opt_upper: &str) -> bool {
    match opt_upper {
        "S" => args.silent = true,
        "V" => args.write_version = true,
        "FA" => args.fill_all = true,
        "SWAPWORD" => args.swap_word = true,
        "SWAPLONG" => args.swap_long = true,
        "S08MAP" => args.s08_map = true,
        "S12MAP" => args.s12_map = true,
        "S12XMAP" => args.s12x_map = true,
        "AL" => args.align_length = Some(0),
        "VS" => args.validation = true,
        "VSHSM" => args.hsm_validation = Some(Some(Placement::Address(0))),
        // Disclaimer acceptance and license path: HexView runtime switches with no effect here.
        "G" | "M" => {}
        _ => return false,
    }
    true
}

fn parse_import_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    args.import = Some(match key_upper {
        // HexView reads all of the /II2 value as the file name.
        "II2" => Import {
            kind: ImportKind::IntelHex16,
            file: PathBuf::from(strip_quotes(value)),
            offset: 0,
        },
        "IN" => parse_import(ImportKind::Binary, value),
        "IA" => parse_import(ImportKind::HexAscii, value),
        _ => return Ok(false),
    });
    Ok(true)
}

fn parse_path_option(args: &mut Args, key_upper: &str, value: &str) -> Result<bool, ParseArgError> {
    let path = Some(PathBuf::from(strip_quotes(value)));
    match key_upper {
        "E" => args.error_log = path,
        "L" => args.log_file = path,
        "P" => args.ini_file = path,
        "M" => {}
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_range_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    match key_upper {
        // HexView keeps the intersection of the valid ranges; with none, /AR has no effect.
        "AR" => {
            let mut ranges = parse_ranges(value).into_iter();
            args.address_range = ranges.next().map(|first| {
                ranges
                    .try_fold(first, |acc, range| acc.intersection(&range))
                    .into_iter()
                    .collect()
            });
        }
        "CR" => args.cut_ranges.extend(parse_ranges(value)),
        "FR" => args.fill_ranges.extend(parse_ranges(value)),
        "CDSPG" => args.dspic_clear_ghost.extend(parse_ranges(value)),
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_merge_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    let mode = match key_upper {
        "MO" => MergeMode::Overwrite,
        "MT" => MergeMode::Preserve,
        _ => return Ok(false),
    };
    args.merge = Some(MergeSpec {
        mode,
        files: parse_merge_params(value)?,
    });
    Ok(true)
}

fn parse_numeric_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    match key_upper {
        // Compatibility performance-tuning flags; accepted for compat, values ignored.
        "BHFCT" | "BTFST" | "BTBS" => {
            let _ = parse_number(value)?;
        }
        "AD" => {
            if value.starts_with("0b") || value.starts_with("0B") {
                let _ = parse_number(value)?;
            } else {
                args.align_address = Some(parse_number(value)?);
            }
        }
        "AL" => args.align_length = Some(parse_lenient_number(value)),
        "AF" => {
            let fill = parse_number(value)?;
            if fill > u8::MAX as u32 {
                return Err(ParseArgError::InvalidNumber(value.to_owned()));
            }
            args.align_fill = fill as u8;
        }
        "AE" => args.align_erase = Some(parse_number(value)?),
        "SB" => args.split_block_size = Some(parse_lenient_number(value)),
        _ => return Ok(false),
    }
    Ok(true)
}

fn parse_checksum_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    let (multi, little_endian, algo) = if let Some(algo) = key_upper.strip_prefix("CSMR") {
        (true, true, algo)
    } else if let Some(algo) = key_upper.strip_prefix("CSM") {
        (true, false, algo)
    } else if let Some(algo) = key_upper.strip_prefix("CSR") {
        (false, true, algo)
    } else if let Some(algo) = key_upper.strip_prefix("CS") {
        (false, false, algo)
    } else {
        return Ok(false);
    };
    if !algo.chars().all(|c| c.is_ascii_digit()) {
        return Ok(false);
    }
    if (multi && args.checksum.is_some()) || (!multi && !args.checksum_multi.is_empty()) {
        return Err(ParseArgError::InvalidOption(
            "cannot combine /CS* with /CSM*".to_owned(),
        ));
    }
    let params = parse_checksum(algo, value, little_endian)?;
    if multi {
        args.checksum_multi.push(params);
    } else {
        args.checksum = Some(params);
    }
    Ok(true)
}

fn parse_data_processing_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    if let Some(method_str) = key_upper.strip_prefix("DP") {
        let method = method_str
            .parse::<u8>()
            .map_err(|_| ParseArgError::InvalidNumber(method_str.to_owned()))?;
        args.data_processing = Some(parse_data_processing(method, value)?);
        return Ok(true);
    }
    Ok(false)
}

fn parse_signature_verify_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    if let Some(method_str) = key_upper.strip_prefix("SV") {
        let method = method_str
            .parse::<u8>()
            .map_err(|_| ParseArgError::InvalidNumber(method_str.to_owned()))?;
        args.signature_verify = Some(parse_signature_verify(method, value));
        return Ok(true);
    }
    Ok(false)
}

fn parse_value_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    match key_upper {
        "CDSPX" => args.dspic_expand.extend(parse_dspic_ops(value)?),
        "CDSPS" => args.dspic_shrink.extend(parse_dspic_ops(value)?),
        // HexView reads the pattern like HEX ASCII data; without any digits the fill is
        // random.
        "FP" => {
            args.fill_pattern = crate::parse_hex_ascii(value.as_bytes(), 0)
                .ok()
                .and_then(|pattern| pattern.into_segments().pop())
                .map(|segment| segment.into_parts().1);
        }
        "REMAP" => args.remap = Some(parse_remap(value)?),
        // HexView reads the address as a lenient number, places the structure at 0
        // without one and after the data for `@end` or `@append`, and inserts nothing
        // for other words.
        "VSHSM" => {
            let target = value.strip_prefix('@').unwrap_or("");
            args.hsm_validation = Some(match target.to_ascii_uppercase().as_str() {
                "END" | "APPEND" => Some(Placement::Append),
                _ if target.is_empty() || target.starts_with(|c: char| c.is_ascii_digit()) => {
                    Some(Placement::Address(parse_lenient_number(target)))
                }
                _ => None,
            });
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// `/XI` and `/XS` record length; HexView crashes above 255.
fn record_length(value: &str) -> Result<u8, ParseArgError> {
    u8::try_from(parse_lenient_number(value))
        .map_err(|_| ParseArgError::InvalidNumber(value.to_owned()))
}

fn parse_output_option(
    args: &mut Args,
    key_upper: &str,
    value: Option<&str>,
) -> Result<bool, ParseArgError> {
    let mut params = value.map(|value| value.splitn(2, ':'));
    let mut param = || params.as_mut().and_then(Iterator::next);
    let format = match key_upper {
        "XI" => {
            let bytes_per_line = param().map(record_length).transpose()?;
            OutputFormat::IntelHex(IntelHexWriteOptions {
                bytes_per_line: bytes_per_line
                    .filter(|&len| len != 0)
                    .unwrap_or(DEFAULT_INTEL_HEX_BYTES_PER_LINE),
                mode: match param().map(parse_lenient_number) {
                    Some(1) => IntelHexMode::ExtendedLinear,
                    Some(2) => IntelHexMode::ExtendedSegment,
                    _ => IntelHexMode::Auto,
                },
            })
        }
        "XS" => OutputFormat::SRecord(SRecordWriteOptions {
            bytes_per_line: param()
                .map(record_length)
                .transpose()?
                .unwrap_or(DEFAULT_SREC_BYTES_PER_LINE),
            record_type: match param().map(parse_lenient_number) {
                Some(0) => Some(SRecordType::S1),
                Some(1) => Some(SRecordType::S2),
                Some(2) => Some(SRecordType::S3),
                _ => None,
            },
        }),
        "XN" => OutputFormat::Binary,
        "XA" => {
            let line_length = param().map_or(0, parse_lenient_number);
            OutputFormat::HexAscii(HexAsciiWriteOptions {
                line_length: if line_length == 0 {
                    HexAsciiWriteOptions::default().line_length
                } else {
                    line_length as usize
                },
                separator: param().unwrap_or_default().to_owned(),
            })
        }
        "XC" => OutputFormat::CCode,
        "XF" => OutputFormat::FordIntelHex,
        "XK" => OutputFormat::FlashKernel,
        "XGACSWIL" => OutputFormat::GacSwil,
        "XP" => OutputFormat::Porsche,
        "XSB" => OutputFormat::SeparateBinary,
        _ => return Ok(false),
    };
    args.output_format = Some(format);
    Ok(true)
}

/// Parse one option without its `/` or `-`; `Ok(false)` when HexView does not know it.
pub(super) fn parse_option(args: &mut Args, opt: &str) -> Result<bool, ParseArgError> {
    let opt_upper = opt.to_ascii_uppercase();

    if parse_simple_flag(args, &opt_upper) {
        return Ok(true);
    }
    // HexView accepts /RB only with '='.
    if let Some(value) = opt_upper.strip_prefix("RB=") {
        args.remove_blocks_below = Some(parse_lenient_number(value));
        return Ok(true);
    }

    // `/ADxx` and `/AFxx` read xx as hex digits.
    let hex_suffix = |prefix| {
        opt_upper
            .strip_prefix(prefix)
            .filter(|raw| !raw.is_empty() && !raw.starts_with([':', '=']))
    };
    if let Some(raw) = hex_suffix("AD") {
        args.align_address = Some(parse_hex_no_sep(raw)?);
        return Ok(true);
    }
    if let Some(raw) = hex_suffix("AF") {
        args.align_fill = u8::try_from(parse_hex_no_sep(raw)?)
            .map_err(|_| ParseArgError::InvalidNumber(raw.to_owned()))?;
        return Ok(true);
    }

    let Some((key, value)) = split_option(opt) else {
        reject_unsupported(&opt_upper)?;
        // `/CSn`, `/DPn` and `/SVn` without parameters; the latter two fail when their
        // stage runs.
        return Ok(parse_output_option(args, &opt_upper, None)?
            || parse_checksum_option(args, &opt_upper, "")?
            || parse_data_processing_option(args, &opt_upper, "")?
            || parse_signature_verify_option(args, &opt_upper, "")?);
    };
    let key_upper = key.to_ascii_uppercase();
    reject_unsupported(&key_upper)?;
    // HexView ignores `/CR=` and `/FR=`.
    if matches!(key_upper.as_str(), "CR" | "FR") && opt[key.len()..].starts_with('=') {
        return Ok(true);
    }

    let parsers: &[ValueParser] = &[
        |args, key, value| parse_output_option(args, key, Some(value)),
        parse_import_option,
        parse_path_option,
        parse_range_option,
        parse_merge_option,
        parse_numeric_option,
        parse_checksum_option,
        parse_data_processing_option,
        parse_signature_verify_option,
        parse_value_option,
    ];
    for parser in parsers {
        if parser(args, &key_upper, value)? {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests;

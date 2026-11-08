use std::path::PathBuf;

use crate::{
    AddressRange, DEFAULT_INTEL_HEX_BYTES_PER_LINE, DEFAULT_SREC_BYTES_PER_LINE,
    HexAsciiWriteOptions, IntelHexMode, IntelHexWriteOptions, SRecordType, SRecordWriteOptions,
};

use super::parse_util::{
    parse_checksum, parse_dspic_op, parse_hex_bytes, parse_import_param, parse_lenient_number,
    parse_lenient_ranges, parse_merge_params, parse_number, parse_remap, split_option,
    strip_quotes,
};
use super::processing::{parse_data_processing, parse_signature_verify};
use super::types::{Args, MergeParam, OutputFormat, ParseArgError};

type ValueParser = fn(&mut Args, &str, &str) -> Result<bool, ParseArgError>;

fn extend_ranges(target: &mut Vec<AddressRange>, value: &str) -> Result<(), ParseArgError> {
    target.extend(parse_lenient_ranges(value)?);
    Ok(())
}

fn extend_merges(target: &mut Vec<MergeParam>, value: &str) -> Result<(), ParseArgError> {
    let params = parse_merge_params(value)?;
    target.extend(params);
    Ok(())
}

fn parse_hex_no_sep(raw: &str) -> Result<u32, ParseArgError> {
    let stripped = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    u32::from_str_radix(stripped, 16).map_err(|_| ParseArgError::InvalidNumber(raw.to_owned()))
}

fn unsupported_output_format(key_upper: &str) -> ParseArgError {
    ParseArgError::InvalidOption(format!("/{key_upper} not yet implemented"))
}

fn parse_simple_flag(args: &mut Args, opt_upper: &str) -> bool {
    match opt_upper {
        "S" => {
            args.silent = true;
            true
        }
        "V" => {
            args.write_version = true;
            true
        }
        "FA" => {
            args.fill_all = true;
            true
        }
        "SWAPWORD" => {
            args.swap_word = true;
            true
        }
        "SWAPLONG" => {
            args.swap_long = true;
            true
        }
        "S08" | "S08MAP" => {
            args.s08_map = true;
            true
        }
        "S12MAP" => {
            args.s12_map = true;
            true
        }
        "S12XMAP" => {
            args.s12x_map = true;
            true
        }
        "AL" => {
            args.align_length = true;
            true
        }
        // Disclaimer acceptance and license path: HexView runtime switches with no effect here.
        "G" | "M" => true,
        _ => false,
    }
}

fn parse_import_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    match key_upper {
        "II2" => {
            args.import_i16 = Some(PathBuf::from(strip_quotes(value)));
            Ok(true)
        }
        "IN" => {
            args.import_binary = Some(parse_import_param(value)?);
            Ok(true)
        }
        "IA" => {
            args.import_hex_ascii = Some(parse_import_param(value)?);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn parse_path_option(args: &mut Args, key_upper: &str, value: &str) -> Result<bool, ParseArgError> {
    match key_upper {
        "E" => {
            args.error_log = Some(PathBuf::from(strip_quotes(value)));
            Ok(true)
        }
        "L" => {
            args.log_file = Some(PathBuf::from(strip_quotes(value)));
            Ok(true)
        }
        "P" => {
            args.ini_file = Some(PathBuf::from(strip_quotes(value)));
            Ok(true)
        }
        "PB" => {
            args.postbuild = Some(PathBuf::from(strip_quotes(value)));
            Ok(true)
        }
        "M" => Ok(true),
        _ => Ok(false),
    }
}

fn parse_range_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    match key_upper {
        // HexView keeps the intersection of the valid ranges; with none, /AR has no effect.
        "AR" => {
            let mut ranges = parse_lenient_ranges(value)?.into_iter();
            args.address_range = ranges.next().map(|first| {
                ranges
                    .try_fold(first, |acc, range| acc.intersection(&range))
                    .into_iter()
                    .collect()
            });
            Ok(true)
        }
        "CR" => {
            extend_ranges(&mut args.cut_ranges, value)?;
            Ok(true)
        }
        "FR" => {
            extend_ranges(&mut args.fill_ranges, value)?;
            Ok(true)
        }
        "CDSPG" => {
            extend_ranges(&mut args.dspic_clear_ghost, value)?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn parse_merge_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    match key_upper {
        "MO" => {
            extend_merges(&mut args.merge_opaque, value)?;
            Ok(true)
        }
        "MT" => {
            extend_merges(&mut args.merge_transparent, value)?;
            Ok(true)
        }
        _ => Ok(false),
    }
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
            Ok(true)
        }
        "AD" => {
            if value.starts_with("0b") || value.starts_with("0B") {
                let _ = parse_number(value)?;
            } else {
                args.align_address = Some(parse_number(value)?);
            }
            Ok(true)
        }
        "AL" => {
            args.align_length = true;
            if !value.is_empty() {
                args.align_address = Some(parse_number(value)?);
            }
            Ok(true)
        }
        "AF" => {
            let fill = parse_number(value)?;
            if fill > u8::MAX as u32 {
                return Err(ParseArgError::InvalidNumber(value.to_owned()));
            }
            args.align_fill = fill as u8;
            Ok(true)
        }
        "AE" => {
            args.align_erase = Some(parse_number(value)?);
            Ok(true)
        }
        "SB" => {
            args.split_block_size = Some(parse_lenient_number(value));
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn parse_checksum_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    fn reject_mixed(args: &Args, is_multi: bool) -> Result<(), ParseArgError> {
        if is_multi && args.checksum.is_some() {
            return Err(ParseArgError::InvalidOption(
                "cannot combine /CS* with /CSM*".to_owned(),
            ));
        }
        if !is_multi && !args.checksum_multi.is_empty() {
            return Err(ParseArgError::InvalidOption(
                "cannot combine /CS* with /CSM*".to_owned(),
            ));
        }
        Ok(())
    }

    if let Some(algo) = key_upper.strip_prefix("CSMR") {
        reject_mixed(args, true)?;
        args.checksum_multi.push(parse_checksum(algo, value, true)?);
        return Ok(true);
    }
    if let Some(algo) = key_upper.strip_prefix("CSM") {
        reject_mixed(args, true)?;
        args.checksum_multi
            .push(parse_checksum(algo, value, false)?);
        return Ok(true);
    }
    if let Some(algo) = key_upper.strip_prefix("CSR") {
        reject_mixed(args, false)?;
        args.checksum = Some(parse_checksum(algo, value, true)?);
        return Ok(true);
    }
    if let Some(algo) = key_upper.strip_prefix("CS") {
        reject_mixed(args, false)?;
        args.checksum = Some(parse_checksum(algo, value, false)?);
        return Ok(true);
    }
    Ok(false)
}

fn parse_bare_checksum_option(args: &mut Args, opt_upper: &str) -> Result<bool, ParseArgError> {
    if let Some(algo) = opt_upper.strip_prefix("CSMR")
        && algo.chars().all(|ch| ch.is_ascii_digit())
    {
        if args.checksum.is_some() {
            return Err(ParseArgError::InvalidOption(
                "cannot combine /CS* with /CSM*".to_owned(),
            ));
        }
        args.checksum_multi.push(parse_checksum(algo, "", true)?);
        return Ok(true);
    }
    if let Some(algo) = opt_upper.strip_prefix("CSM")
        && algo.chars().all(|ch| ch.is_ascii_digit())
    {
        if args.checksum.is_some() {
            return Err(ParseArgError::InvalidOption(
                "cannot combine /CS* with /CSM*".to_owned(),
            ));
        }
        args.checksum_multi.push(parse_checksum(algo, "", false)?);
        return Ok(true);
    }
    if let Some(algo) = opt_upper.strip_prefix("CSR")
        && algo.chars().all(|ch| ch.is_ascii_digit())
    {
        if !args.checksum_multi.is_empty() {
            return Err(ParseArgError::InvalidOption(
                "cannot combine /CS* with /CSM*".to_owned(),
            ));
        }
        args.checksum = Some(parse_checksum(algo, "", true)?);
        return Ok(true);
    }
    if let Some(algo) = opt_upper.strip_prefix("CS")
        && algo.chars().all(|ch| ch.is_ascii_digit())
    {
        if !args.checksum_multi.is_empty() {
            return Err(ParseArgError::InvalidOption(
                "cannot combine /CS* with /CSM*".to_owned(),
            ));
        }
        args.checksum = Some(parse_checksum(algo, "", false)?);
        return Ok(true);
    }
    Ok(false)
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

fn parse_dspic_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    match key_upper {
        "CDSPX" => {
            if let Ok(op) = parse_dspic_op(value) {
                args.dspic_expand.push(op);
            } else {
                for part in value.split(':').filter(|p| !p.is_empty()) {
                    args.dspic_expand.push(parse_dspic_op(part)?);
                }
            }
            Ok(true)
        }
        "CDSPS" => {
            if let Ok(op) = parse_dspic_op(value) {
                args.dspic_shrink.push(op);
            } else {
                for part in value.split(':').filter(|p| !p.is_empty()) {
                    args.dspic_shrink.push(parse_dspic_op(part)?);
                }
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn parse_value_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    match key_upper {
        "FP" => {
            args.fill_pattern = parse_hex_bytes(value)?;
            args.fill_pattern_set = true;
            Ok(true)
        }
        "REMAP" => {
            args.remap = Some(parse_remap(value)?);
            Ok(true)
        }
        _ => Ok(false),
    }
}

fn parse_output_option_value(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    parse_output_option(args, key_upper, Some(value))
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
        "XP" => OutputFormat::Porsche,
        "XSB" => OutputFormat::SeparateBinary,
        "XG" | "XGC" | "XGCC" | "XGAC" | "XGACSWIL" | "XK" | "XV" | "XVBF" | "XB" => {
            return Err(unsupported_output_format(key_upper));
        }
        _ => return Ok(false),
    };
    args.output_format = Some(format);
    Ok(true)
}

pub(super) fn parse_option(args: &mut Args, opt: &str) -> Result<(), ParseArgError> {
    let opt_upper = opt.to_ascii_uppercase();

    if parse_simple_flag(args, &opt_upper) {
        return Ok(());
    }
    if parse_bare_checksum_option(args, &opt_upper)? {
        return Ok(());
    }
    // HexView accepts /RB only with '='.
    if let Some(value) = opt_upper.strip_prefix("RB=") {
        args.remove_blocks_below = Some(parse_lenient_number(value));
        return Ok(());
    }

    if opt_upper.starts_with("AD")
        && opt_upper.len() > 2
        && !opt[2..].starts_with(':')
        && !opt[2..].starts_with('=')
    {
        let raw = &opt[2..];
        let value = parse_hex_no_sep(raw)?;
        args.align_address = Some(value);
        return Ok(());
    }

    if opt_upper.starts_with("AF")
        && opt_upper.len() > 2
        && !opt[2..].starts_with(':')
        && !opt[2..].starts_with('=')
    {
        let raw = &opt[2..];
        let value = parse_hex_no_sep(raw)?;
        if value > u8::MAX as u32 {
            return Err(ParseArgError::InvalidNumber(raw.to_owned()));
        }
        args.align_fill = value as u8;
        return Ok(());
    }

    if let Some((key, value)) = split_option(opt) {
        let key_upper = key.to_ascii_uppercase();

        let parsers: &[ValueParser] = &[
            parse_output_option_value,
            parse_import_option,
            parse_path_option,
            parse_range_option,
            parse_merge_option,
            parse_numeric_option,
            parse_checksum_option,
            parse_data_processing_option,
            parse_signature_verify_option,
            parse_dspic_option,
            parse_value_option,
        ];
        for parser in parsers {
            if parser(args, &key_upper, value)? {
                return Ok(());
            }
        }
        return Err(ParseArgError::InvalidOption(opt.to_owned()));
    } else {
        let opt_upper = opt.to_ascii_uppercase();
        if parse_output_option(args, &opt_upper, None)? {
            return Ok(());
        }
        // `/DPn` and `/SVn` without parameters fail when their stage runs.
        if parse_data_processing_option(args, &opt_upper, "")?
            || parse_signature_verify_option(args, &opt_upper, "")?
        {
            return Ok(());
        }
        if !parse_simple_flag(args, &opt_upper) {
            return Err(ParseArgError::InvalidOption(opt.to_owned()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;

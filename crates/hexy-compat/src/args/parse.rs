use std::path::PathBuf;

use crate::AddressRange;

use super::parse_util::{
    parse_checksum, parse_data_processing_params, parse_dspic_op, parse_hex_ascii_params,
    parse_hex_bytes, parse_hexview_ranges, parse_import_param, parse_merge_params, parse_number,
    parse_output_params, parse_remap, parse_signature_verify_params, split_option, strip_quotes,
};
use super::types::{Args, MergeParam, OutputFormat, ParseArgError};

type ValueParser = fn(&mut Args, &str, &str) -> Result<bool, ParseArgError>;

fn extend_ranges(target: &mut Vec<AddressRange>, value: &str) -> Result<(), ParseArgError> {
    let ranges = parse_hexview_ranges(value)?;
    target.extend(ranges);
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
        _ => Ok(false),
    }
}

fn parse_range_option(
    args: &mut Args,
    key_upper: &str,
    value: &str,
) -> Result<bool, ParseArgError> {
    match key_upper {
        "AR" => {
            extend_ranges(&mut args.address_range, value)?;
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
        // HexView performance-tuning flags; accepted for compat, values ignored.
        "BHFCT" | "BTFST" | "BTBS" => {
            let _ = parse_number(value)?;
            Ok(true)
        }
        "AD" => {
            args.align_address = Some(parse_number(value)?);
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
            args.split_block_size = Some(parse_number(value)?);
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
        args.data_processing = Some(parse_data_processing_params(method, value)?);
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
        args.signature_verify = Some(parse_signature_verify_params(method, value)?);
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
            for part in value.split(':').filter(|p| !p.is_empty()) {
                args.dspic_expand.push(parse_dspic_op(part)?);
            }
            Ok(true)
        }
        "CDSPS" => {
            for part in value.split(':').filter(|p| !p.is_empty()) {
                args.dspic_shrink.push(parse_dspic_op(part)?);
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

fn set_output_format(args: &mut Args, format: OutputFormat) -> Result<(), ParseArgError> {
    if args.output_format.is_some() {
        return Err(ParseArgError::DuplicateOutputFormat);
    }
    args.output_format = Some(format);
    Ok(())
}

fn parse_output_option(
    args: &mut Args,
    key_upper: &str,
    value: Option<&str>,
) -> Result<bool, ParseArgError> {
    match key_upper {
        "XI" => {
            if let Some(value) = value {
                let (len, rec_type) = parse_output_params(value)?;
                if rec_type.is_some() && len.is_none() {
                    return Err(ParseArgError::InvalidOption(
                        "record type requires reclinelen".to_owned(),
                    ));
                }
                args.bytes_per_line = len;
                set_output_format(
                    args,
                    OutputFormat::IntelHex {
                        record_type: rec_type,
                    },
                )?;
            } else {
                set_output_format(args, OutputFormat::IntelHex { record_type: None })?;
            }
            Ok(true)
        }
        "XS" => {
            if let Some(value) = value {
                let (len, rec_type) = parse_output_params(value)?;
                if rec_type.is_some() && len.is_none() {
                    return Err(ParseArgError::InvalidOption(
                        "record type requires reclinelen".to_owned(),
                    ));
                }
                args.bytes_per_line = len;
                set_output_format(
                    args,
                    OutputFormat::SRecord {
                        record_type: rec_type,
                    },
                )?;
            } else {
                set_output_format(args, OutputFormat::SRecord { record_type: None })?;
            }
            Ok(true)
        }
        "XN" => {
            set_output_format(args, OutputFormat::Binary)?;
            Ok(true)
        }
        "XA" => {
            let (line_length, separator) = if let Some(value) = value {
                parse_hex_ascii_params(value)?
            } else {
                (None, None)
            };
            set_output_format(
                args,
                OutputFormat::HexAscii {
                    line_length,
                    separator,
                },
            )?;
            Ok(true)
        }
        "XC" => {
            set_output_format(args, OutputFormat::CCode)?;
            Ok(true)
        }
        "XF" => {
            set_output_format(args, OutputFormat::FordIntelHex)?;
            Ok(true)
        }
        "XG" | "XGC" | "XGCC" | "XGAC" | "XGACSWIL" | "XK" => {
            Err(unsupported_output_format(key_upper))
        }
        "XP" => {
            set_output_format(args, OutputFormat::Porsche)?;
            Ok(true)
        }
        "XSB" => {
            set_output_format(args, OutputFormat::SeparateBinary)?;
            Ok(true)
        }
        "XV" | "XVBF" | "XB" => Err(unsupported_output_format(key_upper)),
        _ => Ok(false),
    }
}

pub(super) fn parse_option(args: &mut Args, opt: &str) -> Result<(), ParseArgError> {
    let opt_upper = opt.to_ascii_uppercase();

    if parse_simple_flag(args, &opt_upper) {
        return Ok(());
    }
    if parse_bare_checksum_option(args, &opt_upper)? {
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
        if !parse_simple_flag(args, &opt_upper) {
            return Err(ParseArgError::InvalidOption(opt.to_owned()));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests;

//! `/vs` and `/vshsm`: HexView's validation structures, configured by `[VALIDATION]`
//! and `[HSMBOOT]` in the INI file.

use std::path::Path;

use crate::{
    ChecksumAlgorithm, HsmValidationOptions, HsmValidationStage, Placement, ValidationCOptions,
    ValidationOptions, ValidationStage, ValidationStructure,
};

use super::error::CliError;
use super::export::load_export_ini;
use super::io::{ReadProvider, checksum_constant};
use super::parse_util::{parse_lenient_number, parse_ranges};
use super::processing::{DataProcessingParams, data_processing_stage, parse_data_processing};
use super::report::Report;
use super::types::Args;

/// The `/vs` stage and what follows it: the C files and an error to report once the
/// structure is built.
pub(super) struct Validation {
    pub(super) stage: ValidationStage,
    /// `.c` and `.h` file names, when `GenerateCFiles` asks for them.
    c_files: Option<(String, String)>,
    tag_values: (u32, u32),
    error: Option<String>,
}

impl Validation {
    /// The `[VALIDATION]` settings as HexView reads them. Missing keys are 0, except
    /// `EndianType`, which defaults to big-endian; a signed flag is set when it is not
    /// 0. A tag is its hex digits as HEX ASCII data, or with `IdTag...Length` the hex
    /// value in that many bytes. A tag with a length but no value makes HexView build
    /// the structure but neither insert nor sum it.
    pub(super) fn from_ini(
        args: &Args,
        provider: &impl ReadProvider,
        report: &Report,
    ) -> Result<Option<Self>, CliError> {
        let ini = load_export_ini(args, provider, "VALIDATION")?;
        if ini.is_empty() {
            report.warn("/vs: the INI file has no [VALIDATION] section");
            return Ok(None);
        }
        let text = |key: &str| ini.get(key).map_or("", String::as_str);
        let number = |key: &str| parse_lenient_number(text(key));
        let flag = |key: &str| {
            let value = text(key).trim();
            parse_lenient_number(value.strip_prefix(['+', '-']).unwrap_or(value)) != 0
        };
        let mut error = None;
        let mut checksum = |key: &str| -> Result<Option<ChecksumAlgorithm>, CliError> {
            let value = text(key).trim();
            if value.is_empty() || value.starts_with('-') {
                return Ok(None);
            }
            match ChecksumAlgorithm::try_from(parse_lenient_number(value).min(255) as u8) {
                Ok(ChecksumAlgorithm::Constant(_)) => Ok(Some(ChecksumAlgorithm::Constant(
                    checksum_constant(provider).map_err(CliError::Other)?,
                ))),
                Ok(algorithm) => Ok(Some(algorithm)),
                // HexView writes an empty checksum and fails the run.
                Err(e) => {
                    error.get_or_insert(format!("/vs {key}: {e}"));
                    Ok(Some(ChecksumAlgorithm::Constant(Vec::new())))
                }
            }
        };
        let block_checksum = checksum("blockchecksumtype")?;
        let file_checksum = checksum("filechecksumtype")?;
        let length = |key: &str| number(&format!("{key}length")) as usize;
        let tag = |key: &str| match tag_bytes(text(key), length(key)) {
            None if length(key) == 0 => Some(Vec::new()),
            tag => tag,
        };
        let tags = (tag("idtagbegin"), tag("idtagend"));
        let complete = tags.0.is_some() && tags.1.is_some();
        if !complete {
            report.warn("/vs: a tag with a length needs a value to insert the structure");
        }
        let blank = |key: &str| vec![0; length(key)];
        let address = text("baseaddress").trim();
        let file_name = |key: &str| Some(text(key).to_owned()).filter(|name| !name.is_empty());
        Ok(Some(Self {
            stage: ValidationStage {
                options: ValidationOptions {
                    tag_begin: tags.0.unwrap_or_else(|| blank("idtagbegin")),
                    tag_end: tags.1.unwrap_or_else(|| blank("idtagend")),
                    block_checksum,
                    file_checksum,
                    validate_sum: complete && flag("validatechecksum"),
                    big_endian: ini.get("endiantype").is_none_or(|_| flag("endiantype")),
                    force_32bit: flag("force32bitformat"),
                    alfi: flag("writealfi"),
                    one_byte_count: flag("forceblocksize1byte"),
                    spare: parse_ranges(text("sparerange")),
                },
                address: (complete && flag("insertdata") && !address.is_empty())
                    .then(|| parse_lenient_number(address)),
            },
            c_files: file_name("cfilename")
                .zip(file_name("hfilename"))
                .filter(|_| flag("generatecfiles")),
            tag_values: (c_number(text("idtagbegin")), c_number(text("idtagend"))),
            error,
        }))
    }

    /// Write the C files of the built `structure`, then report a checksum method HexView
    /// does not know.
    pub(super) fn finish(&self, structure: &ValidationStructure) -> Result<(), CliError> {
        if let Some((c_file_name, h_file_name)) = &self.c_files {
            let (c, h) = crate::write_validation_c(
                &self.stage.options,
                structure,
                &ValidationCOptions {
                    c_file_name: c_file_name.clone(),
                    h_file_name: h_file_name.clone(),
                    created: chrono::Local::now()
                        .format("%a %b %e %H:%M:%S %Y")
                        .to_string(),
                    tag_begin_value: self.tag_values.0,
                    tag_end_value: self.tag_values.1,
                },
            );
            std::fs::write(c_file_name, c)?;
            std::fs::write(h_file_name, h)?;
        }
        self.error
            .clone()
            .map_or(Ok(()), |e| Err(CliError::Other(e)))
    }
}

/// The `/vshsm` stage as HexView reads `[HSMBOOT]`, numbers `0x` hex or decimal:
/// `GROUP_ID` and `MODE` (default 0),
/// `HASH_METHOD` (default 20, SHA-256), and `SIGNATURE_METHOD` with `SIGNATURE_PARAM`
/// for a `/DP` signature over the structure. Relative key paths resolve against `dir`.
pub(super) fn hsm_validation_stage(
    args: &Args,
    placement: Option<Placement>,
    dir: &Path,
    provider: &impl ReadProvider,
) -> Result<HsmValidationStage, String> {
    let ini = load_export_ini(args, provider, "HSMBOOT").map_err(|e| e.to_string())?;
    let text = |key: &str| ini.get(key).map_or("", String::as_str).trim();
    let hash = match text("hash_method") {
        "" => ChecksumAlgorithm::Sha256,
        method => match ChecksumAlgorithm::try_from(parse_lenient_number(method).min(255) as u8)
            .map_err(|e| e.to_string())?
        {
            ChecksumAlgorithm::Constant(_) => {
                ChecksumAlgorithm::Constant(checksum_constant(provider)?)
            }
            algorithm => algorithm,
        },
    };
    let signature = match hsm_signature_params(args, provider)? {
        Some(params) => data_processing_stage(&params, dir, provider)?.map(|stage| stage.operation),
        None => None,
    };
    Ok(HsmValidationStage {
        options: HsmValidationOptions {
            group_id: parse_lenient_number(text("group_id")),
            mode: parse_lenient_number(text("mode")) as u16,
            hash,
        },
        placement,
        signature,
    })
}

/// The `/DP` parameters of the `[HSMBOOT]` signature, which also name its output file.
pub(super) fn hsm_signature_params(
    args: &Args,
    provider: &impl ReadProvider,
) -> Result<Option<DataProcessingParams>, String> {
    let ini = load_export_ini(args, provider, "HSMBOOT").map_err(|e| e.to_string())?;
    let text = |key: &str| ini.get(key).map_or("", String::as_str).trim();
    match text("signature_method") {
        "" => Ok(None),
        method if method.starts_with('-') => Ok(None),
        method => {
            let method = u8::try_from(parse_lenient_number(method)).map_err(|e| e.to_string())?;
            parse_data_processing(method, text("signature_param"))
                .map(Some)
                .map_err(|e| e.to_string())
        }
    }
}

/// A tag's bytes: `len` big-endian bytes of its hex value, or without `len` its hex
/// digits read as HEX ASCII data. `None` for an empty tag.
fn tag_bytes(text: &str, len: usize) -> Option<Vec<u8>> {
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    if len == 0 {
        return crate::parse_hex_ascii(text.as_bytes(), 0)
            .ok()
            .and_then(|tag| tag.into_segments().pop())
            .map(|segment| segment.into_parts().1);
    }
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let end = digits
        .find(|c: char| !c.is_ascii_hexdigit())
        .unwrap_or(digits.len());
    let mut nibbles: Vec<u8> = digits[..end]
        .chars()
        .filter_map(|c| c.to_digit(16).map(|d| d as u8))
        .collect();
    if nibbles.len() % 2 == 1 {
        nibbles.insert(0, 0);
    }
    let value: Vec<u8> = nibbles
        .chunks(2)
        .map(|pair| pair[0] << 4 | pair[1])
        .collect();
    let mut bytes = vec![0; len.saturating_sub(value.len())];
    bytes.extend_from_slice(&value[value.len().saturating_sub(len)..]);
    Some(bytes)
}

/// C's `strtoul(text, NULL, 0)`, as HexView writes a tag value into the `.c` file:
/// `0x` hex, a leading `0` octal, decimal otherwise, up to the first other character.
fn c_number(text: &str) -> u32 {
    let text = text.trim();
    let (radix, digits) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => (16, hex),
        None if text.starts_with('0') => (8, text),
        None => (10, text),
    };
    digits
        .chars()
        .map_while(|c| c.to_digit(radix))
        .fold(0u32, |acc, digit| {
            acc.wrapping_mul(radix).wrapping_add(digit)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HexView 1.15.2 tag bytes and `.c` tag values.
    #[test]
    fn test_tags_match_hexview() {
        assert_eq!(tag_bytes("123", 0), Some(vec![0x12, 0x03]));
        assert_eq!(tag_bytes("zz12", 0), Some(vec![0x12]));
        assert_eq!(tag_bytes("0x1234", 3), Some(vec![0x00, 0x12, 0x34]));
        assert_eq!(tag_bytes("ABCDEF", 1), Some(vec![0xEF]));
        assert_eq!(tag_bytes("0x1234", 20).map(|tag| tag.len()), Some(20));
        assert_eq!(tag_bytes("", 2), None);
        assert_eq!(c_number("12345678"), 0xBC_614E);
        assert_eq!(c_number("123456789A"), 0x75B_CD15);
        assert_eq!(c_number("0x1234"), 0x1234);
        assert_eq!(c_number("ABCDEF"), 0);
    }
}

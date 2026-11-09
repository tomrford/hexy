use std::path::Path;
use std::{collections::HashMap, io};

use hexy_core::HexFile;

use super::error::CliError;
use super::ini::load_ini;
use super::parse_util::parse_lenient_number;
use super::types::ChecksumParams;

pub(super) trait ReadProvider {
    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, std::io::Error>;

    fn read_string(&self, path: &Path) -> Result<String, std::io::Error> {
        let bytes = self.read_bytes(path)?;
        String::from_utf8(bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
    }
}

pub(super) struct FsProvider;

impl ReadProvider for FsProvider {
    fn read_bytes(&self, path: &Path) -> Result<Vec<u8>, std::io::Error> {
        std::fs::read(path)
    }
}

pub(super) fn load_input(provider: &impl ReadProvider, path: &Path) -> Result<HexFile, CliError> {
    let content = provider.read_bytes(path)?;
    Ok(crate::parse_auto(&content)?)
}

pub(super) fn load_ini_or_empty(
    path: &Path,
    provider: &impl ReadProvider,
    section: Option<&str>,
) -> Result<HashMap<String, String>, CliError> {
    match load_ini(path, provider, section) {
        Ok(ini) => Ok(ini),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(HashMap::new()),
        Err(err) => Err(err.into()),
    }
}

/// Core checksum options for `params`.
pub(super) fn checksum_options(
    params: &ChecksumParams,
    provider: &impl ReadProvider,
) -> Result<crate::ChecksumOptions, String> {
    let algorithm =
        match crate::ChecksumAlgorithm::try_from(params.algorithm).map_err(|e| e.to_string())? {
            crate::ChecksumAlgorithm::Constant(_) => {
                crate::ChecksumAlgorithm::Constant(checksum_constant(provider)?)
            }
            algorithm => algorithm,
        };
    Ok(crate::ChecksumOptions {
        algorithm,
        range: params.range,
        little_endian_output: params.little_endian,
        forced_range: params.forced_range.clone(),
        exclude_ranges: params.exclude_ranges.clone(),
    })
}

/// Method 16 bytes from `[constant]` in `expdatproc.ini` in the working directory, as
/// HexView's expdatproc reads them: `NumBytes` (default 2) bytes taken as digit pairs
/// from `HexDataString` (default `0815`), a trailing single digit making the last byte.
fn checksum_constant(provider: &impl ReadProvider) -> Result<Vec<u8>, String> {
    let ini = load_ini_or_empty(Path::new("expdatproc.ini"), provider, Some("constant"))
        .map_err(|e| format!("expdatproc.ini: {e}"))?;
    let num_bytes = ini
        .get("numbytes")
        .map_or(2, |value| parse_lenient_number(value));
    if num_bytes == 0 {
        return Err("expdatproc.ini NumBytes must be a positive number".into());
    }
    let text = ini.get("hexdatastring").map_or("0815", String::as_str);
    text.as_bytes()
        .chunks(2)
        .take(num_bytes as usize)
        .map(|digits| {
            std::str::from_utf8(digits)
                .ok()
                .filter(|digits| digits.bytes().all(|b| b.is_ascii_hexdigit()))
                .and_then(|digits| u8::from_str_radix(digits, 16).ok())
                .ok_or_else(|| format!("expdatproc.ini HexDataString is not hex: {text}"))
        })
        .collect()
}

/// Write checksum bytes as the `0xAA, 0xBB` text HexView produces for file targets.
pub(super) fn write_checksum_text(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    std::fs::write(path, hex_list(bytes, ", "))
}

/// Write bytes as the `0xAA ,0xBB` text HexView produces for `/DP` output files.
pub(super) fn write_data_processing_text(
    path: &Path,
    bytes: &[u8],
    crlf: bool,
) -> Result<(), std::io::Error> {
    let mut text = hex_list(bytes, " ,");
    if crlf {
        text.push_str("\r\n");
    }
    std::fs::write(path, text)
}

fn hex_list(bytes: &[u8], separator: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{b:02X}"))
        .collect::<Vec<_>>()
        .join(separator)
}

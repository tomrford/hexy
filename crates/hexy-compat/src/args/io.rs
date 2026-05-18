use std::path::{Path, PathBuf};
use std::{collections::HashMap, io};

use crate::HexFile;

use super::error::CliError;
use super::ini::load_ini;
use super::parse_util::parse_number;
use super::types::Args;
use super::types::OutputFormat;

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

pub(super) fn load_binary_input(
    provider: &impl ReadProvider,
    path: &Path,
    offset: u32,
) -> Result<HexFile, CliError> {
    let content = provider.read_bytes(path)?;
    let hexfile = crate::parse_binary(&content, offset)?;
    Ok(hexfile)
}

pub(super) fn load_hex_ascii_input(
    provider: &impl ReadProvider,
    path: &Path,
    offset: u32,
) -> Result<HexFile, CliError> {
    let content = provider.read_bytes(path)?;
    let hexfile = crate::parse_hex_ascii(&content, offset)?;
    Ok(hexfile)
}

pub(super) fn hexfiles_overlap(a: &HexFile, b: &HexFile) -> bool {
    let mut a_segments = a.segments().to_vec();
    let mut b_segments = b.segments().to_vec();
    a_segments.sort_by_key(|s| s.start_address);
    b_segments.sort_by_key(|s| s.start_address);

    let mut i = 0usize;
    let mut j = 0usize;
    while i < a_segments.len() && j < b_segments.len() {
        let a_seg = &a_segments[i];
        let b_seg = &b_segments[j];
        if a_seg.end_address() < b_seg.start_address {
            i += 1;
            continue;
        }
        if b_seg.end_address() < a_seg.start_address {
            j += 1;
            continue;
        }
        return true;
    }
    false
}

pub(super) fn load_intel_hex_16bit_input(
    provider: &impl ReadProvider,
    path: &Path,
) -> Result<HexFile, CliError> {
    let content = provider.read_bytes(path)?;
    let hexfile = crate::parse_intel_hex_16bit(&content)?;
    Ok(hexfile)
}

pub(super) fn write_output(
    hexfile: &HexFile,
    path: &PathBuf,
    format: &Option<OutputFormat>,
    bytes_per_line: Option<u8>,
) -> Result<(), CliError> {
    let format = format
        .as_ref()
        .unwrap_or(&OutputFormat::IntelHex { record_type: None });

    match format {
        OutputFormat::IntelHex { record_type } => {
            let mode = match record_type {
                Some(1) => crate::IntelHexMode::ExtendedLinear,
                Some(2) => crate::IntelHexMode::ExtendedSegment,
                _ => crate::IntelHexMode::Auto,
            };
            let options = crate::IntelHexWriteOptions {
                bytes_per_line: bytes_per_line.unwrap_or(32),
                mode,
            };
            hexfile.write_intel_hex_file(path, &options)?;
        }
        OutputFormat::SRecord { record_type } => {
            let record_type = match record_type {
                None => None,
                Some(0) => Some(crate::SRecordType::S1),
                Some(1) => Some(crate::SRecordType::S2),
                Some(2) => Some(crate::SRecordType::S3),
                Some(other) => {
                    return Err(CliError::Other(format!(
                        "unsupported S-Record type {other}"
                    )));
                }
            };
            let options = crate::SRecordWriteOptions {
                bytes_per_line: bytes_per_line.unwrap_or(32),
                record_type,
            };
            hexfile.write_srec_file(path, &options)?;
        }
        OutputFormat::Binary => {
            let options = crate::BinaryWriteOptions::default();
            hexfile.write_binary_file(path, &options)?;
        }
        OutputFormat::HexAscii {
            line_length,
            separator,
        } => {
            let options = crate::HexAsciiWriteOptions {
                line_length: line_length.unwrap_or(16) as usize,
                separator: separator.clone(),
            };
            hexfile.write_hex_ascii_file(path, &options)?;
        }
        OutputFormat::SeparateBinary => write_separate_binary(hexfile, path)?,
        OutputFormat::CCode => {
            return Err(CliError::Other(
                "C-code output must be handled by caller".into(),
            ));
        }
        OutputFormat::Porsche => {
            return Err(CliError::Other(
                "Porsche output must be handled by caller".into(),
            ));
        }
        _ => {
            return Err(CliError::Other(format!(
                "Output format {:?} not yet implemented",
                format
            )));
        }
    }

    Ok(())
}

pub(super) fn write_output_for_args(
    args: &Args,
    hexfile: &HexFile,
    provider: &impl ReadProvider,
) -> Result<(), CliError> {
    match args.output_format {
        Some(OutputFormat::CCode) => {
            let path = resolve_c_code_output_path(args)?;
            write_c_code_output(args, hexfile, &path, provider)?;
            Ok(())
        }
        Some(OutputFormat::FordIntelHex) => {
            let path = resolve_ford_output_path(args)?;
            write_ford_ihex_output(args, hexfile, &path, provider)?;
            Ok(())
        }
        Some(OutputFormat::Porsche) => {
            let path = resolve_porsche_output_path(args)?;
            write_porsche_output(args, hexfile, &path)?;
            Ok(())
        }
        _ => {
            if let Some(ref path) = args.output_file {
                write_output(hexfile, path, &args.output_format, args.bytes_per_line)?;
            }
            Ok(())
        }
    }
}

pub(super) fn write_c_code_output(
    args: &Args,
    hexfile: &HexFile,
    output_path: &Path,
    provider: &impl ReadProvider,
) -> Result<(), CliError> {
    let ini_path = resolve_ini_path(args)?;
    let ini = match load_ini(&ini_path, provider) {
        Ok(ini) => ini,
        Err(err) if err.kind() == io::ErrorKind::NotFound => HashMap::new(),
        Err(err) => return Err(err.into()),
    };

    let prefix = ini
        .get("prefix")
        .cloned()
        .unwrap_or_else(|| "flashDrv".to_owned());
    let word_size = ini
        .get("wordsize")
        .map(|v| parse_number(v))
        .transpose()?
        .unwrap_or(0);
    let word_type = ini
        .get("wordtype")
        .map(|v| parse_number(v))
        .transpose()?
        .unwrap_or(0);
    let decrypt = ini
        .get("decryption")
        .map(|v| parse_number(v).map(|n| n != 0))
        .transpose()?
        .unwrap_or(false);
    let decrypt_value = ini
        .get("decryptvalue")
        .map(|v| parse_number(v))
        .transpose()?
        .unwrap_or(0);

    let word_type = match word_type {
        0 => crate::CCodeWordType::Intel,
        1 => crate::CCodeWordType::Motorola,
        other => {
            return Err(CliError::Other(format!("unsupported WordType {other}")));
        }
    };

    let header_name = output_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(&prefix)
        .to_owned();

    let options = crate::CCodeWriteOptions {
        prefix: prefix.clone(),
        header_name,
        word_size: word_size as u8,
        word_type,
        decrypt,
        decrypt_value,
    };
    let output = crate::write_c_code(hexfile, &options)?;

    let (c_path, h_path) = derive_c_code_paths(output_path, &prefix);
    std::fs::write(c_path, output.c)?;
    std::fs::write(h_path, output.h)?;
    Ok(())
}

pub(super) fn resolve_c_code_output_path(args: &Args) -> Result<PathBuf, CliError> {
    if let Some(path) = args.output_file.clone() {
        return Ok(path);
    }

    if let Some(input) = primary_input_path(args) {
        return Ok(input.with_extension("c"));
    }

    Err(CliError::Other(
        "output file required for /XC (use -o <file>)".into(),
    ))
}

pub(super) fn write_ford_ihex_output(
    args: &Args,
    hexfile: &HexFile,
    output_path: &Path,
    provider: &impl ReadProvider,
) -> Result<(), CliError> {
    let ini_path = resolve_ini_path(args)?;
    let ini = match load_ini(&ini_path, provider) {
        Ok(ini) => ini,
        Err(err) if err.kind() == io::ErrorKind::NotFound => HashMap::new(),
        Err(err) => return Err(err.into()),
    };

    let header = build_ford_header(args, hexfile, output_path, &ini)?;
    let options = crate::IntelHexWriteOptions {
        bytes_per_line: args.bytes_per_line.unwrap_or(32),
        mode: crate::IntelHexMode::Auto,
    };
    let data = crate::write_intel_hex(hexfile, &options);
    let data = String::from_utf8(data)
        .map_err(|e| CliError::Other(format!("invalid Intel HEX output: {e}")))?;

    let mut output = Vec::new();
    output.extend_from_slice(normalize_crlf(&header).as_bytes());
    output.extend_from_slice(normalize_crlf(&data).as_bytes());
    std::fs::write(output_path, output)?;
    Ok(())
}

pub(super) fn resolve_ford_output_path(args: &Args) -> Result<PathBuf, CliError> {
    if let Some(path) = args.output_file.clone() {
        return Ok(path);
    }

    if let Some(input) = primary_input_path(args) {
        return Ok(input.with_extension("hex"));
    }

    Err(CliError::Other(
        "output file required for /XF (use -o <file>)".into(),
    ))
}

pub(super) fn write_porsche_output(
    args: &Args,
    hexfile: &HexFile,
    output_path: &Path,
) -> Result<(), CliError> {
    let mut normalized = hexfile.normalized();
    if normalized.segments().is_empty() {
        std::fs::write(output_path, [])?;
        return Ok(());
    }

    let fill = args.align_fill;
    normalized.fill_gaps(fill);
    let data = normalized.segments()[0].data.clone();
    let checksum = byte_sum_u16(&data);
    let mut output = data;
    output.extend_from_slice(&checksum.to_be_bytes());
    std::fs::write(output_path, output)?;
    Ok(())
}

pub(super) fn resolve_porsche_output_path(args: &Args) -> Result<PathBuf, CliError> {
    if let Some(path) = args.output_file.clone() {
        return Ok(path);
    }

    if let Some(input) = primary_input_path(args) {
        return Ok(input.with_extension("bin"));
    }

    Err(CliError::Other(
        "output file required for /XP (use -o <file>)".into(),
    ))
}

fn resolve_ini_path(args: &Args) -> Result<PathBuf, CliError> {
    if let Some(path) = args.ini_file.clone() {
        return Ok(path);
    }

    if let Some(input) = primary_input_path(args) {
        return Ok(input.with_extension("ini"));
    }

    Err(CliError::Other(
        "INI file required for /XC (use /P:<file>)".into(),
    ))
}

fn primary_input_path(args: &Args) -> Option<&Path> {
    args.input_file
        .as_deref()
        .or(args
            .import_binary
            .as_ref()
            .map(|import| import.file.as_path()))
        .or(args
            .import_hex_ascii
            .as_ref()
            .map(|import| import.file.as_path()))
        .or(args.import_i16.as_deref())
}

fn derive_c_code_paths(output_path: &Path, prefix: &str) -> (PathBuf, PathBuf) {
    let dir = output_path.parent().unwrap_or_else(|| Path::new("."));
    let stem = output_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(prefix);
    let c_path = dir.join(format!("{stem}.c"));
    let h_path = dir.join(format!("{stem}.h"));
    (c_path, h_path)
}

fn build_ford_header(
    args: &Args,
    hexfile: &HexFile,
    output_path: &Path,
    ini: &std::collections::HashMap<String, String>,
) -> Result<String, CliError> {
    let mut lines = Vec::new();

    let required = [
        "application",
        "mask number",
        "module type",
        "production module part number",
        "wers notice",
        "comments",
        "released by",
        "module name",
        "module id",
    ];
    for key in required {
        let value = ini.get(key).cloned().unwrap_or_default();
        lines.push(format!("{}>{}", key.to_ascii_uppercase(), value));
    }

    let file_name = ini.get("file name").cloned().unwrap_or_else(|| {
        output_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("output.hex")
            .to_owned()
    });
    lines.insert(2, format!("FILE NAME>{file_name}"));

    let release_date = ini
        .get("release date")
        .cloned()
        .unwrap_or_else(|| current_date_mmddyyyy().unwrap_or_else(|| "01/01/1970".to_owned()));
    lines.insert(3, format!("RELEASE DATE>{release_date}"));

    let download_format = ini
        .get("download format")
        .cloned()
        .unwrap_or_else(|| "0x00".to_owned());
    lines.push(format!("DOWNLOAD FORMAT>{download_format}"));

    let checksum = compute_ford_checksum(hexfile);
    lines.push(format!("FILE CHECKSUM>0x{checksum:04X}"));

    let flash_indicator = ini
        .get("flash indicator")
        .cloned()
        .unwrap_or_else(|| "0".to_owned());
    lines.push(format!("FLASH INDICATOR>{flash_indicator}"));

    let erase = ini
        .get("flash erase sectors")
        .cloned()
        .unwrap_or_else(|| format_erase_sectors(hexfile, args.align_erase));
    lines.push(format!("FLASH ERASE SECTORS>{erase}"));

    lines.push("$".to_owned());
    Ok(lines.join("\n") + "\n")
}

fn normalize_crlf(text: &str) -> String {
    text.replace("\r\n", "\n")
        .replace('\r', "\n")
        .replace('\n', "\r\n")
}

fn compute_ford_checksum(hexfile: &HexFile) -> u16 {
    let mut sum: u16 = 0;
    let mut segments = hexfile.normalized().into_segments();
    segments.sort_by_key(|s| s.start_address);
    for segment in segments {
        for byte in segment.data {
            sum = sum.wrapping_add(byte as u16);
        }
    }
    sum
}

fn format_erase_sectors(hexfile: &HexFile, alignment: Option<u32>) -> String {
    let mut segments = hexfile.normalized().into_segments();
    segments.sort_by_key(|s| s.start_address);
    let mut parts = Vec::new();

    for segment in segments {
        let start = segment.start_address;
        let len = segment.len() as u32;
        let (aligned_start, aligned_len) = if let Some(align) = alignment.filter(|a| *a > 0) {
            let start64 = start as u64;
            let len64 = len as u64;
            let align64 = align as u64;
            let aligned_start = (start64 / align64) * align64;
            let end = start64 + len64 - 1;
            let aligned_end = (end + 1).div_ceil(align64) * align64 - 1;
            let aligned_len = aligned_end - aligned_start + 1;
            (aligned_start as u32, aligned_len as u32)
        } else {
            (start, len)
        };
        parts.push(format!("0x{aligned_start:X},0x{aligned_len:X}"));
    }

    parts
        .into_iter()
        .map(|p| format!(":{p}"))
        .collect::<String>()
}

fn byte_sum_u16(data: &[u8]) -> u16 {
    data.iter().fold(0u16, |acc, &b| acc.wrapping_add(b as u16))
}

fn current_date_mmddyyyy() -> Option<String> {
    let output = std::process::Command::new("date")
        .arg("+%m/%d/%Y")
        .output()
        .ok()?;
    let date = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if date.is_empty() { None } else { Some(date) }
}

fn write_separate_binary(hexfile: &HexFile, path: &Path) -> Result<(), CliError> {
    let normalized = hexfile.normalized();
    let mut segments = normalized.into_segments();
    segments.sort_by_key(|s| s.start_address);

    if segments.is_empty() {
        return Ok(());
    }

    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("bin");

    for segment in segments {
        let filename = format!("{stem}_{:x}.{ext}", segment.start_address);
        let out_path = dir.join(filename);
        std::fs::write(out_path, segment.data)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;
    use std::fs;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_temp_dir() -> PathBuf {
        static COUNTER: AtomicUsize = AtomicUsize::new(0);
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        let count = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "hexy_test_{stamp}_{}_{}",
            std::process::id(),
            count
        ));
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn test_write_separate_binary_outputs_segments() {
        let dir = unique_temp_dir();
        let output = dir.join("out.bin");
        let hexfile = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA, 0xBB]),
            Segment::new(0x2000, vec![0xCC]),
        ]);

        write_output(&hexfile, &output, &Some(OutputFormat::SeparateBinary), None).unwrap();

        let file1 = dir.join("out_1000.bin");
        let file2 = dir.join("out_2000.bin");
        assert_eq!(fs::read(file1).unwrap(), vec![0xAA, 0xBB]);
        assert_eq!(fs::read(file2).unwrap(), vec![0xCC]);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_write_ford_ihex_happy_path() {
        let dir = unique_temp_dir();
        let ini_path = dir.join("ford.ini");
        let output = dir.join("ford.hex");
        let ini = "[FORDHEADER]\nAPPLICATION=APP\nMASK NUMBER=7\nMODULE TYPE=TYPE\nPRODUCTION MODULE PART NUMBER=PN\nWERS NOTICE=WERS\nCOMMENTS=Note\nRELEASED BY=Dev\nMODULE NAME=MOD\nMODULE ID=0x1234\nRELEASE DATE=01/02/2003\nDOWNLOAD FORMAT=0x01\nFLASH INDICATOR=1\n";
        fs::write(&ini_path, ini).unwrap();

        let args = Args {
            ini_file: Some(ini_path),
            bytes_per_line: Some(16),
            ..Args::default()
        };
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02])]);
        let provider = FsProvider;

        write_ford_ihex_output(&args, &hexfile, &output, &provider).unwrap();
        let content = fs::read_to_string(&output).unwrap();
        assert!(content.contains("APPLICATION>APP"));
        assert!(content.contains("FILE CHECKSUM>"));
        assert!(content.contains("$"));
        assert!(content.contains(":"));
        assert!(content.contains("FLASH ERASE SECTORS>:0x1000,0x2"));
        let bytes = fs::read(&output).unwrap();
        assert!(bytes.windows(2).any(|w| w == b"\r\n"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_write_ford_ihex_allows_minimal_header() {
        let dir = unique_temp_dir();
        let ini_path = dir.join("ford.ini");
        let output = dir.join("ford.hex");
        fs::write(&ini_path, "[FORDHEADER]\nAPPLICATION=APP\n").unwrap();

        let args = Args {
            ini_file: Some(ini_path),
            ..Args::default()
        };
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01])]);
        let provider = FsProvider;
        let result = write_ford_ihex_output(&args, &hexfile, &output, &provider);
        assert!(result.is_ok(), "{result:?}");
        let text = fs::read_to_string(&output).unwrap();
        assert!(text.contains("FILE NAME>ford.hex"));
        assert!(text.contains(":00000001FF"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_write_ford_ihex_allows_missing_ini() {
        let dir = unique_temp_dir();
        let output = dir.join("ford.hex");
        let missing_ini = dir.join("missing.ini");

        let args = Args {
            ini_file: Some(missing_ini),
            ..Args::default()
        };
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01])]);
        let provider = FsProvider;
        let result = write_ford_ihex_output(&args, &hexfile, &output, &provider);
        assert!(result.is_ok(), "{result:?}");
        let text = fs::read_to_string(&output).unwrap();
        assert!(text.contains("FILE NAME>ford.hex"));
        assert!(text.contains(":00000001FF"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_write_porsche_output_appends_checksum() {
        let dir = unique_temp_dir();
        let output = dir.join("porsche.bin");
        let args = Args {
            align_fill: 0xFF,
            ..Args::default()
        };
        let hexfile = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02]),
            Segment::new(0x1004, vec![0x03]),
        ]);

        write_porsche_output(&args, &hexfile, &output).unwrap();
        let data = fs::read(&output).unwrap();
        // data: 0x01,0x02,0xFF,0xFF,0x03 then checksum
        assert_eq!(&data[..5], &[0x01, 0x02, 0xFF, 0xFF, 0x03]);
        let checksum = u16::from_be_bytes([data[5], data[6]]);
        assert_eq!(checksum, 0x01 + 0x02 + 0xFF + 0xFF + 0x03);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_resolve_default_paths_from_i16_input() {
        let input = PathBuf::from("input.hex");
        let args = Args {
            import_i16: Some(input.clone()),
            ..Args::default()
        };

        assert_eq!(
            resolve_c_code_output_path(&args).unwrap(),
            input.with_extension("c")
        );
        assert_eq!(
            resolve_ford_output_path(&args).unwrap(),
            input.with_extension("hex")
        );
        assert_eq!(
            resolve_porsche_output_path(&args).unwrap(),
            input.with_extension("bin")
        );
        assert_eq!(
            resolve_ini_path(&args).unwrap(),
            input.with_extension("ini")
        );
    }
}

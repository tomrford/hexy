//! Exports: the `/X...` formats and the INI files that configure them.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hexy_core::HexFile;

use super::error::CliError;
use super::ini::add_ini_keys;
use super::io::{ReadProvider, checksum_options, load_ini_or_empty};
use super::parse_util::parse_lenient_number;
use super::report::Report;
use super::types::{Args, OutputFormat};

/// Export to `-o`, or to the input file name with the format's suffix. Without an
/// export flag nothing is written.
pub(super) fn write_output_for_args(
    args: &Args,
    hexfile: &HexFile,
    provider: &impl ReadProvider,
    report: &Report,
) -> Result<(), CliError> {
    let Some(format) = &args.output_format else {
        return Ok(());
    };
    let path = match &args.output_file {
        Some(path) => path.clone(),
        None => {
            let input = primary_input(args).ok_or_else(|| {
                CliError::Other("export without a primary input requires -o".into())
            })?;
            let mut name = input.with_extension("").into_os_string();
            name.push(format.default_suffix());
            PathBuf::from(name)
        }
    };
    match format {
        OutputFormat::IntelHex(options) => hexfile.write_intel_hex_file(&path, options)?,
        OutputFormat::SRecord(options) => hexfile.write_srec_file(&path, options)?,
        OutputFormat::Binary => hexfile.write_binary_file(&path, &Default::default())?,
        OutputFormat::HexAscii(options) => hexfile.write_hex_ascii_file(&path, options)?,
        OutputFormat::SeparateBinary => write_separate_binary(hexfile, &path)?,
        OutputFormat::CCode => write_c_code_output(args, hexfile, &path, provider)?,
        OutputFormat::FordIntelHex => {
            write_ford_ihex_output(args, hexfile, &path, provider, report)?;
        }
        OutputFormat::FlashKernel => write_flash_kernel_output(args, hexfile, &path, provider)?,
        // HexView writes no file for an empty image.
        OutputFormat::GacSwil if hexfile.segments().is_empty() => {}
        OutputFormat::GacSwil => std::fs::write(&path, crate::write_gac_swil(hexfile)?)?,
        OutputFormat::Porsche => write_porsche_output(args, hexfile, &path, provider)?,
    }
    Ok(())
}

/// `.c` and `.h` files named after `path`, configured by `[C_EXPORT]` as HexView reads
/// it: `Prefix` (default empty), `WordSize` 0-2, `WordType` (non-zero is Motorola),
/// `Decryption` (default on) and `Decryptvalue`.
fn write_c_code_output(
    args: &Args,
    hexfile: &HexFile,
    path: &Path,
    provider: &impl ReadProvider,
) -> Result<(), CliError> {
    let ini = load_export_ini(args, provider, "C_EXPORT")?;
    let number = |key: &str, default| {
        ini.get(key)
            .map_or(default, |value| parse_lenient_number(value))
    };
    let word_size = match number("wordsize", 0) {
        0 => crate::CCodeWordSize::Byte,
        1 => crate::CCodeWordSize::Word,
        2 => crate::CCodeWordSize::Long,
        other => {
            return Err(CliError::Other(format!(
                "/XC: unsupported WordSize {other}"
            )));
        }
    };
    // HexView names the files after the input's full path when there is no -o.
    let path = if args.output_file.is_none() {
        std::path::absolute(path)?
    } else {
        path.to_path_buf()
    };
    let (c_path, h_path) = (path.with_extension("c"), path.with_extension("h"));
    let now = chrono::Local::now();
    let options = crate::CCodeWriteOptions {
        prefix: ini.get("prefix").cloned().unwrap_or_default(),
        word_size,
        word_type: if number("wordtype", 0) == 0 {
            crate::CCodeWordType::Intel
        } else {
            crate::CCodeWordType::Motorola
        },
        decrypt_value: (number("decryption", 1) != 0).then(|| number("decryptvalue", 0)),
        file_name: c_path.to_string_lossy().into_owned(),
        created: now.format("%a %b %e %H:%M:%S %Y").to_string(),
        // The first C runtime rand() after seeding it with the time, as HexView draws it.
        generation: ((now.timestamp() as u32)
            .wrapping_mul(214_013)
            .wrapping_add(2_531_011)
            >> 16)
            & 0x7FFF,
    };
    let output = crate::write_c_code(hexfile, &options);
    std::fs::write(c_path, output.c)?;
    std::fs::write(h_path, output.h)?;
    Ok(())
}

/// A CCP/XCP flash kernel configured by `[FLASH_KERNEL_CONFIG]`. Values missing from
/// it take the block's defaults, and HexView writes the name, comment and RAM values
/// it used back to the INI file. `FLASH_KERNEL_RAM_START=@file.map:pattern` scans the
/// map file for the first line `pattern` reads a `%lx` address from.
fn write_flash_kernel_output(
    args: &Args,
    hexfile: &HexFile,
    path: &Path,
    provider: &impl ReadProvider,
) -> Result<(), CliError> {
    const SECTION: &str = "FLASH_KERNEL_CONFIG";
    let blocks = hexfile.blocks();
    let [block] = blocks.as_slice() else {
        return Err(CliError::Other(format!(
            "/XK: the flash kernel has {} blocks; use /FA to make it one",
            blocks.len()
        )));
    };
    let ini = load_export_ini(args, provider, SECTION)?;
    let file_name = path.file_name().unwrap_or_default().to_string_lossy();
    let defaults = crate::FlashKernelHeader::new(
        ini.get("flash_kernel_name")
            .map_or(&*file_name, String::as_str),
        block,
    );
    let value = |key: &str, default: &String| ini.get(key).unwrap_or(default).clone();
    let header = crate::FlashKernelHeader {
        comment: value("flash_kernel_comment", &defaults.comment),
        file_address: value("flash_kernel_file_addr", &defaults.file_address),
        size: value("flash_kernel_size", &defaults.size),
        ram_address: value("flash_kernel_ram_addr", &defaults.ram_address),
        ram_start: value("flash_kernel_ram_start", &defaults.ram_start),
        ..defaults
    };
    let missing: Vec<(&str, &str)> = [
        ("FLASH_KERNEL_NAME", &header.name),
        ("FLASH_KERNEL_COMMENT", &header.comment),
        ("FLASH_KERNEL_RAM_ADDR", &header.ram_address),
        ("FLASH_KERNEL_RAM_START", &header.ram_start),
    ]
    .into_iter()
    .filter(|(key, _)| !ini.contains_key(&key.to_ascii_lowercase()))
    .map(|(key, value)| (key, value.as_str()))
    .collect();
    if let Some(ini_path) = ini_path(args).filter(|_| !missing.is_empty()) {
        add_ini_keys(&ini_path, SECTION, &missing)?;
    }
    let header = crate::FlashKernelHeader {
        ram_start: map_address(&header.ram_start, provider).unwrap_or(header.ram_start),
        ..header
    };
    std::fs::write(path, crate::write_flash_kernel(hexfile, &header)?)?;
    Ok(())
}

/// The address `@file.map:pattern` finds: the first map line from which `pattern`, read
/// like C's `sscanf`, converts its `%lx`.
fn map_address(value: &str, provider: &impl ReadProvider) -> Option<String> {
    let reference = value.strip_prefix('@')?;
    let drive = if reference.as_bytes().get(1) == Some(&b':') {
        2
    } else {
        0
    };
    let split = drive + reference[drive..].find(':')?;
    let map = provider.read_bytes(Path::new(&reference[..split])).ok()?;
    let pattern = &reference[split + 1..];
    String::from_utf8_lossy(&map)
        .lines()
        .find_map(|line| scan_hex(pattern, line))
        .map(|address| format!("0x{address:X}"))
}

/// The value `sscanf(line, pattern, &value)` converts for the pattern's `%lx` or `%x`:
/// blanks in the pattern match any run of blanks, other characters match themselves.
fn scan_hex(mut pattern: &str, mut line: &str) -> Option<u32> {
    loop {
        if pattern.starts_with("%lx") || pattern.starts_with("%x") {
            let text = line.trim_start();
            let text = text
                .strip_prefix("0x")
                .or_else(|| text.strip_prefix("0X"))
                .unwrap_or(text);
            let end = text
                .find(|c: char| !c.is_ascii_hexdigit())
                .unwrap_or(text.len());
            return u32::from_str_radix(&text[..end], 16).ok();
        }
        let c = pattern.chars().next()?;
        if c.is_whitespace() {
            pattern = pattern.trim_start();
            line = line.trim_start();
        } else {
            line = line.strip_prefix(c)?;
            pattern = &pattern[c.len_utf8()..];
        }
    }
}

/// Ford Intel HEX configured by `[FORDHEADER]`, as HexView writes it: missing optional
/// fields leave out their line, and a missing mandatory field stops the file with a
/// warning.
fn write_ford_ihex_output(
    args: &Args,
    hexfile: &HexFile,
    path: &Path,
    provider: &impl ReadProvider,
    report: &Report,
) -> Result<(), CliError> {
    let ini = load_export_ini(args, provider, "FORDHEADER")?;
    let text = |key: &str| ini.get(key).filter(|value| !value.is_empty()).cloned();
    let header = crate::FordHeader {
        application: text("application"),
        mask_number: text("mask number"),
        file_name: text("file name").unwrap_or_else(|| {
            path.file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned()
        }),
        release_date: text("release date").unwrap_or_else(release_date),
        module_type: text("module type"),
        part_number: text("production module part number"),
        wers_notice: text("wers notice"),
        comments: text("comments"),
        released_by: text("released by"),
        module_name: text("module name"),
        module_id: text("module id"),
        download_format: text("download format").unwrap_or_else(|| "0x01".to_owned()),
        flash_indicator: text("flash indicator").unwrap_or_else(|| "1".to_owned()),
        erase_sectors: text("flash erase sectors"),
        erase_alignment: args.align_erase.unwrap_or(0),
    };
    if let Some(field) = header.missing_field() {
        report.warn(&format!(
            "/XF: mandatory header field \"{field}\" is missing; the file ends there"
        ));
    }
    std::fs::write(path, crate::write_ford_intel_hex(hexfile, &header)?)?;
    Ok(())
}

/// The image as one region, gaps filled with the `/AF` byte, followed by the checksum
/// of the first `/CS` method over it, big-endian and without its ranges. Without a
/// usable method HexView writes the data alone and fails.
fn write_porsche_output(
    args: &Args,
    hexfile: &HexFile,
    output_path: &Path,
    provider: &impl ReadProvider,
) -> Result<(), CliError> {
    let region = HexFile::with_segments(
        hexfile
            .as_contiguous(args.align_fill, crate::DEFAULT_DENSE_SPAN_LIMIT)
            .map_err(|e| CliError::Other(format!("/XP: {e}")))?
            .into_iter()
            .collect(),
    );
    let checksum = args
        .checksum
        .iter()
        .chain(&args.checksum_multi)
        .next()
        .ok_or_else(|| CliError::Other("/XP: no /CS method for the appended checksum".into()))
        .and_then(|params| {
            let flag = format!("/XP /CS{}", params.algorithm);
            let options = crate::ChecksumOptions {
                range: None,
                little_endian_output: false,
                forced_range: None,
                exclude_ranges: Vec::new(),
                ..checksum_options(params, provider)
                    .map_err(|e| CliError::Other(format!("{flag}: {e}")))?
            };
            region
                .calculate_checksum(&options)
                .map_err(|e| CliError::Other(format!("{flag}: {e}")))
        });
    let mut output = region
        .into_segments()
        .pop()
        .map(|segment| segment.into_parts().1)
        .unwrap_or_default();
    if let Ok(checksum) = &checksum {
        output.extend_from_slice(checksum);
    }
    std::fs::write(output_path, output)?;
    checksum.map(drop)
}

fn primary_input(args: &Args) -> Option<&Path> {
    args.input_file
        .as_deref()
        .or(args.import.as_ref().map(|import| import.file.as_path()))
}

/// The INI file of an export: `/P`, or the input file (or import) with `.ini`.
fn ini_path(args: &Args) -> Option<PathBuf> {
    args.ini_file
        .clone()
        .or_else(|| primary_input(args).map(|input| input.with_extension("ini")))
}

/// `section` of the export INI file; empty without one.
fn load_export_ini(
    args: &Args,
    provider: &impl ReadProvider,
    section: &str,
) -> Result<HashMap<String, String>, CliError> {
    ini_path(args).map_or_else(
        || Ok(HashMap::new()),
        |path| load_ini_or_empty(&path, provider, Some(section)),
    )
}

/// Today's local date, as HexView writes a missing `RELEASE DATE`.
fn release_date() -> String {
    chrono::Local::now().format("%m/%d/%Y").to_string()
}

/// One binary per block, named `<stem>_<start address>` plus the output extension.
fn write_separate_binary(hexfile: &HexFile, path: &Path) -> Result<(), CliError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path.file_stem().unwrap_or_default().to_string_lossy();
    let ext = path
        .extension()
        .map(|ext| format!(".{}", ext.to_string_lossy()))
        .unwrap_or_default();
    for block in hexfile.blocks() {
        let (start_address, data) = block.into_parts();
        std::fs::write(dir.join(format!("{stem}_{start_address:x}{ext}")), data)?;
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
    fn test_write_separate_binary_writes_blocks() -> Result<(), CliError> {
        let dir = unique_temp_dir();
        let hexfile = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x00, 0x01, 0x02, 0x03]).unwrap(),
            Segment::new(0x1004, vec![0x04, 0x05, 0x06, 0x07]).unwrap(),
            Segment::new(0x2000, vec![0x10, 0x11, 0x12, 0x13]).unwrap(),
            Segment::new(0x2002, vec![0xAA, 0xBB]).unwrap(),
        ]);

        write_separate_binary(&hexfile, &dir.join("out"))?;

        assert_eq!(fs::read(dir.join("out_1000"))?, [0x00, 0x01, 0x02, 0x03]);
        assert_eq!(fs::read(dir.join("out_1004"))?, [0x04, 0x05, 0x06, 0x07]);
        assert_eq!(fs::read(dir.join("out_2000"))?, [0x10, 0x11, 0xAA, 0xBB]);
        assert!(!dir.join("out_2002").exists());

        fs::remove_dir_all(dir)?;
        Ok(())
    }
}

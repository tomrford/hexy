use std::path::Path;

use thiserror::Error;

use crate::HexFile;

use super::{
    BinaryWriteOptions, HexAsciiWriteOptions, IntelHexWriteOptions, ParseError,
    SRecordWriteOptions, parse_binary, parse_intel_hex, parse_srec, write_binary, write_hex_ascii,
    write_intel_hex, write_srec,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoFormat {
    IntelHex,
    SRecord,
    Binary,
}

#[derive(Debug, Error)]
pub enum FileIoError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Parse(#[from] ParseError),
}

pub fn detect_format(data: &[u8]) -> AutoFormat {
    let mut lines_checked = 0usize;

    for mut line in data.split(|&b| b == b'\n') {
        if let Some(stripped) = line.strip_suffix(b"\r") {
            line = stripped;
        }
        let Some(first) = line.iter().copied().find(|b| !b.is_ascii_whitespace()) else {
            continue;
        };

        if lines_checked >= 25 {
            break;
        }
        if !line.is_ascii() {
            return AutoFormat::Binary;
        }
        lines_checked += 1;

        match first {
            b':' => return AutoFormat::IntelHex,
            b'S' | b's' if lines_checked == 1 => return AutoFormat::SRecord,
            _ => {}
        }
    }

    AutoFormat::Binary
}

pub fn parse_auto(data: &[u8]) -> Result<HexFile, ParseError> {
    match detect_format(data) {
        AutoFormat::IntelHex => parse_intel_hex(data),
        AutoFormat::SRecord => parse_srec(data),
        AutoFormat::Binary => parse_binary(data, 0),
    }
}

impl HexFile {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, FileIoError> {
        let data = std::fs::read(path)?;
        Ok(Self::from_file_bytes(&data)?)
    }

    pub fn from_file_bytes(data: &[u8]) -> Result<Self, ParseError> {
        parse_auto(data)
    }

    pub fn write_binary_file(
        &self,
        path: impl AsRef<Path>,
        options: &BinaryWriteOptions,
    ) -> Result<(), FileIoError> {
        std::fs::write(path, write_binary(self, options))?;
        Ok(())
    }

    pub fn write_intel_hex_file(
        &self,
        path: impl AsRef<Path>,
        options: &IntelHexWriteOptions,
    ) -> Result<(), FileIoError> {
        std::fs::write(path, write_intel_hex(self, options))?;
        Ok(())
    }

    pub fn write_srec_file(
        &self,
        path: impl AsRef<Path>,
        options: &SRecordWriteOptions,
    ) -> Result<(), FileIoError> {
        std::fs::write(path, write_srec(self, options)?)?;
        Ok(())
    }

    pub fn write_hex_ascii_file(
        &self,
        path: impl AsRef<Path>,
        options: &HexAsciiWriteOptions,
    ) -> Result<(), FileIoError> {
        std::fs::write(path, write_hex_ascii(self, options))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    #[test]
    fn test_detect_format_matches_compat_inputs() {
        assert_eq!(detect_format(b":00000001FF\r\n"), AutoFormat::IntelHex);
        assert_eq!(detect_format(b"S9030000FC\n"), AutoFormat::SRecord);
        assert_eq!(detect_format(b"\x00\xff\x01"), AutoFormat::Binary);
        assert_eq!(detect_format(b"plain ascii"), AutoFormat::Binary);
    }

    #[test]
    fn test_parse_auto_intel_hex() -> Result<(), ParseError> {
        let hexfile = HexFile::from_file_bytes(b":020000040001F9\n:02100000AABB89\n:00000001FF\n")?;
        assert_eq!(
            hexfile.read_bytes_contiguous(0x11000, 2),
            Some(vec![0xAA, 0xBB])
        );
        Ok(())
    }

    #[test]
    fn test_write_file_roundtrip() -> Result<(), FileIoError> {
        let dir = std::env::temp_dir().join(format!(
            "hexy_core_file_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(std::io::Error::other)?
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("out.hex");

        let hexfile = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xDE, 0xAD])]);
        hexfile.write_intel_hex_file(&path, &IntelHexWriteOptions::default())?;
        let parsed = HexFile::from_file(&path)?;
        assert_eq!(
            parsed.read_bytes_contiguous(0x1000, 2),
            Some(vec![0xDE, 0xAD])
        );

        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
}

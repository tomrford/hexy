use std::fmt::Write;

use super::{IntelHexWriteOptions, WriteError, write_intel_hex};
use crate::HexFile;

/// The `[FORDHEADER]` values of a Ford Intel HEX file. Absent optional fields leave out
/// their line; text is written as given.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FordHeader {
    pub application: Option<String>,
    pub mask_number: Option<String>,
    pub file_name: String,
    pub release_date: String,
    pub module_type: Option<String>,
    /// Mandatory: without it the file stops after `MODULE TYPE`.
    pub part_number: Option<String>,
    pub wers_notice: Option<String>,
    pub comments: Option<String>,
    pub released_by: Option<String>,
    pub module_name: Option<String>,
    /// Mandatory: without it the file stops after `MODULE NAME`.
    pub module_id: Option<String>,
    /// HexView's default is `0x01`.
    pub download_format: String,
    /// HexView's default is `1`.
    pub flash_indicator: String,
    /// `None` lists the blocks, widened to `erase_alignment`.
    pub erase_sectors: Option<String>,
    /// Erase sectors cover the bits of `erase_alignment - 1` around each block, and
    /// sectors that touch are joined; 0 lists the blocks as they are.
    pub erase_alignment: u32,
}

impl FordHeader {
    /// The mandatory header line this header lacks, if any.
    pub fn missing_field(&self) -> Option<&'static str> {
        if self.part_number.is_none() {
            Some("PRODUCTION MODULE PART NUMBER")
        } else if self.module_id.is_none() {
            Some("MODULE ID")
        } else {
            None
        }
    }
}

/// Write a Ford Intel HEX file: the `>`-separated header, `$`, then the data as Intel
/// HEX. As in HexView, a header without a mandatory field ([`FordHeader::missing_field`])
/// stops before it and the file holds no data. `FILE CHECKSUM` is the 16-bit sum of the
/// data bytes. CLI: /XF.
pub fn write_ford_intel_hex(hexfile: &HexFile, header: &FordHeader) -> Result<Vec<u8>, WriteError> {
    let mut text = String::new();
    let mut line = |key: &str, value: Option<&str>| {
        if let Some(value) = value {
            let _ = write!(text, "{key}>{value}\r\n");
        }
    };
    line("APPLICATION", header.application.as_deref());
    line("MASK NUMBER", header.mask_number.as_deref());
    line("FILE NAME", Some(&header.file_name));
    line("RELEASE DATE", Some(&header.release_date));
    line("MODULE TYPE", header.module_type.as_deref());
    let complete = header.missing_field().is_none();
    if header.part_number.is_some() {
        line(
            "PRODUCTION MODULE PART NUMBER",
            header.part_number.as_deref(),
        );
        line("WERS NOTICE", header.wers_notice.as_deref());
        line("COMMENTS", header.comments.as_deref());
        line("RELEASED BY", header.released_by.as_deref());
        line("MODULE NAME", header.module_name.as_deref());
    }
    if complete {
        let checksum = hexfile
            .normalized()
            .segments()
            .iter()
            .flat_map(|segment| segment.data())
            .fold(0u16, |sum, &byte| sum.wrapping_add(u16::from(byte)));
        let erase_sectors = header
            .erase_sectors
            .clone()
            .unwrap_or_else(|| erase_sectors(hexfile, header.erase_alignment));
        line("MODULE ID", header.module_id.as_deref());
        line("DOWNLOAD FORMAT", Some(&header.download_format));
        line("FILE CHECKSUM", Some(&format!("0x{checksum:04X}")));
        line("FLASH INDICATOR", Some(&header.flash_indicator));
        line("FLASH ERASE SECTORS", Some(&erase_sectors));
        text.push_str("$\r\n");
    }
    let data = if complete { hexfile } else { &HexFile::new() };
    let mut out = text.into_bytes();
    out.extend(write_intel_hex(data, &IntelHexWriteOptions::default())?);
    Ok(out)
}

/// `:start,length` for every erase sector.
fn erase_sectors(hexfile: &HexFile, alignment: u32) -> String {
    let mask = u64::from(alignment.saturating_sub(1));
    let mut sectors: Vec<(u64, u64)> = Vec::new();
    for segment in hexfile.normalized().segments() {
        let start = u64::from(segment.start_address()) & !mask;
        let end = (u64::from(segment.end_address()) | mask).min(u64::from(u32::MAX));
        match sectors.last_mut() {
            Some((_, last_end)) if start <= *last_end + 1 => *last_end = (*last_end).max(end),
            _ => sectors.push((start, end)),
        }
    }
    sectors
        .iter()
        .map(|(start, end)| format!(":0x{start:X},0x{:X}", end - start + 1))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    fn complete() -> FordHeader {
        let text = |value: &str| Some(value.to_owned());
        FordHeader {
            application: text("A"),
            file_name: "o.hex".to_owned(),
            release_date: "X".to_owned(),
            part_number: text("P"),
            module_id: text("I"),
            download_format: "0x01".to_owned(),
            flash_indicator: "1".to_owned(),
            ..Default::default()
        }
    }

    fn image(blocks: &[(u32, usize)]) -> HexFile {
        HexFile::with_segments(
            blocks
                .iter()
                .map(|&(start, len)| Segment::new(start, vec![0xFF; len]).unwrap())
                .collect(),
        )
    }

    /// HexView 1.15.2 `/XF` with `/AE:0x1000` and `/AE:0x300`: sectors are widened with
    /// the bit mask and touching sectors are joined.
    #[test]
    fn test_erase_sectors_match_hexview() {
        let blocks = image(&[(0x10A00, 0x40), (0x10C00, 0x10), (0x13000, 4)]);
        assert_eq!(
            erase_sectors(&blocks, 0x1000),
            ":0x10000,0x1000:0x13000,0x1000"
        );
        let blocks = image(&[(0x10A00, 0x40), (0x12C00, 0x10)]);
        assert_eq!(
            erase_sectors(&blocks, 0x300),
            ":0x10800,0x300:0x12C00,0x300"
        );
        assert_eq!(erase_sectors(&blocks, 0), ":0x10A00,0x40:0x12C00,0x10");
    }

    /// HexView 1.15.2 `/XF` without `MODULE ID`: the header stops and no data follows.
    #[test]
    fn test_missing_mandatory_field_stops_the_file() {
        let header = FordHeader {
            module_name: Some("N".to_owned()),
            module_id: None,
            ..complete()
        };
        let out = write_ford_intel_hex(&image(&[(0x10000, 0x200)]), &header).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out),
            "APPLICATION>A\r\nFILE NAME>o.hex\r\nRELEASE DATE>X\r\nPRODUCTION MODULE PART NUMBER>P\r\nMODULE NAME>N\r\n:00000001FF\r\n"
        );
        let out = write_ford_intel_hex(&image(&[(0x10000, 0x200)]), &complete()).unwrap();
        assert!(String::from_utf8_lossy(&out).contains("MODULE ID>I\r\nDOWNLOAD FORMAT>0x01\r\nFILE CHECKSUM>0xFE00\r\nFLASH INDICATOR>1\r\nFLASH ERASE SECTORS>:0x10000,0x200\r\n$\r\n:020000021000EC\r\n"));
    }
}

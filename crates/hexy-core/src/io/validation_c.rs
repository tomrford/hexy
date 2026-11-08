//! The `.c` and `.h` files of a validation structure (`/vs`).

use std::fmt::Write;

use chrono::{DateTime, FixedOffset};

use super::c_code::banner;
use crate::{ValidationOptions, ValidationStructure};

/// Names and values of the C files of a validation structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationCOptions {
    /// The `.c` file name in its header comment.
    pub c_file_name: String,
    /// The `.h` file name in its header comment; the `.c` file includes its file name.
    pub h_file_name: String,
    /// When the files were created, written in its local time.
    pub created: DateTime<FixedOffset>,
    /// The tag values HexView writes in the `.c` file: C's reading of the tag text,
    /// which need not match the tag bytes.
    pub tag_begin_value: u32,
    pub tag_end_value: u32,
}

/// The `.c` and `.h` files HexView writes for a validation structure: `ValidateInfo` as
/// a `tValidateInfo` initializer and the struct definitions. Without `structure`'s
/// validate sum the field is left out.
pub fn write_validation_c(
    options: &ValidationOptions,
    structure: &ValidationStructure,
    names: &ValidationCOptions,
) -> (Vec<u8>, Vec<u8>) {
    let h_name = names
        .h_file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&names.h_file_name);
    let (word, word_suffix) = if structure.wide {
        ("unsigned long ", "ul")
    } else {
        ("unsigned short", "u")
    };
    let scalar = |len: usize| match len {
        1 => Some("unsigned char "),
        2 => Some("unsigned short"),
        4 => Some("unsigned long "),
        _ => None,
    };
    let field = |len: usize, name: &str| match scalar(len) {
        Some(ty) => format!("\t{ty} {name};\r\n"),
        None => format!("\tunsigned char  {name}[{len}];\r\n"),
    };
    let tag_suffix = |len: usize| if len == 4 { "ul" } else { "u" };
    let tag_value = |value: u32, len: usize| {
        if scalar(len).is_some() {
            return format!("0x{value:X}{}", tag_suffix(len));
        }
        let bytes = value.to_be_bytes();
        let elements: Vec<String> = (0..len)
            .map(|index| {
                let remaining = len - index;
                let byte = if remaining <= bytes.len() {
                    bytes[bytes.len() - remaining]
                } else {
                    0
                };
                format!("0x{byte:02X}")
            })
            .collect();
        format!("{{{}}}", elements.join(", "))
    };
    let count_bytes = if structure.wide && !options.one_byte_count {
        2
    } else {
        1
    };

    let mut c = banner(
        &names.c_file_name,
        "C-File for validation structure",
        names.created,
    );
    let _ = write!(
        c,
        "#include \"{h_name}\"\r\n\r\n#define VALIDATEINFO_START_SEC_CONST\r\n#include \"memmap.h\"\r\n\r\nconst tValidateInfo ValidateInfo = {{\r\n"
    );
    // An empty tag has no field.
    if !options.tag_begin.is_empty() {
        let _ = write!(
            c,
            "\t{},\t\t/* Magic Tag begin */\r\n",
            tag_value(names.tag_begin_value, options.tag_begin.len())
        );
    }
    let mut needs_comma = false;
    if !structure.blocks.is_empty() {
        let _ = write!(
            c,
            "\t{}\t\t/* Number of block elements */\r\n",
            structure.blocks.len()
        );
        needs_comma = true;
    }
    if options.alfi && !structure.blocks.is_empty() {
        let size = if structure.wide { 4 } else { 2 };
        let _ = write!(
            c,
            "\t,0x{:X}\t\t/* address-length identifier (ALFI) */\r\n",
            size << 4 | size
        );
    }
    for block in &structure.blocks {
        let _ = write!(
            c,
            "\t,0x{:X}{word_suffix}, 0x{:X}{word_suffix}",
            block.address, block.length
        );
        if let Some(checksum) = &block.checksum {
            if scalar(checksum.len()).is_some() {
                let _ = write!(c, ", 0x{}", hex(checksum));
            } else {
                for byte in checksum {
                    let _ = write!(c, ", 0x{byte:02X}");
                }
            }
        }
        c.push_str("\r\n");
    }
    if let Some(checksum) = &structure.file_checksum
        && !checksum.is_empty()
    {
        let separator = if needs_comma { "," } else { "" };
        match checksum.len() {
            len @ (1 | 2 | 4) => {
                let _ = write!(
                    c,
                    "\t{separator}0x{}{}\t\t/* Total file checksum*/\r\n",
                    hex(checksum),
                    if len == 4 { "ul" } else { "u" }
                );
            }
            _ => {
                let list: Vec<String> = checksum.iter().map(|b| format!("0x{b:02X}")).collect();
                let _ = write!(
                    c,
                    "\t{separator}{}\t/* Total file checksum */\r\n",
                    list.join(", ")
                );
            }
        }
        needs_comma = true;
    }
    if !options.tag_end.is_empty() {
        let separator = if needs_comma { "," } else { "" };
        let _ = write!(
            c,
            "\t{separator}{}\t\t/* Magic Tag end */\r\n",
            tag_value(names.tag_end_value, options.tag_end.len())
        );
        needs_comma = true;
    }
    match structure.validate_sum {
        Some(sum) => {
            let separator = if needs_comma { "," } else { "" };
            let _ = write!(
                c,
                "\t{separator}0x{sum:X}u\t/* 16-bit byte-sum on validation area. */}};\r\n"
            );
        }
        None => c.push_str("};\r\n"),
    }
    c.push_str("\r\n#define VALIDATEINFO_STOP_SEC_CONST\r\n#include \"memmap.h\"\r\n");

    let guard = match h_name.rsplit_once('.') {
        Some((stem, ext)) => format!("{stem}_{ext}"),
        None => h_name.to_owned(),
    }
    .to_uppercase();
    let mut h = banner(
        &names.h_file_name,
        "Header-File for validation structure",
        names.created,
    );
    let _ = write!(
        h,
        "#ifndef __{guard}__\r\n#define __{guard}__\r\n\r\n/* Structure describing a single block info */\r\ntypedef struct tVsBlockInfo {{\r\n\t{word} blockAddress;\r\n\t{word} blockLength;\r\n"
    );
    let block_checksum_len = structure
        .blocks
        .first()
        .and_then(|block| block.checksum.as_ref())
        .map(Vec::len);
    if let Some(len) =
        block_checksum_len.or_else(|| options.block_checksum.as_ref().map(|a| a.result_size()))
    {
        h.push_str(&field(len, "blockChecksum"));
    }
    h.push_str("} tVsBlockInfo;\r\n\r\ntypedef struct tValidateInfo {\r\n");
    if !options.tag_begin.is_empty() {
        h.push_str(&field(options.tag_begin.len(), "tagBegin"));
    }
    if !structure.blocks.is_empty() {
        h.push_str(&field(count_bytes, "blockCount"));
        if options.alfi {
            h.push_str(&field(1, "alfi"));
        }
        let _ = write!(
            h,
            "\ttVsBlockInfo   blockInfo[{}];\r\n",
            structure.blocks.len()
        );
    }
    if let Some(checksum) = &structure.file_checksum {
        h.push_str(&field(checksum.len(), "fileChecksum"));
    }
    if !options.tag_end.is_empty() {
        h.push_str(&field(options.tag_end.len(), "tagEnd"));
    }
    if structure.validate_sum.is_some() {
        h.push_str(&field(2, "validateSum"));
    }
    h.push_str("} tValidateInfo;\r\n\r\n/* Extern definition of the data generated structure */\r\n#define VALIDATEINFO_START_SEC_CONST_EXPORT\r\n#include \"memmap.h\"\r\n\r\nextern const tValidateInfo ValidateInfo;\r\n\r\n#define VALIDATEINFO_STOP_SEC_CONST_EXPORT\r\n#include \"memmap.h\"\r\n\r\n\r\n#endif\r\n\r\n");
    (c.into_bytes(), h.into_bytes())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChecksumAlgorithm, HexFile, Segment};

    /// HexView 1.15.2 `/vs` with the manual's `[VALIDATION]` example.
    #[test]
    fn test_validation_c_matches_hexview() {
        let pattern = |n: usize, seed: u8| (0..n).map(|i| seed.wrapping_add(7 * i as u8)).collect();
        let image = HexFile::with_segments(vec![
            Segment::new(0x1000, pattern(0x13, 1)).unwrap(),
            Segment::new(0x2000, pattern(0x20, 2)).unwrap(),
        ]);
        let options = ValidationOptions {
            tag_begin: vec![0x12, 0x34],
            tag_end: vec![0x43, 0x21],
            block_checksum: Some(ChecksumAlgorithm::ByteSumBe),
            file_checksum: Some(ChecksumAlgorithm::Crc32),
            validate_sum: true,
            ..Default::default()
        };
        let structure = image.validation_structure(&options).unwrap();
        let (c, h) = write_validation_c(
            &options,
            &structure,
            &ValidationCOptions {
                c_file_name: "v.c".to_owned(),
                h_file_name: "v.h".to_owned(),
                created: DateTime::parse_from_rfc3339("2026-11-07T22:36:43+01:00").unwrap(),
                tag_begin_value: 0x1234,
                tag_end_value: 0x4321,
            },
        );
        assert!(String::from_utf8_lossy(&c).ends_with("const tValidateInfo ValidateInfo = {\r\n\t0x1234u,\t\t/* Magic Tag begin */\r\n\t2\t\t/* Number of block elements */\r\n\t,0x1000u, 0x13u, 0x04C0\r\n\t,0x2000u, 0x20u, 0x0DD0\r\n\t,0xBA9FF711ul\t\t/* Total file checksum*/\r\n\t,0x4321u\t\t/* Magic Tag end */\r\n\t,0x511u\t/* 16-bit byte-sum on validation area. */};\r\n\r\n#define VALIDATEINFO_STOP_SEC_CONST\r\n#include \"memmap.h\"\r\n"));
        assert!(String::from_utf8_lossy(&h).contains("#ifndef __V_H__\r\n#define __V_H__\r\n\r\n/* Structure describing a single block info */\r\ntypedef struct tVsBlockInfo {\r\n\tunsigned short blockAddress;\r\n\tunsigned short blockLength;\r\n\tunsigned short blockChecksum;\r\n} tVsBlockInfo;\r\n\r\ntypedef struct tValidateInfo {\r\n\tunsigned short tagBegin;\r\n\tunsigned char  blockCount;\r\n\ttVsBlockInfo   blockInfo[2];\r\n\tunsigned long  fileChecksum;\r\n\tunsigned short tagEnd;\r\n\tunsigned short validateSum;\r\n} tValidateInfo;\r\n"));
    }
}

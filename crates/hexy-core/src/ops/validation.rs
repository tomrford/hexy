//! HexView's validation structures: `/vs`, an address and length list of the blocks
//! with optional checksums framed by magic tags, and `/vshsm`, the list of block
//! hashes that Vector's vHSM checks at secure boot.

use std::fmt::Write;

use super::OpsError;
use crate::{AddressRange, ChecksumAlgorithm, ChecksumOptions, HexFile};

/// What the validation structure holds and how it is encoded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationOptions {
    /// Written first, as given.
    pub tag_begin: Vec<u8>,
    /// Written after the checksums, as given.
    pub tag_end: Vec<u8>,
    /// Checksum of each block's data, written after its address and length.
    pub block_checksum: Option<ChecksumAlgorithm>,
    /// Checksum of the data of all blocks.
    pub file_checksum: Option<ChecksumAlgorithm>,
    /// End with the 16-bit sum of all the structure's bytes, given at least one block.
    pub validate_sum: bool,
    /// Byte order of addresses, lengths, a 16-bit block count and the sum; checksums keep
    /// the order of the checksum method.
    pub big_endian: bool,
    /// 32-bit addresses and lengths even when every block fits 16 bits.
    pub force_32bit: bool,
    /// Write the address and length format identifier byte (`0x22` or `0x44`) after the
    /// count.
    pub alfi: bool,
    /// Keep the block count to one byte with 32-bit addresses.
    pub one_byte_count: bool,
    /// Address ranges left out of the blocks.
    pub spare: Vec<AddressRange>,
}

/// One block entry of a validation structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationBlock {
    pub address: u32,
    pub length: u32,
    pub checksum: Option<Vec<u8>>,
}

/// A validation structure and the parts it was built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationStructure {
    pub blocks: Vec<ValidationBlock>,
    pub file_checksum: Option<Vec<u8>>,
    /// Addresses and lengths take 32 bits: forced, or a block ends above `0xFFFF`.
    pub wide: bool,
    pub validate_sum: Option<u16>,
    /// The encoded structure.
    pub bytes: Vec<u8>,
}

impl HexFile {
    /// Build HexView's validation structure over the blocks of this image; an image of
    /// one byte has none. A 16-bit
    /// structure counts the blocks in one byte and a 32-bit one in two, unless
    /// `one_byte_count`.
    pub fn validation_structure(
        &self,
        options: &ValidationOptions,
    ) -> Result<ValidationStructure, OpsError> {
        let mut image = self.clone();
        image.cut_ranges(&options.spare);
        // HexView's data range needs an end above its start, so one byte of data counts
        // as none.
        let blocks = if self.min_address() == self.max_address() {
            Vec::new()
        } else {
            image.blocks()
        };
        let checksum = |algorithm: &ChecksumAlgorithm, image: HexFile| {
            image.calculate_checksum(&ChecksumOptions {
                algorithm: algorithm.clone(),
                ..Default::default()
            })
        };
        let entries = blocks
            .iter()
            .map(|block| {
                Ok(ValidationBlock {
                    address: block.start_address(),
                    length: block.len() as u32,
                    checksum: options
                        .block_checksum
                        .as_ref()
                        .map(|algorithm| {
                            checksum(algorithm, HexFile::with_segments(vec![block.clone()]))
                        })
                        .transpose()?,
                })
            })
            .collect::<Result<Vec<_>, OpsError>>()?;
        let file_checksum = options
            .file_checksum
            .as_ref()
            .map(|algorithm| checksum(algorithm, HexFile::with_segments(blocks.clone())))
            .transpose()?;
        let wide = options.force_32bit
            || blocks
                .iter()
                .any(|block| block.end_address() > 0xFFFF || block.len() > 0xFFFF);

        let mut bytes = options.tag_begin.clone();
        let word = |bytes: &mut Vec<u8>, value: u32, size: usize| {
            let be = value.to_be_bytes();
            let be = &be[4 - size..];
            if options.big_endian {
                bytes.extend_from_slice(be);
            } else {
                bytes.extend(be.iter().rev());
            }
        };
        let size = if wide { 4 } else { 2 };
        let count = entries.len() as u32;
        if wide && !options.one_byte_count {
            word(&mut bytes, count, 2);
        } else {
            bytes.push(count as u8);
        }
        if options.alfi {
            bytes.push((size as u8) << 4 | size as u8);
        }
        for entry in &entries {
            word(&mut bytes, entry.address, size);
            word(&mut bytes, entry.length, size);
            bytes.extend(entry.checksum.iter().flatten());
        }
        bytes.extend(file_checksum.iter().flatten());
        bytes.extend_from_slice(&options.tag_end);
        // HexView sums only a structure with blocks.
        let validate_sum = (options.validate_sum && !entries.is_empty()).then(|| {
            bytes
                .iter()
                .fold(0u16, |sum, &byte| sum.wrapping_add(u16::from(byte)))
        });
        if let Some(sum) = validate_sum {
            word(&mut bytes, u32::from(sum), 2);
        }
        Ok(ValidationStructure {
            blocks: entries,
            file_checksum,
            wide,
            validate_sum,
            bytes,
        })
    }
}

/// The vHSM validation structure's settings (`/vshsm`, `[HSMBOOT]`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HsmValidationOptions {
    pub group_id: u32,
    /// Boot mode of every segment: 0 none, 1 parallel, 2 sequential.
    pub mode: u16,
    /// Hash of each segment; HexView's default is SHA-256 (method 20).
    pub hash: ChecksumAlgorithm,
}

impl HexFile {
    /// Build the vHSM validation structure over the blocks of this image, big-endian:
    /// group ID (4 bytes), segment count (2), then per segment address (4), length (4),
    /// mode (2) and hash.
    pub fn hsm_validation_structure(
        &self,
        options: &HsmValidationOptions,
    ) -> Result<Vec<u8>, OpsError> {
        let blocks = self.blocks();
        let mut bytes = options.group_id.to_be_bytes().to_vec();
        bytes.extend((blocks.len() as u16).to_be_bytes());
        for block in &blocks {
            bytes.extend(block.start_address().to_be_bytes());
            bytes.extend((block.len() as u32).to_be_bytes());
            bytes.extend(options.mode.to_be_bytes());
            bytes.extend(
                HexFile::with_segments(vec![block.clone()]).calculate_checksum(
                    &ChecksumOptions {
                        algorithm: options.hash.clone(),
                        ..Default::default()
                    },
                )?,
            );
        }
        Ok(bytes)
    }
}

/// Names and values of the C files of a validation structure.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidationCOptions {
    /// The `.c` file name in its header comment.
    pub c_file_name: String,
    /// The `.h` file name in its header comment; the `.c` file includes its file name.
    pub h_file_name: String,
    /// `File created:` text, such as `Sat Nov  7 21:34:44 2026`.
    pub created: String,
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
    let count_bytes = if structure.wide && !options.one_byte_count {
        2
    } else {
        1
    };

    let mut c = banner(
        &names.c_file_name,
        "C-File for validation structure",
        &names.created,
    );
    let _ = write!(
        c,
        "#include \"{h_name}\"\r\n\r\n#define VALIDATEINFO_START_SEC_CONST\r\n#include \"memmap.h\"\r\n\r\nconst tValidateInfo ValidateInfo = {{\r\n"
    );
    // An empty tag has no field.
    if !options.tag_begin.is_empty() {
        let _ = write!(
            c,
            "\t0x{:X}{},\t\t/* Magic Tag begin */\r\n",
            names.tag_begin_value,
            tag_suffix(options.tag_begin.len())
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
            "\t{separator}0x{:X}{}\t\t/* Magic Tag end */\r\n",
            names.tag_end_value,
            tag_suffix(options.tag_end.len())
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
        &names.created,
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

fn banner(file_name: &str, project: &str, created: &str) -> String {
    let rule = "*".repeat(64);
    format!(
        "/{rule}\r\n*\r\n*  Filename:      {file_name}\r\n*  Project:       {project}\r\n*  File created:  {created}\r\n\r\n*\r\n{rule}/\r\n\r\n"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    fn image() -> HexFile {
        let pattern = |n: usize, seed: u8| (0..n).map(|i| seed.wrapping_add(7 * i as u8)).collect();
        HexFile::with_segments(vec![
            Segment::new(0x1000, pattern(0x13, 1)).unwrap(),
            Segment::new(0x2000, pattern(0x20, 2)).unwrap(),
        ])
    }

    fn options() -> ValidationOptions {
        ValidationOptions {
            tag_begin: vec![0x12, 0x34],
            tag_end: vec![0x43, 0x21],
            block_checksum: Some(ChecksumAlgorithm::ByteSumBe),
            file_checksum: Some(ChecksumAlgorithm::Crc32),
            validate_sum: true,
            ..Default::default()
        }
    }

    /// HexView 1.15.2 `/vs` with the manual's `[VALIDATION]` example.
    #[test]
    fn test_validation_structure_matches_hexview() {
        let structure = image().validation_structure(&options()).unwrap();
        assert_eq!(
            structure.bytes,
            [
                0x12, 0x34, 0x02, 0x00, 0x10, 0x13, 0x00, 0x04, 0xC0, 0x00, 0x20, 0x20, 0x00, 0x0D,
                0xD0, 0xBA, 0x9F, 0xF7, 0x11, 0x43, 0x21, 0x11, 0x05
            ]
        );
        let (c, h) = write_validation_c(
            &options(),
            &structure,
            &ValidationCOptions {
                c_file_name: "v.c".to_owned(),
                h_file_name: "v.h".to_owned(),
                created: "Sat Nov  7 22:36:43 2026".to_owned(),
                tag_begin_value: 0x1234,
                tag_end_value: 0x4321,
            },
        );
        assert!(String::from_utf8_lossy(&c).ends_with("const tValidateInfo ValidateInfo = {\r\n\t0x1234u,\t\t/* Magic Tag begin */\r\n\t2\t\t/* Number of block elements */\r\n\t,0x1000u, 0x13u, 0x04C0\r\n\t,0x2000u, 0x20u, 0x0DD0\r\n\t,0xBA9FF711ul\t\t/* Total file checksum*/\r\n\t,0x4321u\t\t/* Magic Tag end */\r\n\t,0x511u\t/* 16-bit byte-sum on validation area. */};\r\n\r\n#define VALIDATEINFO_STOP_SEC_CONST\r\n#include \"memmap.h\"\r\n"));
        assert!(String::from_utf8_lossy(&h).contains("#ifndef __V_H__\r\n#define __V_H__\r\n\r\n/* Structure describing a single block info */\r\ntypedef struct tVsBlockInfo {\r\n\tunsigned short blockAddress;\r\n\tunsigned short blockLength;\r\n\tunsigned short blockChecksum;\r\n} tVsBlockInfo;\r\n\r\ntypedef struct tValidateInfo {\r\n\tunsigned short tagBegin;\r\n\tunsigned char  blockCount;\r\n\ttVsBlockInfo   blockInfo[2];\r\n\tunsigned long  fileChecksum;\r\n\tunsigned short tagEnd;\r\n\tunsigned short validateSum;\r\n} tValidateInfo;\r\n"));
    }

    /// HexView 1.15.2 with `Force32BitFormat=1`, `WriteALFI=1` and `EndianType=1`.
    #[test]
    fn test_wide_big_endian_structure_matches_hexview() {
        let options = ValidationOptions {
            big_endian: true,
            force_32bit: true,
            alfi: true,
            ..options()
        };
        let structure = image().validation_structure(&options).unwrap();
        assert_eq!(
            structure.bytes,
            [
                0x12, 0x34, 0x00, 0x02, 0x44, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x13, 0x04,
                0xC0, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0D, 0xD0, 0xBA, 0x9F, 0xF7,
                0x11, 0x43, 0x21, 0x05, 0x55
            ]
        );
    }

    /// HexView 1.15.2 `/vshsm:@0x8000` with `GROUP_ID=0x1234`, `MODE=1` and
    /// `HASH_METHOD=9`.
    #[test]
    fn test_hsm_structure_matches_hexview() {
        let options = HsmValidationOptions {
            group_id: 0x1234,
            mode: 1,
            hash: ChecksumAlgorithm::Crc32,
        };
        assert_eq!(
            image().hsm_validation_structure(&options).unwrap(),
            [
                0x00, 0x00, 0x12, 0x34, 0x00, 0x02, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x13,
                0x00, 0x01, 0x10, 0x30, 0x80, 0xA3, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x20,
                0x00, 0x01, 0xAA, 0x35, 0xED, 0xB3
            ]
        );
    }
}

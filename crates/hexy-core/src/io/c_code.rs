use std::fmt::Write;

use chrono::{DateTime, FixedOffset};

use crate::HexFile;

/// Element width of the C arrays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CCodeWordSize {
    Byte,
    Word,
    Long,
}

impl CCodeWordSize {
    fn bytes(self) -> usize {
        match self {
            Self::Byte => 1,
            Self::Word => 2,
            Self::Long => 4,
        }
    }

    fn c_type(self) -> &'static str {
        match self {
            Self::Byte => "vuint8",
            Self::Word => "vuint16",
            Self::Long => "vuint32",
        }
    }

    /// Integer suffix of array elements and the XOR value.
    fn suffix(self) -> &'static str {
        match self {
            Self::Byte => "",
            Self::Word => "u",
            Self::Long => "ul",
        }
    }

    fn mask(self) -> u32 {
        u32::MAX >> (32 - 8 * self.bytes())
    }
}

/// Byte order of 16- and 32-bit elements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CCodeWordType {
    Intel,
    Motorola,
}

/// Options for [`write_c_code`].
#[derive(Debug, Clone)]
pub struct CCodeWriteOptions {
    /// Array name prefix; its upper-case form prefixes the macros.
    pub prefix: String,
    pub word_size: CCodeWordSize,
    pub word_type: CCodeWordType,
    /// XOR value applied to every element; `None` writes the data as it is.
    pub decrypt_value: Option<u32>,
    /// The `.c` file name in its header comment; the `.h` name replaces its extension.
    pub file_name: String,
    /// When the files were created, written in its local time. `<PREFIX>_GEN_RAND`, the
    /// number that ties the two files together, is drawn from it as HexView draws it.
    pub created: DateTime<FixedOffset>,
}

/// The `.c` and `.h` files of a C-array export.
#[derive(Debug, Clone)]
pub struct CCodeOutput {
    pub c: Vec<u8>,
    pub h: Vec<u8>,
}

/// Write each block as a C array with HexView's flash-driver declarations. Elements of
/// a block's last partial word are padded with zero bytes, and `_CHECKSUM` is the
/// 16-bit (32-bit for `Long`) sum of the unencrypted elements. CLI: /XC.
pub fn write_c_code(hexfile: &HexFile, options: &CCodeWriteOptions) -> CCodeOutput {
    let size = options.word_size;
    let (ty, suffix) = (size.c_type(), size.suffix());
    let prefix = &options.prefix;
    let upper = prefix.to_ascii_uppercase();
    let h_file_name = header_name(&options.file_name);
    let include = h_file_name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(&h_file_name);
    let blocks = hexfile.blocks();
    let values: Vec<Vec<u32>> = blocks
        .iter()
        .map(|block| words(block.data(), options))
        .collect();

    let mut c = banner(
        &options.file_name,
        "C-Array of Flash-Driver",
        options.created,
    );
    let _ = write!(
        c,
        "#include <fbl_inc.h>\r\n#include <{include}>\r\n\r\n#if ({upper}_GEN_RAND!={})\r\n# error \"Generated header and C-File inconsistent!!\"\r\n#endif\r\n\r\n",
        generation(options.created)
    );
    for (index, values) in values.iter().enumerate() {
        let _ = write!(
            c,
            "V_MEMROM0 V_MEMROM1  {ty} V_MEMROM2 {prefix}Blk{index}[{upper}_BLOCK{index}_LENGTH] = {{\r\n"
        );
        let mask = size.mask();
        let per_line = 16 / size.bytes();
        for (line_index, line) in values.chunks(per_line).enumerate() {
            let text: Vec<String> = line
                .iter()
                .map(|value| {
                    let value = options
                        .decrypt_value
                        .map_or(*value, |xor| value ^ (xor & mask));
                    format!("0x{value:0width$X}{suffix}", width = 2 * size.bytes())
                })
                .collect();
            let last = (line_index + 1) * per_line >= values.len();
            let _ = write!(
                c,
                "\t{}{}\r\n",
                text.join(", "),
                if last { "" } else { "," }
            );
        }
        c.push_str("};\r\n");
    }

    let mut h = banner(
        &h_file_name,
        "Exported definition of C-Array Flash-Driver",
        options.created,
    );
    let _ = write!(
        h,
        "#ifndef __{upper}__\r\n#define __{upper}__\r\n#define {upper}_GEN_RAND {}\r\n\r\n#define {upper}_NUMBLOCKS {}\r\n\r\n",
        generation(options.created),
        blocks.len()
    );
    match options.decrypt_value {
        Some(xor) => {
            let _ = write!(
                h,
                "#define {upper}_DECRYPTVALUE\t0x{:X}{suffix}\r\n#define {upper}_DECRYPTDATA(a)   ({ty})(({ty})(a) ^ ({ty}){upper}_DECRYPTVALUE)\r\n",
                xor & size.mask()
            );
        }
        None => {
            let _ = write!(h, "#define {upper}_DECRYPTDATA(a)   ({ty})(a)\r\n");
        }
    }
    for (index, (block, values)) in blocks.iter().zip(&values).enumerate() {
        let checksum = values
            .iter()
            .fold(0u32, |sum, value| sum.wrapping_add(*value))
            & if size == CCodeWordSize::Long {
                u32::MAX
            } else {
                0xFFFF
            };
        let checksum_suffix = if size == CCodeWordSize::Long {
            "ul"
        } else {
            "u"
        };
        let _ = write!(
            h,
            "#define {upper}_BLOCK{index}_ADDRESS\t0x{:X}\r\n#define {upper}_BLOCK{index}_LENGTH\t0x{:X}\r\n#define {upper}_BLOCK{index}_CHECKSUM\t0x{checksum:X}{checksum_suffix}\r\n\r\nV_MEMROM0 extern V_MEMROM1 {ty} V_MEMROM2 {prefix}Blk{index}[{upper}_BLOCK{index}_LENGTH];\r\n\r\n",
            block.start_address(),
            values.len()
        );
    }
    let _ = write!(h, "\r\n#endif    /* #ifdef __{upper}__ */\r\n\r\n");

    CCodeOutput {
        c: c.into_bytes(),
        h: h.into_bytes(),
    }
}

/// `name` with its extension replaced by `.h`.
fn header_name(name: &str) -> String {
    let file_start = name.rfind(['/', '\\']).map_or(0, |index| index + 1);
    let stem_end = name[file_start..]
        .rfind('.')
        .map_or(name.len(), |dot| file_start + dot);
    format!("{}.h", &name[..stem_end])
}

/// The elements of `data`, the last one padded with zero bytes.
fn words(data: &[u8], options: &CCodeWriteOptions) -> Vec<u32> {
    data.chunks(options.word_size.bytes())
        .map(|chunk| {
            let mut bytes = [0u8; 4];
            bytes[..chunk.len()].copy_from_slice(chunk);
            let bytes = &bytes[..options.word_size.bytes()];
            match options.word_type {
                CCodeWordType::Intel => bytes
                    .iter()
                    .rev()
                    .fold(0, |acc, &b| acc << 8 | u32::from(b)),
                CCodeWordType::Motorola => bytes.iter().fold(0, |acc, &b| acc << 8 | u32::from(b)),
            }
        })
        .collect()
}

/// The comment HexView starts its C files with.
pub(super) fn banner(file_name: &str, project: &str, created: DateTime<FixedOffset>) -> String {
    let rule = "*".repeat(64);
    let created = created.format("%a %b %e %H:%M:%S %Y");
    format!(
        "/{rule}\r\n*\r\n*  Filename:      {file_name}\r\n*  Project:       {project}\r\n*  File created:  {created}\r\n\r\n*\r\n{rule}/\r\n\r\n"
    )
}

/// The first C runtime `rand()` after seeding it with the creation time.
fn generation(created: DateTime<FixedOffset>) -> u32 {
    ((created.timestamp() as u32)
        .wrapping_mul(214_013)
        .wrapping_add(2_531_011)
        >> 16)
        & 0x7FFF
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    fn options(word_size: CCodeWordSize, decrypt_value: Option<u32>) -> CCodeWriteOptions {
        CCodeWriteOptions {
            prefix: "fd".to_owned(),
            word_size,
            word_type: CCodeWordType::Intel,
            decrypt_value,
            file_name: "out.c".to_owned(),
            created: DateTime::parse_from_rfc3339("2026-11-07T21:36:07+01:00").unwrap(),
        }
    }

    fn image() -> HexFile {
        let pattern = |n: usize, seed: u8| (0..n).map(|i| seed.wrapping_add(7 * i as u8)).collect();
        HexFile::with_segments(vec![
            Segment::new(0x1000, pattern(0x13, 1)).unwrap(),
            Segment::new(0x2001, pattern(6, 2)).unwrap(),
        ])
    }

    /// HexView 1.15.2 `/XC` with `[C_EXPORT] Prefix=fd`.
    #[test]
    fn test_c_code_matches_hexview() {
        let output = write_c_code(&image(), &options(CCodeWordSize::Byte, Some(0)));
        let header = "/****************************************************************\r\n*\r\n*  Filename:      out.h\r\n*  Project:       Exported definition of C-Array Flash-Driver\r\n*  File created:  Sat Nov  7 21:36:07 2026\r\n\r\n*\r\n****************************************************************/\r\n\r\n#ifndef __FD__\r\n#define __FD__\r\n#define FD_GEN_RAND 921\r\n\r\n#define FD_NUMBLOCKS 2\r\n\r\n#define FD_DECRYPTVALUE\t0x0\r\n#define FD_DECRYPTDATA(a)   (vuint8)((vuint8)(a) ^ (vuint8)FD_DECRYPTVALUE)\r\n#define FD_BLOCK0_ADDRESS\t0x1000\r\n#define FD_BLOCK0_LENGTH\t0x13\r\n#define FD_BLOCK0_CHECKSUM\t0x4C0u\r\n\r\nV_MEMROM0 extern V_MEMROM1 vuint8 V_MEMROM2 fdBlk0[FD_BLOCK0_LENGTH];\r\n\r\n#define FD_BLOCK1_ADDRESS\t0x2001\r\n#define FD_BLOCK1_LENGTH\t0x6\r\n#define FD_BLOCK1_CHECKSUM\t0x75u\r\n\r\nV_MEMROM0 extern V_MEMROM1 vuint8 V_MEMROM2 fdBlk1[FD_BLOCK1_LENGTH];\r\n\r\n\r\n#endif    /* #ifdef __FD__ */\r\n\r\n";
        assert_eq!(String::from_utf8_lossy(&output.h), header);
        let c = String::from_utf8_lossy(&output.c);
        assert!(c.ends_with("V_MEMROM0 V_MEMROM1  vuint8 V_MEMROM2 fdBlk1[FD_BLOCK1_LENGTH] = {\r\n\t0x02, 0x09, 0x10, 0x17, 0x1E, 0x25\r\n};\r\n"));
        assert!(c.contains("\t0x01, 0x08, 0x0F, 0x16, 0x1D, 0x24, 0x2B, 0x32, 0x39, 0x40, 0x47, 0x4E, 0x55, 0x5C, 0x63, 0x6A,\r\n\t0x71, 0x78, 0x7F\r\n};\r\n"));
    }

    /// HexView 1.15.2 with `WordSize=2` and `Decryptvalue=0xCC`: Intel elements, zero
    /// padded, XORed, and a 32-bit checksum of the plain elements.
    #[test]
    fn test_c_code_long_words_match_hexview() {
        let output = write_c_code(&image(), &options(CCodeWordSize::Long, Some(0xCC)));
        let (c, h) = (
            String::from_utf8_lossy(&output.c),
            String::from_utf8_lossy(&output.h),
        );
        assert!(c.contains(
            "\t0x160F08CDul, 0x322B24D1ul, 0x4E4740F5ul, 0x6A635C99ul,\r\n\t0x007F78BDul\r\n};"
        ));
        assert!(h.contains("#define FD_DECRYPTVALUE\t0xCCul\r\n"));
        assert!(h.contains("#define FD_BLOCK0_CHECKSUM\t0x164411Dul\r\n"));
    }
}

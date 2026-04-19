use crate::io::ParseError;
use crate::{HexFile, Segment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CCodeWordType {
    Intel,
    Motorola,
}

#[derive(Debug, Clone)]
pub struct CCodeWriteOptions {
    pub prefix: String,
    pub header_name: String,
    /// 0=byte, 1=ushort, 2=ulong
    pub word_size: u8,
    pub word_type: CCodeWordType,
    pub decrypt: bool,
    pub decrypt_value: u32,
}

#[derive(Debug, Clone)]
pub struct CCodeOutput {
    pub c: Vec<u8>,
    pub h: Vec<u8>,
}

/// Write C-array output. CLI: /XC.
pub fn write_c_code(
    hexfile: &HexFile,
    options: &CCodeWriteOptions,
) -> Result<CCodeOutput, ParseError> {
    let (elem_bytes, c_type) = match options.word_size {
        0 => (1usize, "uint8_t"),
        1 => (2usize, "uint16_t"),
        2 => (4usize, "uint32_t"),
        other => {
            return Err(ParseError::InvalidOutput(format!(
                "unsupported WordSize {other}"
            )));
        }
    };

    let segments = hexfile.normalized().into_segments();

    let prefix = options.prefix.trim();
    if prefix.is_empty() {
        return Err(ParseError::InvalidOutput(
            "Prefix must not be empty".to_owned(),
        ));
    }

    let mut header = Vec::new();
    header.extend_from_slice(b"#pragma once\n#include <stdint.h>\n\n");
    header.extend_from_slice(
        format!(
            "#define {}_BLOCK_COUNT {}\n\n",
            sanitize_define(prefix),
            segments.len()
        )
        .as_bytes(),
    );

    let mut source = Vec::new();
    let header_name = options.header_name.trim();
    if header_name.is_empty() {
        return Err(ParseError::InvalidOutput(
            "Header name must not be empty".to_owned(),
        ));
    }
    source.extend_from_slice(format!("#include \"{}.h\"\n\n", header_name).as_bytes());

    for (idx, segment) in segments.iter().enumerate() {
        if segment.len() % elem_bytes != 0 {
            return Err(ParseError::InvalidOutput(format!(
                "segment {} length {} not multiple of {}",
                idx,
                segment.len(),
                elem_bytes
            )));
        }

        let addr = segment.start_address;
        let elem_count = segment.len() / elem_bytes;
        let upper = sanitize_define(prefix);
        header.extend_from_slice(
            format!("#define {upper}_BLOCK{idx}_ADDRESS 0x{addr:08X}u\n").as_bytes(),
        );
        header.extend_from_slice(
            format!(
                "#define {upper}_BLOCK{idx}_LENGTH_BYTES 0x{:X}u\n",
                segment.len()
            )
            .as_bytes(),
        );
        header.extend_from_slice(
            format!(
                "#define {upper}_BLOCK{idx}_LENGTH_ELEMENTS 0x{:X}u\n",
                elem_count
            )
            .as_bytes(),
        );
        header
            .extend_from_slice(format!("extern const {c_type} {prefix}Blk{idx}[];\n\n").as_bytes());

        source.extend_from_slice(format!("const {c_type} {prefix}Blk{idx}[] = {{\n").as_bytes());
        let values = segment_to_values(segment, elem_bytes, options)?;
        write_values(&mut source, &values, elem_bytes);
        source.extend_from_slice(b"};\n\n");
    }

    Ok(CCodeOutput {
        c: source,
        h: header,
    })
}

fn segment_to_values(
    segment: &Segment,
    elem_bytes: usize,
    options: &CCodeWriteOptions,
) -> Result<Vec<u32>, ParseError> {
    let mut values = Vec::new();
    for chunk in segment.data.chunks(elem_bytes) {
        let mut val = match (elem_bytes, options.word_type) {
            (1, _) => chunk[0] as u32,
            (2, CCodeWordType::Intel) => u16::from_le_bytes([chunk[0], chunk[1]]) as u32,
            (2, CCodeWordType::Motorola) => u16::from_be_bytes([chunk[0], chunk[1]]) as u32,
            (4, CCodeWordType::Intel) => {
                u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            }
            (4, CCodeWordType::Motorola) => {
                u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
            }
            _ => {
                return Err(ParseError::InvalidOutput(
                    "unsupported word size".to_owned(),
                ));
            }
        };

        if options.decrypt {
            let mask = match elem_bytes {
                1 => options.decrypt_value & 0xFF,
                2 => options.decrypt_value & 0xFFFF,
                4 => options.decrypt_value,
                _ => 0,
            };
            val ^= mask;
        }

        values.push(val);
    }
    Ok(values)
}

fn write_values(out: &mut Vec<u8>, values: &[u32], elem_bytes: usize) {
    let per_line = 12usize;
    for (idx, value) in values.iter().enumerate() {
        if idx % per_line == 0 {
            out.extend_from_slice(b"    ");
        }
        let width = elem_bytes * 2;
        let formatted = format!("0x{:0width$X}", value, width = width);
        out.extend_from_slice(formatted.as_bytes());
        if idx + 1 != values.len() {
            out.extend_from_slice(b", ");
        }
        if (idx + 1) % per_line == 0 || idx + 1 == values.len() {
            out.extend_from_slice(b"\n");
        }
    }
}

fn sanitize_define(prefix: &str) -> String {
    prefix
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_c_code_basic() {
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02, 0x03])]);
        let options = CCodeWriteOptions {
            prefix: "flashDrv".to_owned(),
            header_name: "flashDrv".to_owned(),
            word_size: 0,
            word_type: CCodeWordType::Intel,
            decrypt: false,
            decrypt_value: 0,
        };
        let output = write_c_code(&hexfile, &options).unwrap();
        assert!(
            String::from_utf8(output.c)
                .unwrap()
                .contains("flashDrvBlk0")
        );
        assert!(
            String::from_utf8(output.h)
                .unwrap()
                .contains("FLASHDRV_BLOCK0_ADDRESS")
        );
    }
}

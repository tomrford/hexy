use super::{ParseError, push_crlf, push_hex_byte};
use crate::{HexFile, Segment};

#[derive(Debug, Clone)]
pub struct HexAsciiWriteOptions {
    /// Bytes per line; 0 writes one line.
    pub line_length: usize,
    /// Written after every byte that does not end a line.
    pub separator: String,
}

impl Default for HexAsciiWriteOptions {
    fn default() -> Self {
        Self {
            line_length: 16,
            separator: String::new(),
        }
    }
}

/// Parse HEX ASCII data into a single segment at `base_address`, as HexView reads it:
/// every pair of hex digits is a byte, and a single digit before a separator is a byte
/// of its own. A lower-case `x` is skipped, dropping a `0` that comes right before it
/// (the `0x` prefix); every other character separates. CLI: /IA.
pub fn parse_hex_ascii(data: &[u8], base_address: u32) -> Result<HexFile, ParseError> {
    let mut bytes = Vec::new();
    let mut pending: Option<u8> = None;
    for &b in data {
        if let Some(digit) = (b as char).to_digit(16) {
            let digit = digit as u8;
            match pending.take() {
                Some(high) => bytes.push(high << 4 | digit),
                None => pending = Some(digit),
            }
        } else if b == b'x' {
            pending = pending.filter(|&digit| digit != 0);
        } else if let Some(digit) = pending.take() {
            bytes.push(digit);
        }
    }
    bytes.extend(pending);

    if bytes.is_empty() {
        return Ok(HexFile::new());
    }
    Ok(HexFile::with_segments(vec![Segment::new(
        base_address,
        bytes,
    )?]))
}

/// Write the HexFile to HEX ASCII bytes. CLI: /XA.
///
/// Every byte is followed by CRLF when it completes a line and by the separator
/// otherwise, the last byte included, as HexView writes it.
pub fn write_hex_ascii(hexfile: &HexFile, options: &HexAsciiWriteOptions) -> Vec<u8> {
    let normalized = hexfile.normalized();
    let mut out = Vec::new();
    let mut column = 0;
    for &byte in normalized.segments().iter().flat_map(|s| &s.data) {
        push_hex_byte(&mut out, byte);
        column += 1;
        if column == options.line_length {
            push_crlf(&mut out);
            column = 0;
        } else {
            out.extend_from_slice(options.separator.as_bytes());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_ascii_roundtrip() {
        let hexfile =
            HexFile::with_segments(vec![Segment::new(0x1000, vec![0xDE, 0xAD, 0xBE]).unwrap()]);
        let options = HexAsciiWriteOptions {
            line_length: 2,
            separator: ", ".to_owned(),
        };
        let out = write_hex_ascii(&hexfile, &options);
        let parsed = parse_hex_ascii(&out, 0x1000).unwrap();
        assert_eq!(parsed.segments().len(), 1);
        assert_eq!(parsed.segments()[0].start_address, 0x1000);
        assert_eq!(parsed.segments()[0].data, vec![0xDE, 0xAD, 0xBE]);
    }

    /// HexView 1.15.2 `/XA:8:,` and `/XA:16:,` on eight bytes.
    #[test]
    fn test_hex_ascii_ends_with_line_end_or_separator() {
        let data = vec![0x01, 0x08, 0x0F, 0x16, 0x1D, 0x24, 0x2B, 0x32];
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1000, data).unwrap()]);
        let write = |line_length| {
            let options = HexAsciiWriteOptions {
                line_length,
                separator: ",".to_owned(),
            };
            write_hex_ascii(&hexfile, &options)
        };
        assert_eq!(write(8), b"01,08,0F,16,1D,24,2B,32\r\n");
        assert_eq!(write(16), b"01,08,0F,16,1D,24,2B,32,");
    }

    /// HexView 1.15.2 `/IA` readings.
    #[test]
    fn test_hex_ascii_matches_hexview() {
        let parse = |text: &[u8]| {
            parse_hex_ascii(text, 0)
                .unwrap()
                .into_segments()
                .pop()
                .map(|segment| segment.into_parts().1)
                .unwrap_or_default()
        };
        assert_eq!(
            parse(b"0x12, 0x23, 0x34\r\n23456789 5 F3"),
            [0x12, 0x23, 0x34, 0x23, 0x45, 0x67, 0x89, 0x05, 0xF3]
        );
        assert_eq!(
            parse(b"123 4567 0x5 0xABC x1 1x2"),
            [0x12, 0x03, 0x45, 0x67, 0x05, 0xAB, 0x0C, 0x01, 0x12]
        );
        assert_eq!(parse(b"12 G4 zz 5"), [0x12, 0x04, 0x05]);
        assert_eq!(parse(b"00x1"), [0x00, 0x01]);
        assert_eq!(parse(b"0X12"), [0x00, 0x12]);
        assert_eq!(parse(b"0x0x12"), [0x12]);
        assert_eq!(parse(b"zz"), []);
    }
}

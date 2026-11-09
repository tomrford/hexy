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

/// Parse a HEX ASCII data file into a single segment at the given base address.
/// Non-hex characters are treated as separators. CLI: /IA.
pub fn parse_hex_ascii(data: &[u8], base_address: u32) -> Result<HexFile, ParseError> {
    let mut bytes = Vec::new();
    let mut line_no = 1usize;
    let mut token_digits: Vec<u8> = Vec::new();

    let mut idx = 0usize;
    while idx < data.len() {
        let b = data[idx];
        if b == b'\r' {
            idx += 1;
            continue;
        }
        if b == b'\n' {
            if !token_digits.is_empty() {
                push_hex_token(&token_digits, &mut bytes, line_no)?;
                token_digits.clear();
            }
            line_no += 1;
            idx += 1;
            continue;
        }
        if b == b'0' && idx + 1 < data.len() && token_digits.is_empty() {
            let next = data[idx + 1];
            if next == b'x' || next == b'X' {
                idx += 2;
                continue;
            }
        }
        if (b as char).is_ascii_hexdigit() {
            token_digits.push(b);
            idx += 1;
            continue;
        }
        if !token_digits.is_empty() {
            push_hex_token(&token_digits, &mut bytes, line_no)?;
            token_digits.clear();
        }
        idx += 1;
    }

    if !token_digits.is_empty() {
        push_hex_token(&token_digits, &mut bytes, line_no)?;
    }

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

fn push_hex_token(digits: &[u8], out: &mut Vec<u8>, line: usize) -> Result<(), ParseError> {
    match digits {
        [digit] => out.push(super::hex_digit(*digit, line)?),
        _ => out.extend(super::parse_hex_bytes(digits, line)?),
    }
    Ok(())
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

    #[test]
    fn test_hex_ascii_odd_digits_error() {
        let data = b"0A1";
        let result = parse_hex_ascii(data, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_hex_ascii_accepts_0x_prefix() {
        let data = b"0x12, 0x34\n0XAB";
        let parsed = parse_hex_ascii(data, 0x2000).unwrap();
        assert_eq!(parsed.segments()[0].start_address, 0x2000);
        assert_eq!(parsed.segments()[0].data, vec![0x12, 0x34, 0xAB]);
    }

    #[test]
    fn test_hex_ascii_single_digit_tokens() {
        let data = b"A B C";
        let parsed = parse_hex_ascii(data, 0).unwrap();
        assert_eq!(parsed.segments()[0].data, vec![0x0A, 0x0B, 0x0C]);
    }

    #[test]
    fn test_hex_ascii_contiguous_pairs() {
        let data = b"23456789";
        let parsed = parse_hex_ascii(data, 0).unwrap();
        assert_eq!(parsed.segments()[0].data, vec![0x23, 0x45, 0x67, 0x89]);
    }
}

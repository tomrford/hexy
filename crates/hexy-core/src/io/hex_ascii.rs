use crate::io::{ParseError, push_crlf, push_hex_byte};
use crate::{HexFile, Segment};

#[derive(Debug, Clone)]
pub struct HexAsciiWriteOptions {
    pub line_length: usize,
    pub separator: Option<String>,
}

impl Default for HexAsciiWriteOptions {
    fn default() -> Self {
        Self {
            line_length: 16,
            separator: None,
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

    let len = u32::try_from(bytes.len()).map_err(|_| {
        ParseError::AddressOverflow(format!(
            "HEX ASCII length {} exceeds u32 address space",
            bytes.len()
        ))
    })?;
    let end = base_address
        .checked_add(len.saturating_sub(1))
        .ok_or_else(|| {
            ParseError::AddressOverflow(format!("{:#X} + {} exceeds u32", base_address, len))
        })?;
    if end < base_address {
        return Err(ParseError::AddressOverflow(format!(
            "{:#X} + {} exceeds u32",
            base_address, len
        )));
    }

    let segment = Segment::try_new(base_address, bytes).map_err(|e| {
        ParseError::AddressOverflow(format!("{:#X} + {} exceeds u32: {e}", base_address, len))
    })?;

    Ok(HexFile::with_segments(vec![segment]))
}

/// Write the HexFile to HEX ASCII bytes. CLI: /XA.
pub fn write_hex_ascii(hexfile: &HexFile, options: &HexAsciiWriteOptions) -> Vec<u8> {
    let segments = hexfile.normalized().into_segments();

    let mut out = Vec::new();
    let mut line_len = options.line_length;
    if line_len == 0 {
        line_len = usize::MAX;
    }

    let sep = options.separator.as_deref().unwrap_or("");
    let mut current_count = 0usize;

    for segment in segments {
        for &byte in &segment.data {
            if current_count == line_len {
                push_crlf(&mut out);
                current_count = 0;
            } else if current_count > 0 && !sep.is_empty() {
                out.extend_from_slice(sep.as_bytes());
            }
            push_hex_byte(&mut out, byte);
            current_count += 1;
        }
    }

    out
}

fn push_hex_token(digits: &[u8], out: &mut Vec<u8>, line: usize) -> Result<(), ParseError> {
    if digits.len() == 1 {
        let hi = (digits[0] as char)
            .to_digit(16)
            .ok_or(ParseError::InvalidHexDigit {
                line,
                char: digits[0] as char,
            })?;
        out.push(hi as u8);
        return Ok(());
    }

    if !digits.len().is_multiple_of(2) {
        return Err(ParseError::InvalidRecord {
            line,
            message: "odd number of hex digits".to_owned(),
        });
    }

    let mut iter = digits.iter();
    while let (Some(&hi), Some(&lo)) = (iter.next(), iter.next()) {
        let hi = (hi as char)
            .to_digit(16)
            .ok_or(ParseError::InvalidHexDigit {
                line,
                char: hi as char,
            })?;
        let lo = (lo as char)
            .to_digit(16)
            .ok_or(ParseError::InvalidHexDigit {
                line,
                char: lo as char,
            })?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_ascii_roundtrip() {
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xDE, 0xAD, 0xBE])]);
        let options = HexAsciiWriteOptions {
            line_length: 2,
            separator: Some(", ".to_owned()),
        };
        let out = write_hex_ascii(&hexfile, &options);
        let parsed = parse_hex_ascii(&out, 0x1000).unwrap();
        assert_eq!(parsed.segments().len(), 1);
        assert_eq!(parsed.segments()[0].start_address, 0x1000);
        assert_eq!(parsed.segments()[0].data, vec![0xDE, 0xAD, 0xBE]);
    }

    #[test]
    fn test_hex_ascii_omits_final_newline() {
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1000, vec![0xDE, 0xAD, 0xBE])]);
        let options = HexAsciiWriteOptions {
            line_length: 2,
            separator: None,
        };

        assert_eq!(write_hex_ascii(&hexfile, &options), b"DEAD\r\nBE");
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

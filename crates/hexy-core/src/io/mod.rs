mod binary;
mod c_code;
mod error;
mod hex_ascii;
mod intel_hex;
mod srec;

pub use binary::{BinaryWriteOptions, parse_binary, write_binary};
pub use c_code::{CCodeOutput, CCodeWordType, CCodeWriteOptions, write_c_code};
pub use error::ParseError;
pub use hex_ascii::{HexAsciiWriteOptions, parse_hex_ascii, write_hex_ascii};
pub use intel_hex::{
    IntelHexMode, IntelHexWriteOptions, parse_intel_hex, parse_intel_hex_16bit, write_intel_hex,
};
pub use srec::{SRecordType, SRecordWriteOptions, parse_srec, write_srec};

fn push_hex_byte(out: &mut Vec<u8>, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push(HEX[(byte >> 4) as usize]);
    out.push(HEX[(byte & 0x0F) as usize]);
}

fn push_crlf(out: &mut Vec<u8>) {
    out.push(b'\r');
    out.push(b'\n');
}

fn hex_digit(b: u8, line: usize) -> Result<u8, error::ParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(error::ParseError::InvalidHexDigit {
            line,
            char: b as char,
        }),
    }
}

fn parse_hex_bytes(data: &[u8], line: usize) -> Result<Vec<u8>, error::ParseError> {
    if !data.len().is_multiple_of(2) {
        return Err(error::ParseError::InvalidRecord {
            line,
            message: "odd number of hex digits".to_owned(),
        });
    }
    let mut out = Vec::with_capacity(data.len() / 2);
    for chunk in data.chunks_exact(2) {
        let high = hex_digit(chunk[0], line)?;
        let low = hex_digit(chunk[1], line)?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

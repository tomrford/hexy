mod binary;
mod c_code;
mod error;
mod file;
mod flash_kernel;
mod ford;
mod gac;
mod hex_ascii;
mod intel_hex;
mod srec;
mod validation_c;

pub use binary::{BinaryWriteOptions, parse_binary, write_binary};
pub use c_code::{CCodeOutput, CCodeWordSize, CCodeWordType, CCodeWriteOptions, write_c_code};
pub use error::{ParseError, WriteError};
pub use file::{AutoFormat, FileIoError, detect_format, parse_auto};
pub use flash_kernel::{FlashKernelHeader, write_flash_kernel};
pub use ford::{FordHeader, write_ford_intel_hex};
pub use gac::write_gac_swil;
pub use hex_ascii::{HexAsciiWriteOptions, parse_hex_ascii, write_hex_ascii};
pub use intel_hex::{
    DEFAULT_INTEL_HEX_BYTES_PER_LINE, IntelHexMode, IntelHexWriteOptions, parse_intel_hex,
    parse_intel_hex_16bit, write_intel_hex,
};
pub use srec::{
    DEFAULT_SREC_BYTES_PER_LINE, SRecordType, SRecordWriteOptions, parse_srec, write_srec,
};
pub use validation_c::{ValidationCOptions, write_validation_c};

use crate::segment::end_address_for;
use crate::{HexFile, Segment};

/// Collects data records into segments in file order, extending the open segment while
/// each record starts directly after it.
#[derive(Default)]
struct SegmentBuilder {
    segments: Vec<Segment>,
    open: bool,
}

impl SegmentBuilder {
    fn push(&mut self, address: u32, data: &[u8], line: usize) -> Result<(), ParseError> {
        if data.is_empty() {
            return Ok(());
        }
        if end_address_for(address, data.len()).is_none() {
            return Err(ParseError::AddressOverflow { line });
        }
        match self.segments.last_mut() {
            Some(last) if self.open && last.end_address().checked_add(1) == Some(address) => {
                last.data.extend_from_slice(data);
            }
            _ => self
                .segments
                .push(Segment::from_valid(address, data.to_vec())),
        }
        self.open = true;
        Ok(())
    }

    /// Start a new segment at the next record even if it is contiguous.
    fn close(&mut self) {
        self.open = false;
    }

    fn finish(self) -> HexFile {
        HexFile::with_segments(self.segments)
    }
}

fn push_hex_byte(out: &mut Vec<u8>, byte: u8) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    out.push(HEX[(byte >> 4) as usize]);
    out.push(HEX[(byte & 0x0F) as usize]);
}

fn push_crlf(out: &mut Vec<u8>) {
    out.push(b'\r');
    out.push(b'\n');
}

fn hex_digit(b: u8, line: usize) -> Result<u8, ParseError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(ParseError::InvalidHexDigit {
            line,
            char: b as char,
        }),
    }
}

fn parse_hex_bytes(data: &[u8], line: usize) -> Result<Vec<u8>, ParseError> {
    if !data.len().is_multiple_of(2) {
        return Err(ParseError::InvalidRecord {
            line,
            message: "odd number of hex digits".to_owned(),
        });
    }
    data.chunks_exact(2)
        .map(|pair| Ok((hex_digit(pair[0], line)? << 4) | hex_digit(pair[1], line)?))
        .collect()
}

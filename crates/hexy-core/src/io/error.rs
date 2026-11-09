use thiserror::Error;

use crate::{OpsError, SegmentError};

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("invalid record at line {line}: {message}")]
    InvalidRecord { line: usize, message: String },

    #[error("checksum mismatch at line {line}: expected {expected:02X}, got {actual:02X}")]
    ChecksumMismatch {
        line: usize,
        expected: u8,
        actual: u8,
    },

    #[error("unexpected end of file")]
    UnexpectedEof,

    #[error("record at line {line} exceeds u32 address space")]
    AddressOverflow { line: usize },

    #[error("invalid hex digit at line {line}: {char}")]
    InvalidHexDigit { line: usize, char: char },

    #[error("unsupported record type at line {line}: {record_type:02X}")]
    UnsupportedRecordType { line: usize, record_type: u8 },

    #[error(transparent)]
    Segment(#[from] SegmentError),
}

#[derive(Debug, Error)]
pub enum WriteError {
    #[error("address {address:#X} cannot be encoded as {format}")]
    AddressNotEncodable { address: u32, format: &'static str },

    #[error("invalid output: {0}")]
    InvalidOutput(String),

    #[error(transparent)]
    Ops(#[from] OpsError),
}

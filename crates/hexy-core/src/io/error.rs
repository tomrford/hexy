use thiserror::Error;

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

    #[error("address overflow: {0}")]
    AddressOverflow(String),

    #[error("invalid hex digit at line {line}: {char}")]
    InvalidHexDigit { line: usize, char: char },

    #[error("unsupported record type at line {line}: {record_type:02X}")]
    UnsupportedRecordType { line: usize, record_type: u8 },

    #[error("invalid output: {0}")]
    InvalidOutput(String),
}

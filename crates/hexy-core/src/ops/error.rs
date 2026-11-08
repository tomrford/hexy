use thiserror::Error;

use crate::SegmentError;

#[derive(Debug, Error)]
pub enum OpsError {
    /// The operation would place data outside the u32 address space; `address` is the
    /// start of the data or target that does not fit.
    #[error("address overflow at {address:#X}")]
    AddressOverflow { address: u32 },

    #[error(transparent)]
    Segment(#[from] SegmentError),

    #[error("address {address:#X} not divisible by {divisor}")]
    AddressNotDivisible { address: u32, divisor: u32 },

    #[error("length {length} not a multiple of {expected} for {operation}")]
    LengthNotMultiple {
        length: u64,
        expected: u64,
        operation: &'static str,
    },

    #[error("unsupported checksum algorithm index: {0}")]
    UnsupportedChecksumAlgorithm(u8),

    #[error("invalid remap parameters: {0}")]
    InvalidRemapParams(String),

    #[error("range not fully covered by data: start {start:#X}, length {length}")]
    RangeNotCovered { start: u32, length: u64 },

    #[error("dense span of {span} bytes exceeds limit {limit} bytes")]
    DenseSpanTooLarge { span: u64, limit: u64 },
}

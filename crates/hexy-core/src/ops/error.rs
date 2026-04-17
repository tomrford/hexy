use thiserror::Error;

#[derive(Debug, Error)]
pub enum OpsError {
    #[error("address overflow: {0}")]
    AddressOverflow(String),

    #[error("address {address:#X} not divisible by {divisor}")]
    AddressNotDivisible { address: u32, divisor: u32 },

    #[error("segment length {length} not a multiple of {expected} for {operation}")]
    LengthNotMultiple {
        length: usize,
        expected: usize,
        operation: String,
    },

    #[error("alignment must be non-zero, got {0}")]
    InvalidAlignment(u32),

    #[error("unsupported checksum algorithm index: {0}")]
    UnsupportedChecksumAlgorithm(u8),

    #[error("invalid remap parameters: {0}")]
    InvalidRemapParams(String),

    #[error("range not fully covered by data: start {start:#X}, length {length}")]
    RangeNotCovered { start: u32, length: u32 },

    #[error("{context}: {source}")]
    Context {
        context: String,
        source: Box<OpsError>,
    },
}

impl OpsError {
    pub fn with_context(self, context: &str) -> Self {
        match self {
            OpsError::Context { .. } => self,
            other => OpsError::Context {
                context: context.to_string(),
                source: Box::new(other),
            },
        }
    }
}

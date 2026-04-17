use thiserror::Error;

use super::types::ParseArgError;
use hexy_core::SignatureError;
use hexy_core::ops::LogError;

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Arg(#[from] ParseArgError),
    #[error(transparent)]
    Ops(#[from] crate::OpsError),
    #[error(transparent)]
    Log(#[from] LogError),
    #[error(transparent)]
    Parse(#[from] crate::ParseError),
    #[error(transparent)]
    Signature(#[from] SignatureError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ExecuteOutput {
    pub checksum_bytes: Option<Vec<u8>>,
}

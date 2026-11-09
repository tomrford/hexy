use thiserror::Error;

use super::types::ParseArgError;
use hexy_core::{FileIoError, WriteError};

#[derive(Debug, Error)]
pub enum CliError {
    #[error(transparent)]
    Arg(#[from] ParseArgError),
    #[error(transparent)]
    Ops(#[from] crate::OpsError),
    #[error(transparent)]
    Parse(#[from] crate::ParseError),
    #[error(transparent)]
    Write(#[from] WriteError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    FileIo(#[from] FileIoError),
    #[error("{0}")]
    Unsupported(String),
    #[error("{0}")]
    Other(String),
}

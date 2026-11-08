//! Python exceptions for `hexy-core` errors.

use hexy_core::{
    AddressRangeError, FileIoError, OpsError, PipelineError, SegmentError, WriteError,
};
use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;

create_exception!(hexy, HexyError, PyException, "Base class of hexy's errors.");
create_exception!(
    hexy,
    RangeError,
    HexyError,
    "An address range or segment that does not fit the 32-bit address space, or range text that does not read as one."
);
create_exception!(
    hexy,
    ParseError,
    HexyError,
    "Input that is not valid in its file format."
);
create_exception!(
    hexy,
    OperationError,
    HexyError,
    "An image operation or export that cannot be carried out."
);
create_exception!(
    hexy,
    ProcessingError,
    HexyError,
    "A data processing step that cannot be carried out, such as one with an invalid key."
);
create_exception!(
    hexy,
    VerificationError,
    ProcessingError,
    "A signature or AES-GCM tag that does not match the data."
);

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = module.py();
    module.add("HexyError", py.get_type::<HexyError>())?;
    module.add("RangeError", py.get_type::<RangeError>())?;
    module.add("ParseError", py.get_type::<ParseError>())?;
    module.add("OperationError", py.get_type::<OperationError>())?;
    module.add("ProcessingError", py.get_type::<ProcessingError>())?;
    module.add("VerificationError", py.get_type::<VerificationError>())?;
    Ok(())
}

/// A core error as the Python exception for its kind.
pub(crate) trait ToPyErr {
    fn to_py_err(self) -> PyErr;
}

pub(crate) fn py_err(error: impl ToPyErr) -> PyErr {
    error.to_py_err()
}

impl ToPyErr for AddressRangeError {
    fn to_py_err(self) -> PyErr {
        RangeError::new_err(self.to_string())
    }
}

impl ToPyErr for SegmentError {
    fn to_py_err(self) -> PyErr {
        RangeError::new_err(self.to_string())
    }
}

impl ToPyErr for hexy_core::ParseError {
    fn to_py_err(self) -> PyErr {
        ParseError::new_err(self.to_string())
    }
}

impl ToPyErr for OpsError {
    fn to_py_err(self) -> PyErr {
        match self {
            Self::Segment(error) => error.to_py_err(),
            error => OperationError::new_err(error.to_string()),
        }
    }
}

impl ToPyErr for WriteError {
    fn to_py_err(self) -> PyErr {
        OperationError::new_err(self.to_string())
    }
}

impl ToPyErr for FileIoError {
    fn to_py_err(self) -> PyErr {
        match self {
            Self::Io(error) => error.into(),
            Self::Parse(error) => error.to_py_err(),
            Self::Write(error) => error.to_py_err(),
        }
    }
}

impl ToPyErr for hexy_core::ProcessingError {
    fn to_py_err(self) -> PyErr {
        match self {
            Self::Ops(error) => error.to_py_err(),
            Self::VerificationFailed | Self::TagMismatch => {
                VerificationError::new_err(self.to_string())
            }
            error => ProcessingError::new_err(error.to_string()),
        }
    }
}

impl ToPyErr for PipelineError {
    fn to_py_err(self) -> PyErr {
        match self {
            Self::Ops(error) => error.to_py_err(),
            Self::Processing(error) => error.to_py_err(),
        }
    }
}

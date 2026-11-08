use hexy_core::{AddressRange, Segment};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::errors::py_err;

#[pyclass(name = "AddressRange", module = "hexy", frozen, eq, from_py_object)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct PyAddressRange {
    pub(crate) inner: AddressRange,
}

#[pymethods]
impl PyAddressRange {
    #[new]
    #[pyo3(signature = (start, end=None, *, length=None))]
    fn new(start: u32, end: Option<u32>, length: Option<u64>) -> PyResult<Self> {
        let inner = match (end, length) {
            (Some(end), None) => AddressRange::from_start_end(start, end),
            (None, Some(length)) => AddressRange::from_start_length(start, length),
            _ => {
                return Err(PyTypeError::new_err(
                    "expected either end or keyword-only length",
                ));
            }
        }
        .map_err(py_err)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn parse(text: &str) -> PyResult<Self> {
        Ok(Self {
            inner: text.parse().map_err(py_err)?,
        })
    }

    #[getter]
    fn start(&self) -> u32 {
        self.inner.start()
    }

    #[getter]
    fn end(&self) -> u32 {
        self.inner.end()
    }

    #[getter]
    fn length(&self) -> u64 {
        self.inner.length()
    }

    fn __contains__(&self, address: u32) -> bool {
        self.inner.contains(address)
    }

    fn __repr__(&self) -> String {
        format!("AddressRange(0x{:X}, 0x{:X})", self.start(), self.end())
    }
}

#[pyclass(name = "Segment", module = "hexy", frozen, eq, skip_from_py_object)]
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct PySegment {
    pub(crate) inner: Segment,
}

#[pymethods]
impl PySegment {
    #[new]
    fn new(start: u32, data: Vec<u8>) -> PyResult<Self> {
        Ok(Self {
            inner: Segment::new(start, data).map_err(py_err)?,
        })
    }

    #[getter]
    fn start(&self) -> u32 {
        self.inner.start_address()
    }

    #[getter]
    fn end(&self) -> u32 {
        self.inner.end_address()
    }

    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, self.inner.data())
    }

    fn __len__(&self) -> usize {
        self.inner.len()
    }

    fn __repr__(&self) -> String {
        format!(
            "Segment(start=0x{:X}, end=0x{:X}, length={})",
            self.start(),
            self.end(),
            self.inner.len()
        )
    }
}

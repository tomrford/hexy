use hexy_core::{AddressRange, Segment};
use pyo3::exceptions::PyTypeError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::util::{py_bytes, value_error};

#[pyclass(name = "AddressRange", frozen, skip_from_py_object)]
#[derive(Clone, Copy)]
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
            (None, None) => {
                return Err(PyTypeError::new_err(
                    "expected either end or keyword-only length",
                ));
            }
            (Some(_), Some(_)) => {
                return Err(PyTypeError::new_err(
                    "end and length are mutually exclusive",
                ));
            }
        }
        .map_err(value_error)?;
        Ok(Self { inner })
    }

    #[staticmethod]
    fn from_start_end(start: u32, end: u32) -> PyResult<Self> {
        Ok(Self {
            inner: AddressRange::from_start_end(start, end).map_err(value_error)?,
        })
    }

    #[staticmethod]
    fn from_start_length(start: u32, length: u64) -> PyResult<Self> {
        Ok(Self {
            inner: AddressRange::from_start_length(start, length).map_err(value_error)?,
        })
    }

    #[staticmethod]
    fn parse(text: &str) -> PyResult<Self> {
        Ok(Self {
            inner: text.parse::<AddressRange>().map_err(value_error)?,
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

    #[getter]
    fn addressable_length(&self) -> u64 {
        self.inner.addressable_length()
    }

    #[getter]
    fn extends_past_address_space(&self) -> bool {
        self.inner.extends_past_address_space()
    }

    fn contains(&self, addr: u32) -> bool {
        self.inner.contains(addr)
    }

    fn __repr__(&self) -> String {
        format!("AddressRange(0x{:X}, 0x{:X})", self.start(), self.end())
    }
}

#[pyclass(name = "Segment", frozen, skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PySegment {
    pub(crate) inner: Segment,
}

#[pymethods]
impl PySegment {
    #[new]
    fn new(start: u32, data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: Segment::try_new(start, data.to_vec()).map_err(value_error)?,
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
    fn data(&self, py: Python<'_>) -> Py<PyBytes> {
        py_bytes(py, self.inner.data())
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

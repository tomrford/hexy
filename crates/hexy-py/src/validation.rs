//! HexView's validation structures: `/vs` options and the `ValidationStructure` they
//! build.

use chrono::{DateTime, FixedOffset};
use hexy_core::{
    HsmValidationOptions, ValidationCOptions, ValidationOptions, ValidationStructure,
    write_validation_c,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::args::{checksum_algorithm, ranges};

/// The keyword arguments of the `/vs` structure.
pub(crate) struct ValidationArgs<'a, 'py> {
    pub(crate) tag_begin: Vec<u8>,
    pub(crate) tag_end: Vec<u8>,
    pub(crate) block_checksum: Option<u8>,
    pub(crate) file_checksum: Option<u8>,
    pub(crate) validate_sum: bool,
    pub(crate) big_endian: bool,
    pub(crate) force_32bit: bool,
    pub(crate) alfi: bool,
    pub(crate) one_byte_count: bool,
    pub(crate) spare: Option<&'a Bound<'py, PyAny>>,
}

impl ValidationArgs<'_, '_> {
    pub(crate) fn options(self) -> PyResult<ValidationOptions> {
        let algorithm = |index: Option<u8>| {
            index
                .map(|index| checksum_algorithm(index, None))
                .transpose()
        };
        Ok(ValidationOptions {
            tag_begin: self.tag_begin,
            tag_end: self.tag_end,
            block_checksum: algorithm(self.block_checksum)?,
            file_checksum: algorithm(self.file_checksum)?,
            validate_sum: self.validate_sum,
            big_endian: self.big_endian,
            force_32bit: self.force_32bit,
            alfi: self.alfi,
            one_byte_count: self.one_byte_count,
            spare: self.spare.map(ranges).transpose()?.unwrap_or_default(),
        })
    }
}

pub(crate) fn hsm_options(group_id: u32, mode: u16, hash: u8) -> PyResult<HsmValidationOptions> {
    Ok(HsmValidationOptions {
        group_id,
        mode,
        hash: checksum_algorithm(hash, None)?,
    })
}

#[pyclass(name = "ValidationStructure", module = "hexy", frozen)]
pub(crate) struct PyValidationStructure {
    pub(crate) options: ValidationOptions,
    pub(crate) inner: ValidationStructure,
}

#[pymethods]
impl PyValidationStructure {
    /// The encoded structure.
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        PyBytes::new(py, &self.inner.bytes)
    }

    fn __bytes__<'py>(&self, py: Python<'py>) -> Bound<'py, PyBytes> {
        self.data(py)
    }

    #[getter]
    fn blocks(&self) -> Vec<(u32, u32, Option<Vec<u8>>)> {
        self.inner
            .blocks
            .iter()
            .map(|block| (block.address, block.length, block.checksum.clone()))
            .collect()
    }

    #[getter]
    fn file_checksum(&self) -> Option<Vec<u8>> {
        self.inner.file_checksum.clone()
    }

    #[getter]
    fn validate_sum(&self) -> Option<u16> {
        self.inner.validate_sum
    }

    #[getter]
    fn wide(&self) -> bool {
        self.inner.wide
    }

    #[pyo3(signature = (c_file_name, h_file_name, *, tag_begin_value=None, tag_end_value=None, created=None))]
    fn to_c<'py>(
        &self,
        py: Python<'py>,
        c_file_name: String,
        h_file_name: String,
        tag_begin_value: Option<u32>,
        tag_end_value: Option<u32>,
        created: Option<DateTime<FixedOffset>>,
    ) -> (Bound<'py, PyBytes>, Bound<'py, PyBytes>) {
        let value = |tag: &[u8]| {
            tag.iter()
                .fold(0u32, |acc, &byte| acc << 8 | u32::from(byte))
        };
        let (c, h) = write_validation_c(
            &self.options,
            &self.inner,
            &ValidationCOptions {
                c_file_name,
                h_file_name,
                created: created.unwrap_or_else(|| chrono::Local::now().fixed_offset()),
                tag_begin_value: tag_begin_value.unwrap_or_else(|| value(&self.options.tag_begin)),
                tag_end_value: tag_end_value.unwrap_or_else(|| value(&self.options.tag_end)),
            },
        );
        (PyBytes::new(py, &c), PyBytes::new(py, &h))
    }
}

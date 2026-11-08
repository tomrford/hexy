use hexy_core::{
    AddressMap, AlignOptions, ChecksumStage, DataProcessingStage, DspicOp, Fill, FillData,
    HsmValidationStage, Merge, MergeOptions, Pipeline, RemapOptions, SwapMode, ValidationStage,
    VerifyStage,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::args::{
    ChecksumArgs, fill_pattern, key_file, merge_mode, optional_range, placement, range, ranges,
    swap_mode,
};
use crate::errors::py_err;
use crate::hexfile::PyHexFile;
use crate::processing::{PyDataProcessing, signature_method};
use crate::validation::{PyValidationStructure, ValidationArgs, hsm_options};

/// A `hexy_core::Pipeline`: each method configures one stage, and `apply` runs the
/// configured stages in HexView order.
#[pyclass(name = "Pipeline", module = "hexy", skip_from_py_object)]
#[derive(Default)]
pub(crate) struct PyPipeline {
    inner: Pipeline,
}

#[pyclass(name = "PipelineResult", module = "hexy", frozen, skip_from_py_object)]
pub(crate) struct PyPipelineResult {
    #[pyo3(get)]
    hexfile: Py<PyHexFile>,
    #[pyo3(get)]
    checksums: Vec<Py<PyBytes>>,
    #[pyo3(get)]
    data_processing: Option<Py<PyBytes>>,
    #[pyo3(get)]
    validation: Option<Py<PyValidationStructure>>,
    #[pyo3(get)]
    hsm_validation: Option<Py<PyBytes>>,
    #[pyo3(get)]
    hsm_signature: Option<Py<PyBytes>>,
}

#[pymethods]
impl PyPipeline {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn apply(&self, py: Python<'_>, source: PyRef<'_, PyHexFile>) -> PyResult<PyPipelineResult> {
        let mut hexfile = source.inner.clone();
        let output = self.inner.run(&mut hexfile).map_err(py_err)?;
        let bytes = |data: Vec<u8>| PyBytes::new(py, &data).unbind();
        let validation = match (output.validation, &self.inner.validation) {
            (Some(inner), Some(stage)) => Some(Py::new(
                py,
                PyValidationStructure {
                    options: stage.options.clone(),
                    inner,
                },
            )?),
            _ => None,
        };
        Ok(PyPipelineResult {
            hexfile: Py::new(py, PyHexFile { inner: hexfile })?,
            checksums: output.checksums.into_iter().map(bytes).collect(),
            data_processing: output.data_processing.map(bytes),
            validation,
            hsm_validation: output.hsm_validation.map(bytes),
            hsm_signature: output.hsm_signature.map(bytes),
        })
    }

    fn map_star12(&mut self) {
        self.inner.address_map = Some(AddressMap::Star12);
    }

    fn map_star12x(&mut self) {
        self.inner.address_map = Some(AddressMap::Star12x);
    }

    fn map_star08(&mut self) {
        self.inner.address_map = Some(AddressMap::Star08);
    }

    fn remap(&mut self, start: u32, end: u32, linear: u32, size: u32, inc: u32) {
        self.inner.address_map = Some(AddressMap::Remap(RemapOptions {
            start,
            end,
            linear,
            size,
            inc,
        }));
    }

    #[pyo3(signature = (range, target=None))]
    fn dspic_expand(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        let range = self::range(range)?;
        self.inner.dspic_expand.push(DspicOp { range, target });
        Ok(())
    }

    #[pyo3(signature = (range, target=None))]
    fn dspic_shrink(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        let range = self::range(range)?;
        self.inner.dspic_shrink.push(DspicOp { range, target });
        Ok(())
    }

    fn dspic_clear_ghost(&mut self, range: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.dspic_clear_ghost.push(self::range(range)?);
        Ok(())
    }

    #[pyo3(signature = (ranges, *, pattern=None))]
    fn fill(&mut self, ranges: &Bound<'_, PyAny>, pattern: Option<&[u8]>) -> PyResult<()> {
        self.inner.fill = Some(Fill {
            ranges: self::ranges(ranges)?,
            data: FillData::Pattern(fill_pattern(pattern)?),
        });
        Ok(())
    }

    #[pyo3(signature = (ranges, *, seed))]
    fn fill_random(&mut self, ranges: &Bound<'_, PyAny>, seed: u64) -> PyResult<()> {
        self.inner.fill = Some(Fill {
            ranges: self::ranges(ranges)?,
            data: FillData::Random { seed },
        });
        Ok(())
    }

    fn cut(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.cut.extend(self::ranges(ranges)?);
        Ok(())
    }

    #[pyo3(signature = (other, *, mode="overwrite", offset=0, range=None))]
    fn merge(
        &mut self,
        other: PyRef<'_, PyHexFile>,
        mode: &str,
        offset: i64,
        range: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.inner.merges.push(Merge {
            file: other.inner.clone(),
            options: MergeOptions {
                mode: merge_mode(mode)?,
                offset,
                range: optional_range(range)?,
            },
        });
        Ok(())
    }

    fn filter(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.address_filter = Some(self::ranges(ranges)?);
        Ok(())
    }

    #[pyo3(signature = (*, fill=0xFF))]
    fn fill_gaps(&mut self, fill: u8) {
        self.inner.fill_gaps = Some(fill);
    }

    #[pyo3(signature = (alignment, *, length=0, fill=0xFF))]
    fn align(&mut self, alignment: u32, length: u32, fill: u8) {
        self.inner.align = Some(AlignOptions {
            address_alignment: alignment,
            length_alignment: length,
            fill_byte: fill,
        });
    }

    fn split(&mut self, max_size: u32) {
        self.inner.split = Some(max_size);
    }

    fn swap(&mut self, mode: &str) -> PyResult<()> {
        match swap_mode(mode)? {
            SwapMode::Word => self.inner.swap_word = true,
            SwapMode::DWord => self.inner.swap_dword = true,
        }
        Ok(())
    }

    fn remove_small_blocks(&mut self, min_length: u32) {
        self.inner.remove_small_blocks = Some(min_length);
    }

    #[pyo3(signature = (
        algorithm,
        *,
        placement=None,
        range=None,
        reverse=false,
        exclude=None,
        forced_range=None,
        forced_pattern=None,
        constant=None,
    ))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn checksum(
        &mut self,
        algorithm: u8,
        placement: Option<&Bound<'_, PyAny>>,
        range: Option<&Bound<'_, PyAny>>,
        reverse: bool,
        exclude: Option<&Bound<'_, PyAny>>,
        forced_range: Option<&Bound<'_, PyAny>>,
        forced_pattern: Option<&[u8]>,
        constant: Option<&[u8]>,
    ) -> PyResult<()> {
        let options = ChecksumArgs {
            algorithm,
            range,
            reverse,
            exclude,
            forced_range,
            forced_pattern,
            constant,
        }
        .options()?;
        self.inner.checksums.push(ChecksumStage {
            options,
            placement: self::placement(placement)?,
        });
        Ok(())
    }

    #[pyo3(signature = (operation, *, placement=None))]
    fn process_data(
        &mut self,
        operation: PyDataProcessing,
        placement: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.inner.data_processing = Some(DataProcessingStage {
            operation: operation.inner,
            placement: self::placement(placement)?,
        });
        Ok(())
    }

    #[pyo3(signature = (method, key, signature, *, metadata=false))]
    fn verify(
        &mut self,
        method: &str,
        key: &Bound<'_, PyAny>,
        signature: Vec<u8>,
        metadata: bool,
    ) -> PyResult<()> {
        let method = signature_method(method, metadata)?;
        let key = method
            .scheme
            .verifying_key(&key_file(key)?)
            .map_err(py_err)?;
        self.inner.verify = Some(VerifyStage {
            method,
            key,
            signature,
        });
        Ok(())
    }

    #[pyo3(signature = (
        *,
        tag_begin,
        tag_end,
        block_checksum=None,
        file_checksum=None,
        validate_sum=false,
        big_endian=false,
        force_32bit=false,
        alfi=false,
        one_byte_count=false,
        spare=None,
        address=None,
    ))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn validation_structure(
        &mut self,
        tag_begin: Vec<u8>,
        tag_end: Vec<u8>,
        block_checksum: Option<u8>,
        file_checksum: Option<u8>,
        validate_sum: bool,
        big_endian: bool,
        force_32bit: bool,
        alfi: bool,
        one_byte_count: bool,
        spare: Option<&Bound<'_, PyAny>>,
        address: Option<u32>,
    ) -> PyResult<()> {
        let options = ValidationArgs {
            tag_begin,
            tag_end,
            block_checksum,
            file_checksum,
            validate_sum,
            big_endian,
            force_32bit,
            alfi,
            one_byte_count,
            spare,
        }
        .options()?;
        self.inner.validation = Some(ValidationStage { options, address });
        Ok(())
    }

    #[pyo3(signature = (*, group_id=0, mode=0, hash=20, placement=None, signature=None))]
    fn hsm_validation_structure(
        &mut self,
        group_id: u32,
        mode: u16,
        hash: u8,
        placement: Option<&Bound<'_, PyAny>>,
        signature: Option<PyDataProcessing>,
    ) -> PyResult<()> {
        self.inner.hsm_validation = Some(HsmValidationStage {
            options: hsm_options(group_id, mode, hash)?,
            placement: self::placement(placement)?,
            signature: signature.map(|operation| operation.inner),
        });
        Ok(())
    }
}

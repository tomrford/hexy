use hexy_core::{
    AddressMap, AlignOptions, ChecksumAlgorithm, ChecksumOptions, ChecksumStage, DspicOp, Fill,
    FillData, ForcedRange, Merge, MergeOptions, Pipeline, RemapOptions, SwapMode,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::hexfile::PyHexFile;
use crate::util::{
    parse_fill_pattern, parse_merge_mode, parse_placement, parse_range_arg, parse_ranges_arg,
    parse_swap_mode, py_bytes, value_error,
};

/// A `hexy_core::Pipeline`: each method configures one stage, and `apply` runs the
/// configured stages in HexView order.
#[pyclass(name = "Pipeline", skip_from_py_object)]
#[derive(Default)]
pub(crate) struct PyPipeline {
    inner: Pipeline,
}

#[pyclass(name = "PipelineResult", frozen, skip_from_py_object)]
pub(crate) struct PyPipelineResult {
    #[pyo3(get)]
    hexfile: Py<PyHexFile>,
    #[pyo3(get)]
    checksums: Vec<Py<PyBytes>>,
}

#[pymethods]
impl PyPipeline {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn apply(&self, py: Python<'_>, source: PyRef<'_, PyHexFile>) -> PyResult<PyPipelineResult> {
        let mut hexfile = source.inner.clone();
        let output = self.inner.run(&mut hexfile).map_err(value_error)?;
        Ok(PyPipelineResult {
            hexfile: Py::new(py, PyHexFile { inner: hexfile })?,
            checksums: output.checksums.iter().map(|c| py_bytes(py, c)).collect(),
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
        let range = parse_range_arg(range)?;
        self.inner.dspic_expand.push(DspicOp { range, target });
        Ok(())
    }

    #[pyo3(signature = (range, target=None))]
    fn dspic_shrink(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        let range = parse_range_arg(range)?;
        self.inner.dspic_shrink.push(DspicOp { range, target });
        Ok(())
    }

    fn dspic_clear_ghost(&mut self, range: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.dspic_clear_ghost.push(parse_range_arg(range)?);
        Ok(())
    }

    #[pyo3(signature = (ranges, *, pattern=None))]
    fn fill(&mut self, ranges: &Bound<'_, PyAny>, pattern: Option<&[u8]>) -> PyResult<()> {
        self.inner.fill = Some(Fill {
            ranges: parse_ranges_arg(ranges)?,
            data: FillData::Pattern(parse_fill_pattern(pattern)?),
        });
        Ok(())
    }

    #[pyo3(signature = (ranges, *, seed))]
    fn fill_random(&mut self, ranges: &Bound<'_, PyAny>, seed: u64) -> PyResult<()> {
        self.inner.fill = Some(Fill {
            ranges: parse_ranges_arg(ranges)?,
            data: FillData::Random { seed },
        });
        Ok(())
    }

    fn cut(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.cut.extend(parse_ranges_arg(ranges)?);
        Ok(())
    }

    #[pyo3(signature = (other, *, mode=None, offset=0, range=None))]
    fn merge(
        &mut self,
        other: PyRef<'_, PyHexFile>,
        mode: Option<&str>,
        offset: i64,
        range: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        self.inner.merges.push(Merge {
            file: other.inner.clone(),
            options: MergeOptions {
                mode: parse_merge_mode(mode)?,
                offset,
                range: range.map(parse_range_arg).transpose()?,
            },
        });
        Ok(())
    }

    fn filter(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.address_filter = Some(parse_ranges_arg(ranges)?);
        Ok(())
    }

    #[pyo3(signature = (*, fill=0xFF))]
    fn fill_gaps(&mut self, fill: u8) {
        self.inner.fill_gaps = Some(fill);
    }

    #[pyo3(signature = (alignment, *, fill=0xFF, length=false))]
    fn align(&mut self, alignment: u32, fill: u8, length: bool) {
        self.inner.align = Some(AlignOptions {
            alignment,
            fill_byte: fill,
            align_length: length,
        });
    }

    fn split(&mut self, max_size: u32) {
        self.inner.split = Some(max_size);
    }

    fn swap(&mut self, mode: &str) -> PyResult<()> {
        match parse_swap_mode(mode)? {
            SwapMode::Word => self.inner.swap_word = true,
            SwapMode::DWord => self.inner.swap_dword = true,
        }
        Ok(())
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
    ) -> PyResult<()> {
        let forced_range = forced_range
            .map(|range| -> PyResult<ForcedRange> {
                Ok(ForcedRange {
                    range: parse_range_arg(range)?,
                    pattern: forced_pattern.unwrap_or_default().to_vec(),
                })
            })
            .transpose()?;
        self.inner.checksums.push(ChecksumStage {
            options: ChecksumOptions {
                algorithm: ChecksumAlgorithm::try_from(algorithm).map_err(value_error)?,
                range: range.map(parse_range_arg).transpose()?,
                little_endian_output: reverse,
                forced_range,
                exclude_ranges: exclude
                    .map(parse_ranges_arg)
                    .transpose()?
                    .unwrap_or_default(),
            },
            placement: placement.map(parse_placement).transpose()?,
        });
        Ok(())
    }
}

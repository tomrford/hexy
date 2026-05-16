use hexy_core::{
    AlignOptions, BinaryWriteOptions, FillOptions, HexAsciiWriteOptions, HexFile,
    IntelHexWriteOptions, MergeOptions, RemapOptions, SRecordWriteOptions, parse_binary,
    parse_hex_ascii, parse_intel_hex, parse_intel_hex_16bit, parse_srec, write_binary,
    write_hex_ascii, write_intel_hex, write_srec,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::types::PySegment;
use crate::util::{
    parse_error, parse_fill_pattern, parse_intel_mode, parse_merge_mode, parse_range_arg,
    parse_ranges_arg, parse_srec_type, parse_swap_mode, py_bytes, value_error,
};

#[pyclass(name = "HexFile", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PyHexFile {
    pub(crate) inner: HexFile,
}

#[pymethods]
impl PyHexFile {
    #[new]
    fn new() -> Self {
        Self {
            inner: HexFile::new(),
        }
    }

    #[staticmethod]
    fn from_segments(segments: Vec<PyRef<'_, PySegment>>) -> Self {
        Self {
            inner: HexFile::with_segments(segments.iter().map(|s| s.inner.clone()).collect()),
        }
    }

    #[staticmethod]
    fn from_binary(data: &[u8], base_address: Option<u32>) -> PyResult<Self> {
        Ok(Self {
            inner: parse_binary(data, base_address.unwrap_or(0)).map_err(parse_error)?,
        })
    }

    #[staticmethod]
    fn from_hex_ascii(data: &[u8], base_address: Option<u32>) -> PyResult<Self> {
        Ok(Self {
            inner: parse_hex_ascii(data, base_address.unwrap_or(0)).map_err(parse_error)?,
        })
    }

    #[staticmethod]
    fn from_intel_hex(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: parse_intel_hex(data).map_err(parse_error)?,
        })
    }

    #[staticmethod]
    fn from_intel_hex_16bit(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: parse_intel_hex_16bit(data).map_err(parse_error)?,
        })
    }

    #[staticmethod]
    fn from_srec(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: parse_srec(data).map_err(parse_error)?,
        })
    }

    #[pyo3(signature = (*, normalized=false))]
    fn segments(&self, normalized: bool) -> Vec<PySegment> {
        let hexfile = if normalized {
            self.inner.normalized()
        } else {
            self.inner.clone()
        };
        hexfile
            .segments()
            .iter()
            .cloned()
            .map(|inner| PySegment { inner })
            .collect()
    }

    fn normalized(&self) -> Self {
        Self {
            inner: self.inner.normalized(),
        }
    }

    fn copy(&self) -> Self {
        self.clone()
    }

    fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    #[getter]
    fn min_address(&self) -> Option<u32> {
        self.inner.min_address()
    }

    #[getter]
    fn max_address(&self) -> Option<u32> {
        self.inner.max_address()
    }

    #[getter]
    fn total_bytes(&self) -> usize {
        self.inner.total_bytes()
    }

    #[getter]
    fn gap_count(&self) -> usize {
        self.inner.gap_count()
    }

    fn append_segment(&mut self, segment: PyRef<'_, PySegment>) {
        self.inner.append_segment(segment.inner.clone());
    }

    fn prepend_segment(&mut self, segment: PyRef<'_, PySegment>) {
        self.inner.prepend_segment(segment.inner.clone());
    }

    fn write(&mut self, addr: u32, data: &[u8]) {
        self.inner.write_bytes(addr, data);
    }

    fn read_byte(&self, addr: u32) -> Option<u8> {
        self.inner.read_byte(addr)
    }

    fn read(&self, py: Python<'_>, addr: u32, length: usize) -> Option<Py<PyBytes>> {
        self.inner
            .read_bytes_contiguous(addr, length)
            .map(|data| py_bytes(py, &data))
    }

    fn read_sparse(&self, addr: u32, length: usize) -> Vec<Option<u8>> {
        self.inner.read_bytes(addr, length)
    }

    #[pyo3(signature = (*, fill=0xFF))]
    fn to_bytes(&self, py: Python<'_>, fill: u8) -> Option<Py<PyBytes>> {
        self.inner
            .as_contiguous(fill)
            .map(|segment| py_bytes(py, &segment.data))
    }

    #[pyo3(signature = (*, fill_gaps=None))]
    fn to_binary(&self, py: Python<'_>, fill_gaps: Option<u8>) -> Py<PyBytes> {
        let data = write_binary(&self.inner, &BinaryWriteOptions { fill_gaps });
        py_bytes(py, &data)
    }

    #[pyo3(signature = (*, bytes_per_line=32, mode=None))]
    fn to_intel_hex(
        &self,
        py: Python<'_>,
        bytes_per_line: u8,
        mode: Option<&str>,
    ) -> PyResult<Py<PyBytes>> {
        let data = write_intel_hex(
            &self.inner,
            &IntelHexWriteOptions {
                bytes_per_line,
                mode: parse_intel_mode(mode)?,
            },
        );
        Ok(py_bytes(py, &data))
    }

    #[pyo3(signature = (*, bytes_per_line=16, record_type=None))]
    fn to_srec(
        &self,
        py: Python<'_>,
        bytes_per_line: u8,
        record_type: Option<&str>,
    ) -> PyResult<Py<PyBytes>> {
        let data = write_srec(
            &self.inner,
            &SRecordWriteOptions {
                bytes_per_line,
                record_type: parse_srec_type(record_type)?,
            },
        )
        .map_err(parse_error)?;
        Ok(py_bytes(py, &data))
    }

    #[pyo3(signature = (*, line_length=16, separator=None))]
    fn to_hex_ascii(
        &self,
        py: Python<'_>,
        line_length: usize,
        separator: Option<String>,
    ) -> Py<PyBytes> {
        let data = write_hex_ascii(
            &self.inner,
            &HexAsciiWriteOptions {
                line_length,
                separator,
            },
        );
        py_bytes(py, &data)
    }

    fn filter(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.filter_ranges(&parse_ranges_arg(ranges)?);
        Ok(())
    }

    fn cut(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.cut_ranges(&parse_ranges_arg(ranges)?);
        Ok(())
    }

    #[pyo3(signature = (ranges, *, pattern=None, overwrite=false))]
    fn fill(
        &mut self,
        ranges: &Bound<'_, PyAny>,
        pattern: Option<&[u8]>,
        overwrite: bool,
    ) -> PyResult<()> {
        self.inner.fill_ranges(
            &parse_ranges_arg(ranges)?,
            &FillOptions {
                pattern: parse_fill_pattern(pattern)?,
                overwrite,
            },
        );
        Ok(())
    }

    #[pyo3(signature = (*, fill=0xFF))]
    fn fill_gaps(&mut self, fill: u8) {
        self.inner.fill_gaps(fill);
    }

    #[pyo3(signature = (other, *, mode=None, offset=0, range=None))]
    fn merge(
        &mut self,
        other: PyRef<'_, PyHexFile>,
        mode: Option<&str>,
        offset: i64,
        range: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let options = MergeOptions {
            mode: parse_merge_mode(mode)?,
            offset,
            range: range.map(parse_range_arg).transpose()?,
        };
        self.inner
            .merge(&other.inner, &options)
            .map_err(value_error)
    }

    fn offset(&mut self, offset: i64) -> PyResult<()> {
        self.inner.offset_addresses(offset).map_err(value_error)
    }

    #[pyo3(signature = (alignment, *, fill=0xFF, length=false))]
    fn align(&mut self, alignment: u32, fill: u8, length: bool) -> PyResult<()> {
        self.inner
            .align(&AlignOptions {
                alignment,
                fill_byte: fill,
                align_length: length,
            })
            .map_err(value_error)
    }

    fn split(&mut self, max_size: u32) {
        self.inner.split(max_size);
    }

    fn swap(&mut self, mode: &str) -> PyResult<()> {
        self.inner
            .swap_bytes(parse_swap_mode(mode)?)
            .map_err(value_error)
    }

    fn dspic_expand(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        self.inner
            .dspic_expand(parse_range_arg(range)?, target)
            .map_err(value_error)
    }

    fn dspic_shrink(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        self.inner
            .dspic_shrink(parse_range_arg(range)?, target)
            .map_err(value_error)
    }

    fn dspic_clear_ghost(&mut self, range: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner
            .dspic_clear_ghost(parse_range_arg(range)?)
            .map_err(value_error)
    }

    fn remap(&mut self, start: u32, end: u32, linear: u32, size: u32, inc: u32) -> PyResult<()> {
        self.inner
            .remap(&RemapOptions {
                start,
                end,
                linear,
                size,
                inc,
            })
            .map_err(value_error)
    }

    fn map_star12(&mut self) -> PyResult<()> {
        self.inner.map_star12().map_err(value_error)
    }

    fn map_star12x(&mut self) -> PyResult<()> {
        self.inner.map_star12x().map_err(value_error)
    }

    fn map_star08(&mut self) -> PyResult<()> {
        self.inner.map_star08().map_err(value_error)
    }

    fn __repr__(&self) -> String {
        format!(
            "HexFile(segments={}, total_bytes={})",
            self.inner.segments().len(),
            self.inner.total_bytes()
        )
    }
}

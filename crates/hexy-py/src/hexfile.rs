use std::path::PathBuf;

use chrono::{DateTime, FixedOffset};
use hexy_core::{
    AlignOptions, BinaryWriteOptions, CCodeWordSize, CCodeWordType, CCodeWriteOptions, FillOptions,
    FlashKernelHeader, FordHeader, HexAsciiWriteOptions, HexFile, IntelHexWriteOptions,
    MergeOptions, RemapOptions, SRecordWriteOptions, parse_binary, parse_hex_ascii,
    parse_intel_hex, parse_intel_hex_16bit, parse_srec, write_binary, write_c_code,
    write_flash_kernel, write_ford_intel_hex, write_gac_swil, write_hex_ascii, write_intel_hex,
    write_srec,
};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::args::{
    ChecksumArgs, fill_pattern, intel_hex_mode, key_file, merge_mode, optional_range, placement,
    range, ranges, srec_type, swap_mode,
};
use crate::errors::py_err;
use crate::processing::{PyDataProcessing, signature_method};
use crate::types::PySegment;
use crate::validation::{PyValidationStructure, ValidationArgs, hsm_options};

#[pyclass(name = "HexFile", module = "hexy", skip_from_py_object)]
#[derive(Clone)]
pub(crate) struct PyHexFile {
    pub(crate) inner: HexFile,
}

fn segments(segments: Vec<hexy_core::Segment>) -> Vec<PySegment> {
    segments
        .into_iter()
        .map(|inner| PySegment { inner })
        .collect()
}

fn intel_hex_options(bytes_per_line: u8, mode: &str) -> PyResult<IntelHexWriteOptions> {
    Ok(IntelHexWriteOptions {
        bytes_per_line,
        mode: intel_hex_mode(mode)?,
    })
}

fn srec_options(bytes_per_line: u8, record_type: &str) -> PyResult<SRecordWriteOptions> {
    Ok(SRecordWriteOptions {
        bytes_per_line,
        record_type: srec_type(record_type)?,
    })
}

#[pymethods]
impl PyHexFile {
    #[new]
    #[pyo3(signature = (segments=None))]
    fn new(segments: Option<&Bound<'_, PyAny>>) -> PyResult<Self> {
        let segments = match segments {
            Some(items) => items
                .try_iter()?
                .map(|item| Ok(item?.extract::<PyRef<'_, PySegment>>()?.inner.clone()))
                .collect::<PyResult<Vec<_>>>()?,
            None => Vec::new(),
        };
        Ok(Self {
            inner: HexFile::with_segments(segments),
        })
    }

    // --- Parsers ---

    #[staticmethod]
    #[pyo3(signature = (data, base_address=0))]
    fn from_binary(data: &[u8], base_address: u32) -> PyResult<Self> {
        Ok(Self {
            inner: parse_binary(data, base_address).map_err(py_err)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (data, base_address=0))]
    fn from_hex_ascii(data: &[u8], base_address: u32) -> PyResult<Self> {
        Ok(Self {
            inner: parse_hex_ascii(data, base_address).map_err(py_err)?,
        })
    }

    #[staticmethod]
    fn from_intel_hex(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: parse_intel_hex(data).map_err(py_err)?,
        })
    }

    #[staticmethod]
    fn from_intel_hex_16bit(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: parse_intel_hex_16bit(data).map_err(py_err)?,
        })
    }

    #[staticmethod]
    fn from_srec(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: parse_srec(data).map_err(py_err)?,
        })
    }

    #[staticmethod]
    fn from_file(path: PathBuf) -> PyResult<Self> {
        Ok(Self {
            inner: HexFile::from_file(path).map_err(py_err)?,
        })
    }

    #[staticmethod]
    fn from_file_bytes(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: HexFile::from_file_bytes(data).map_err(py_err)?,
        })
    }

    // --- Inspection and access ---

    fn segments(&self) -> Vec<PySegment> {
        segments(self.inner.segments().to_vec())
    }

    fn blocks(&self) -> Vec<PySegment> {
        segments(self.inner.blocks())
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

    fn write(&mut self, address: u32, data: &[u8]) -> PyResult<()> {
        self.inner.write_bytes(address, data).map_err(py_err)
    }

    fn read_byte(&self, address: u32) -> Option<u8> {
        self.inner.read_byte(address)
    }

    fn read<'py>(
        &self,
        py: Python<'py>,
        address: u32,
        length: usize,
    ) -> Option<Bound<'py, PyBytes>> {
        self.inner
            .read_bytes_contiguous(address, length)
            .map(|data| PyBytes::new(py, &data))
    }

    fn read_sparse(&self, address: u32, length: usize) -> Vec<Option<u8>> {
        self.inner.read_bytes(address, length)
    }

    // --- Exports ---

    #[pyo3(signature = (*, fill_gaps=None))]
    fn to_binary<'py>(
        &self,
        py: Python<'py>,
        fill_gaps: Option<u8>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let data = write_binary(&self.inner, &BinaryWriteOptions { fill_gaps }).map_err(py_err)?;
        Ok(PyBytes::new(py, &data))
    }

    #[pyo3(signature = (*, bytes_per_line=hexy_core::DEFAULT_INTEL_HEX_BYTES_PER_LINE, mode="auto"))]
    fn to_intel_hex<'py>(
        &self,
        py: Python<'py>,
        bytes_per_line: u8,
        mode: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let options = intel_hex_options(bytes_per_line, mode)?;
        let data = write_intel_hex(&self.inner, &options).map_err(py_err)?;
        Ok(PyBytes::new(py, &data))
    }

    #[pyo3(signature = (*, bytes_per_line=hexy_core::DEFAULT_SREC_BYTES_PER_LINE, record_type="auto"))]
    fn to_srec<'py>(
        &self,
        py: Python<'py>,
        bytes_per_line: u8,
        record_type: &str,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let options = srec_options(bytes_per_line, record_type)?;
        let data = write_srec(&self.inner, &options).map_err(py_err)?;
        Ok(PyBytes::new(py, &data))
    }

    #[pyo3(signature = (*, line_length=16, separator=String::new()))]
    fn to_hex_ascii<'py>(
        &self,
        py: Python<'py>,
        line_length: usize,
        separator: String,
    ) -> Bound<'py, PyBytes> {
        let options = HexAsciiWriteOptions {
            line_length,
            separator,
        };
        PyBytes::new(py, &write_hex_ascii(&self.inner, &options))
    }

    #[pyo3(signature = (file_name, *, prefix=String::new(), word_size=1, motorola=false, xor=None, created=None))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn to_c_code<'py>(
        &self,
        py: Python<'py>,
        file_name: String,
        prefix: String,
        word_size: u8,
        motorola: bool,
        xor: Option<u32>,
        created: Option<DateTime<FixedOffset>>,
    ) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
        let word_size = match word_size {
            1 => CCodeWordSize::Byte,
            2 => CCodeWordSize::Word,
            4 => CCodeWordSize::Long,
            other => {
                return Err(PyValueError::new_err(format!(
                    "the word size must be 1, 2 or 4, not {other}"
                )));
            }
        };
        let output = write_c_code(
            &self.inner,
            &CCodeWriteOptions {
                prefix,
                word_size,
                word_type: if motorola {
                    CCodeWordType::Motorola
                } else {
                    CCodeWordType::Intel
                },
                decrypt_value: xor,
                file_name,
                created: created.unwrap_or_else(|| chrono::Local::now().fixed_offset()),
            },
        );
        Ok((PyBytes::new(py, &output.c), PyBytes::new(py, &output.h)))
    }

    #[pyo3(signature = (name, *, comment=None, file_address=None, size=None, ram_address=None, ram_start=None))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn to_flash_kernel<'py>(
        &self,
        py: Python<'py>,
        name: &str,
        comment: Option<String>,
        file_address: Option<String>,
        size: Option<String>,
        ram_address: Option<String>,
        ram_start: Option<String>,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let blocks = self.inner.blocks();
        let block = blocks
            .first()
            .ok_or_else(|| PyValueError::new_err("a flash kernel needs data"))?;
        let defaults = FlashKernelHeader::new(name, block);
        let header = FlashKernelHeader {
            comment: comment.unwrap_or(defaults.comment),
            file_address: file_address.unwrap_or(defaults.file_address),
            size: size.unwrap_or(defaults.size),
            ram_address: ram_address.unwrap_or(defaults.ram_address),
            ram_start: ram_start.unwrap_or(defaults.ram_start),
            name: defaults.name,
        };
        let data = write_flash_kernel(&self.inner, &header).map_err(py_err)?;
        Ok(PyBytes::new(py, &data))
    }

    #[pyo3(signature = (
        file_name,
        release_date,
        *,
        application=None,
        mask_number=None,
        module_type=None,
        part_number=None,
        wers_notice=None,
        comments=None,
        released_by=None,
        module_name=None,
        module_id=None,
        download_format=String::from("0x01"),
        flash_indicator=String::from("1"),
        erase_sectors=None,
        erase_alignment=0,
    ))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn to_ford_intel_hex<'py>(
        &self,
        py: Python<'py>,
        file_name: String,
        release_date: String,
        application: Option<String>,
        mask_number: Option<String>,
        module_type: Option<String>,
        part_number: Option<String>,
        wers_notice: Option<String>,
        comments: Option<String>,
        released_by: Option<String>,
        module_name: Option<String>,
        module_id: Option<String>,
        download_format: String,
        flash_indicator: String,
        erase_sectors: Option<String>,
        erase_alignment: u32,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let header = FordHeader {
            application,
            mask_number,
            file_name,
            release_date,
            module_type,
            part_number,
            wers_notice,
            comments,
            released_by,
            module_name,
            module_id,
            download_format,
            flash_indicator,
            erase_sectors,
            erase_alignment,
        };
        let data = write_ford_intel_hex(&self.inner, &header).map_err(py_err)?;
        Ok(PyBytes::new(py, &data))
    }

    fn to_gac_swil<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let data = write_gac_swil(&self.inner).map_err(py_err)?;
        Ok(PyBytes::new(py, &data))
    }

    #[pyo3(signature = (path, *, fill_gaps=None))]
    fn write_binary(&self, path: PathBuf, fill_gaps: Option<u8>) -> PyResult<()> {
        self.inner
            .write_binary_file(&path, &BinaryWriteOptions { fill_gaps })
            .map_err(py_err)
    }

    #[pyo3(signature = (path, *, bytes_per_line=hexy_core::DEFAULT_INTEL_HEX_BYTES_PER_LINE, mode="auto"))]
    fn write_intel_hex(&self, path: PathBuf, bytes_per_line: u8, mode: &str) -> PyResult<()> {
        let options = intel_hex_options(bytes_per_line, mode)?;
        self.inner
            .write_intel_hex_file(&path, &options)
            .map_err(py_err)
    }

    #[pyo3(signature = (path, *, bytes_per_line=hexy_core::DEFAULT_SREC_BYTES_PER_LINE, record_type="auto"))]
    fn write_srec(&self, path: PathBuf, bytes_per_line: u8, record_type: &str) -> PyResult<()> {
        let options = srec_options(bytes_per_line, record_type)?;
        self.inner.write_srec_file(&path, &options).map_err(py_err)
    }

    #[pyo3(signature = (path, *, line_length=16, separator=String::new()))]
    fn write_hex_ascii(
        &self,
        path: PathBuf,
        line_length: usize,
        separator: String,
    ) -> PyResult<()> {
        let options = HexAsciiWriteOptions {
            line_length,
            separator,
        };
        self.inner
            .write_hex_ascii_file(&path, &options)
            .map_err(py_err)
    }

    // --- Operations, in Pipeline stage order ---

    fn map_star12(&mut self) -> PyResult<()> {
        self.inner.map_star12().map_err(py_err)
    }

    fn map_star12x(&mut self) -> PyResult<()> {
        self.inner.map_star12x().map_err(py_err)
    }

    fn map_star08(&mut self) -> PyResult<()> {
        self.inner.map_star08().map_err(py_err)
    }

    fn remap(&mut self, start: u32, end: u32, linear: u32, size: u32, inc: u32) -> PyResult<()> {
        let options = RemapOptions {
            start,
            end,
            linear,
            size,
            inc,
        };
        self.inner.remap(&options).map_err(py_err)
    }

    #[pyo3(signature = (range, target=None))]
    fn dspic_expand(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        self.inner
            .dspic_expand(self::range(range)?, target)
            .map_err(py_err)
    }

    #[pyo3(signature = (range, target=None))]
    fn dspic_shrink(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        self.inner
            .dspic_shrink(self::range(range)?, target)
            .map_err(py_err)
    }

    fn dspic_clear_ghost(&mut self, range: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner
            .dspic_clear_ghost(self::range(range)?)
            .map_err(py_err)
    }

    #[pyo3(signature = (ranges, *, pattern=None, overwrite=false))]
    fn fill(
        &mut self,
        ranges: &Bound<'_, PyAny>,
        pattern: Option<&[u8]>,
        overwrite: bool,
    ) -> PyResult<()> {
        let options = FillOptions {
            pattern: fill_pattern(pattern)?,
            overwrite,
        };
        self.inner
            .fill_ranges(&self::ranges(ranges)?, &options)
            .map_err(py_err)
    }

    #[pyo3(signature = (ranges, *, seed))]
    fn fill_random(&mut self, ranges: &Bound<'_, PyAny>, seed: u64) -> PyResult<()> {
        self.inner
            .fill_random(&self::ranges(ranges)?, seed)
            .map_err(py_err)
    }

    fn cut(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.cut_ranges(&self::ranges(ranges)?);
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
        let options = MergeOptions {
            mode: merge_mode(mode)?,
            offset,
            range: optional_range(range)?,
        };
        self.inner.merge(&other.inner, &options).map_err(py_err)
    }

    fn filter(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.inner.filter_ranges(&self::ranges(ranges)?);
        Ok(())
    }

    fn offset(&mut self, delta: i64) -> PyResult<()> {
        self.inner.offset_addresses(delta).map_err(py_err)
    }

    #[pyo3(signature = (*, fill=0xFF))]
    fn fill_gaps(&mut self, fill: u8) -> PyResult<()> {
        self.inner.fill_gaps(fill, u64::MAX).map_err(py_err)
    }

    #[pyo3(signature = (alignment, *, length=0, fill=0xFF))]
    fn align(&mut self, alignment: u32, length: u32, fill: u8) {
        self.inner.align(&AlignOptions {
            address_alignment: alignment,
            length_alignment: length,
            fill_byte: fill,
        });
    }

    fn split(&mut self, max_size: u32) {
        self.inner.split(max_size);
    }

    fn swap(&mut self, mode: &str) -> PyResult<()> {
        self.inner.swap_bytes(swap_mode(mode)?);
        Ok(())
    }

    fn remove_small_blocks(&mut self, min_length: usize) {
        self.inner.remove_small_blocks(min_length);
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
    fn checksum<'py>(
        &mut self,
        py: Python<'py>,
        algorithm: u8,
        placement: Option<&Bound<'py, PyAny>>,
        range: Option<&Bound<'py, PyAny>>,
        reverse: bool,
        exclude: Option<&Bound<'py, PyAny>>,
        forced_range: Option<&Bound<'py, PyAny>>,
        forced_pattern: Option<&[u8]>,
        constant: Option<&[u8]>,
    ) -> PyResult<Bound<'py, PyBytes>> {
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
        let bytes = self
            .inner
            .checksum(&options, self::placement(placement)?)
            .map_err(py_err)?;
        Ok(PyBytes::new(py, &bytes))
    }

    #[pyo3(signature = (operation, *, placement=None))]
    fn process_data<'py>(
        &mut self,
        py: Python<'py>,
        operation: PyRef<'_, PyDataProcessing>,
        placement: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Option<Bound<'py, PyBytes>>> {
        let output = self
            .inner
            .process_data(&operation.inner, self::placement(placement)?)
            .map_err(py_err)?;
        Ok(output.map(|bytes| PyBytes::new(py, &bytes)))
    }

    #[pyo3(signature = (method, key, signature, *, metadata=false))]
    fn verify(
        &self,
        method: &str,
        key: &Bound<'_, PyAny>,
        signature: &[u8],
        metadata: bool,
    ) -> PyResult<()> {
        let method = signature_method(method, metadata)?;
        let key = method
            .scheme
            .verifying_key(&key_file(key)?)
            .map_err(py_err)?;
        self.inner
            .verify_signature(method, &key, signature)
            .map_err(py_err)
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
    ))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn validation_structure(
        &self,
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
    ) -> PyResult<PyValidationStructure> {
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
        let inner = self.inner.validation_structure(&options).map_err(py_err)?;
        Ok(PyValidationStructure { options, inner })
    }

    #[pyo3(signature = (*, group_id=0, mode=0, hash=20))]
    fn hsm_validation_structure<'py>(
        &self,
        py: Python<'py>,
        group_id: u32,
        mode: u16,
        hash: u8,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let structure = self
            .inner
            .hsm_validation_structure(&hsm_options(group_id, mode, hash)?)
            .map_err(py_err)?;
        Ok(PyBytes::new(py, &structure))
    }

    fn __repr__(&self) -> String {
        format!(
            "HexFile(segments={}, total_bytes={})",
            self.inner.segments().len(),
            self.inner.total_bytes()
        )
    }
}

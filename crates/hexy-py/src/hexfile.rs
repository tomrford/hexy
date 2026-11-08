use hexy_core::{
    AlignOptions, BinaryWriteOptions, CCodeWordSize, CCodeWordType, CCodeWriteOptions,
    DataProcessing, FillOptions, FlashKernelHeader, HexAsciiWriteOptions, HexFile,
    IntelHexWriteOptions, MergeOptions, RemapOptions, SRecordWriteOptions, parse_binary,
    parse_hex_ascii, parse_intel_hex, parse_intel_hex_16bit, parse_srec, write_binary,
    write_c_code, write_flash_kernel, write_gac_swil, write_hex_ascii, write_intel_hex, write_srec,
};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::path::PathBuf;

use crate::types::PySegment;
use crate::util::{
    CipherArgs, CompressionArgs, cipher_operation, compression_operation, key_content,
    mac_operation, parse_fill_pattern, parse_intel_mode, parse_merge_mode, parse_placement,
    parse_range_arg, parse_ranges_arg, parse_signature_method, parse_srec_type, parse_swap_mode,
    py_bytes, value_error,
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
    #[pyo3(signature = (data, base_address=None))]
    fn from_binary(data: &[u8], base_address: Option<u32>) -> PyResult<Self> {
        Ok(Self {
            inner: parse_binary(data, base_address.unwrap_or(0)).map_err(value_error)?,
        })
    }

    #[staticmethod]
    #[pyo3(signature = (data, base_address=None))]
    fn from_hex_ascii(data: &[u8], base_address: Option<u32>) -> PyResult<Self> {
        Ok(Self {
            inner: parse_hex_ascii(data, base_address.unwrap_or(0)).map_err(value_error)?,
        })
    }

    #[staticmethod]
    fn from_intel_hex(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: parse_intel_hex(data).map_err(value_error)?,
        })
    }

    #[staticmethod]
    fn from_intel_hex_16bit(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: parse_intel_hex_16bit(data).map_err(value_error)?,
        })
    }

    #[staticmethod]
    fn from_srec(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: parse_srec(data).map_err(value_error)?,
        })
    }

    #[staticmethod]
    fn from_file(path: PathBuf) -> PyResult<Self> {
        Ok(Self {
            inner: HexFile::from_file(path).map_err(value_error)?,
        })
    }

    #[staticmethod]
    fn from_file_bytes(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            inner: HexFile::from_file_bytes(data).map_err(value_error)?,
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

    fn write(&mut self, addr: u32, data: &[u8]) -> PyResult<()> {
        self.inner.write_bytes(addr, data).map_err(value_error)
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
    fn to_bytes(&self, py: Python<'_>, fill: u8) -> PyResult<Option<Py<PyBytes>>> {
        let contiguous = self
            .inner
            .as_contiguous(fill, u64::MAX)
            .map_err(value_error)?;
        Ok(contiguous.map(|segment| py_bytes(py, segment.data())))
    }

    #[pyo3(signature = (*, fill_gaps=None))]
    fn to_binary(&self, py: Python<'_>, fill_gaps: Option<u8>) -> PyResult<Py<PyBytes>> {
        let data =
            write_binary(&self.inner, &BinaryWriteOptions { fill_gaps }).map_err(value_error)?;
        Ok(py_bytes(py, &data))
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
        )
        .map_err(value_error)?;
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
        .map_err(value_error)?;
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
                separator: separator.unwrap_or_default(),
            },
        );
        py_bytes(py, &data)
    }

    #[pyo3(signature = (file_name, *, prefix=String::new(), word_size=1, motorola=false, xor=None, created=String::new(), generation=0))]
    #[allow(clippy::too_many_arguments)]
    fn to_c_code(
        &self,
        py: Python<'_>,
        file_name: String,
        prefix: String,
        word_size: u8,
        motorola: bool,
        xor: Option<u32>,
        created: String,
        generation: u32,
    ) -> PyResult<(Py<PyBytes>, Py<PyBytes>)> {
        let word_size = match word_size {
            1 => CCodeWordSize::Byte,
            2 => CCodeWordSize::Word,
            4 => CCodeWordSize::Long,
            other => {
                return Err(value_error(format!(
                    "word_size must be 1, 2 or 4, not {other}"
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
                created,
                generation,
            },
        );
        Ok((py_bytes(py, &output.c), py_bytes(py, &output.h)))
    }

    #[pyo3(signature = (name, *, comment=None, file_address=None, size=None, ram_address=None, ram_start=None))]
    #[allow(clippy::too_many_arguments)]
    fn to_flash_kernel(
        &self,
        py: Python<'_>,
        name: &str,
        comment: Option<String>,
        file_address: Option<String>,
        size: Option<String>,
        ram_address: Option<String>,
        ram_start: Option<String>,
    ) -> PyResult<Py<PyBytes>> {
        let blocks = self.inner.blocks();
        let block = blocks
            .first()
            .ok_or_else(|| value_error("a flash kernel needs data"))?;
        let defaults = FlashKernelHeader::new(name, block);
        let header = FlashKernelHeader {
            comment: comment.unwrap_or(defaults.comment),
            file_address: file_address.unwrap_or(defaults.file_address),
            size: size.unwrap_or(defaults.size),
            ram_address: ram_address.unwrap_or(defaults.ram_address),
            ram_start: ram_start.unwrap_or(defaults.ram_start),
            name: defaults.name,
        };
        let data = write_flash_kernel(&self.inner, &header).map_err(value_error)?;
        Ok(py_bytes(py, &data))
    }

    fn to_gac_swil(&self, py: Python<'_>) -> PyResult<Py<PyBytes>> {
        let data = write_gac_swil(&self.inner).map_err(value_error)?;
        Ok(py_bytes(py, &data))
    }

    #[pyo3(signature = (path, *, fill_gaps=None))]
    fn write_binary(&self, path: PathBuf, fill_gaps: Option<u8>) -> PyResult<()> {
        self.inner
            .write_binary_file(&path, &BinaryWriteOptions { fill_gaps })
            .map_err(value_error)
    }

    #[pyo3(signature = (path, *, bytes_per_line=32, mode=None))]
    fn write_intel_hex(
        &self,
        path: PathBuf,
        bytes_per_line: u8,
        mode: Option<&str>,
    ) -> PyResult<()> {
        self.inner
            .write_intel_hex_file(
                &path,
                &IntelHexWriteOptions {
                    bytes_per_line,
                    mode: parse_intel_mode(mode)?,
                },
            )
            .map_err(value_error)
    }

    #[pyo3(signature = (path, *, bytes_per_line=16, record_type=None))]
    fn write_srec(
        &self,
        path: PathBuf,
        bytes_per_line: u8,
        record_type: Option<&str>,
    ) -> PyResult<()> {
        self.inner
            .write_srec_file(
                &path,
                &SRecordWriteOptions {
                    bytes_per_line,
                    record_type: parse_srec_type(record_type)?,
                },
            )
            .map_err(value_error)
    }

    #[pyo3(signature = (path, *, line_length=16, separator=None))]
    fn write_hex_ascii(
        &self,
        path: PathBuf,
        line_length: usize,
        separator: Option<String>,
    ) -> PyResult<()> {
        self.inner
            .write_hex_ascii_file(
                &path,
                &HexAsciiWriteOptions {
                    line_length,
                    separator: separator.unwrap_or_default(),
                },
            )
            .map_err(value_error)
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
        self.inner
            .fill_ranges(
                &parse_ranges_arg(ranges)?,
                &FillOptions {
                    pattern: parse_fill_pattern(pattern)?,
                    overwrite,
                },
            )
            .map_err(value_error)
    }

    #[pyo3(signature = (*, fill=0xFF))]
    fn fill_gaps(&mut self, fill: u8) -> PyResult<()> {
        self.inner.fill_gaps(fill, u64::MAX).map_err(value_error)
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

    fn remove_small_blocks(&mut self, min_len: usize) {
        self.inner.remove_small_blocks(min_len);
    }

    fn swap(&mut self, mode: &str) -> PyResult<()> {
        self.inner.swap_bytes(parse_swap_mode(mode)?);
        Ok(())
    }

    #[pyo3(signature = (range, target=None))]
    fn dspic_expand(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        self.inner
            .dspic_expand(parse_range_arg(range)?, target)
            .map_err(value_error)
    }

    #[pyo3(signature = (range, target=None))]
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

    #[pyo3(signature = (method, key, *, metadata=false, placement=None, salt=None))]
    fn sign(
        &mut self,
        py: Python<'_>,
        method: &str,
        key: &Bound<'_, PyAny>,
        metadata: bool,
        placement: Option<&Bound<'_, PyAny>>,
        salt: Option<&[u8]>,
    ) -> PyResult<Py<PyBytes>> {
        let method = parse_signature_method(method, metadata)?;
        let key = method
            .scheme
            .signing_key(&key_content(key)?)
            .map_err(value_error)?;
        let output = self
            .inner
            .process_data(
                &DataProcessing::Sign {
                    method,
                    key,
                    salt: salt.map(<[u8]>::to_vec),
                },
                placement.map(parse_placement).transpose()?,
            )
            .map_err(value_error)?;
        Ok(py_bytes(py, &output.unwrap_or_default()))
    }

    #[pyo3(signature = (method, key, *, metadata=false, placement=None))]
    fn mac(
        &mut self,
        py: Python<'_>,
        method: &str,
        key: &[u8],
        metadata: bool,
        placement: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyBytes>> {
        let output = self
            .inner
            .process_data(
                &mac_operation(method, key, metadata)?,
                placement.map(parse_placement).transpose()?,
            )
            .map_err(value_error)?;
        Ok(py_bytes(py, &output.unwrap_or_default()))
    }

    #[pyo3(signature = (key=None))]
    fn xor(&mut self, key: Option<&[u8]>) -> PyResult<()> {
        let key = key.unwrap_or_default().to_vec();
        self.inner
            .process_data(&DataProcessing::Xor { key }, None)
            .map_err(value_error)?;
        Ok(())
    }

    #[pyo3(signature = (mode, key, *, iv=None, padding=None, aad=None, placement=None))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn encrypt(
        &mut self,
        py: Python<'_>,
        mode: &str,
        key: &Bound<'_, PyAny>,
        iv: Option<&[u8]>,
        padding: Option<&str>,
        aad: Option<&[u8]>,
        placement: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Option<Py<PyBytes>>> {
        let args = CipherArgs {
            mode,
            key,
            iv,
            padding,
            aad: aad.unwrap_or_default(),
        };
        let output = self
            .inner
            .process_data(
                &cipher_operation(args, false, None)?,
                placement.map(parse_placement).transpose()?,
            )
            .map_err(value_error)?;
        Ok(output.map(|tag| py_bytes(py, &tag)))
    }

    #[pyo3(signature = (mode, key, *, iv=None, padding=None, aad=None, tag=None))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn decrypt(
        &mut self,
        mode: &str,
        key: &Bound<'_, PyAny>,
        iv: Option<&[u8]>,
        padding: Option<&str>,
        aad: Option<&[u8]>,
        tag: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<()> {
        let args = CipherArgs {
            mode,
            key,
            iv,
            padding,
            aad: aad.unwrap_or_default(),
        };
        self.inner
            .process_data(&cipher_operation(args, true, tag)?, None)
            .map_err(value_error)?;
        Ok(())
    }

    #[pyo3(signature = (method="lzss", *, window_bits=None, length_bits=None, key=None, iv=None, padding=None))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn compress(
        &mut self,
        method: &str,
        window_bits: Option<u8>,
        length_bits: Option<u8>,
        key: Option<&[u8]>,
        iv: Option<&[u8]>,
        padding: Option<&str>,
    ) -> PyResult<()> {
        let args = CompressionArgs {
            method,
            window_bits,
            length_bits,
            key,
            iv,
            padding,
        };
        self.inner
            .process_data(&compression_operation(args, false)?, None)
            .map_err(value_error)?;
        Ok(())
    }

    #[pyo3(signature = (method="lzss", *, window_bits=None, length_bits=None, key=None, iv=None, padding=None))]
    #[allow(clippy::too_many_arguments)] // mirrors the Python keyword arguments
    fn decompress(
        &mut self,
        method: &str,
        window_bits: Option<u8>,
        length_bits: Option<u8>,
        key: Option<&[u8]>,
        iv: Option<&[u8]>,
        padding: Option<&str>,
    ) -> PyResult<()> {
        let args = CompressionArgs {
            method,
            window_bits,
            length_bits,
            key,
            iv,
            padding,
        };
        self.inner
            .process_data(&compression_operation(args, true)?, None)
            .map_err(value_error)?;
        Ok(())
    }

    #[pyo3(signature = (method, key, signature, *, metadata=false))]
    fn verify_signature(
        &self,
        method: &str,
        key: &Bound<'_, PyAny>,
        signature: &[u8],
        metadata: bool,
    ) -> PyResult<()> {
        let method = parse_signature_method(method, metadata)?;
        let key = method
            .scheme
            .verifying_key(&key_content(key)?)
            .map_err(value_error)?;
        self.inner
            .verify_signature(method, &key, signature)
            .map_err(value_error)
    }

    fn __repr__(&self) -> String {
        format!(
            "HexFile(segments={}, total_bytes={})",
            self.inner.segments().len(),
            self.inner.total_bytes()
        )
    }
}

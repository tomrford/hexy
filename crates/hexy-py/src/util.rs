use hexy_core::{
    AddressRange, IntelHexMode, MergeMode, ParseError, SRecordType, SwapMode, parse_compat_ranges,
};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pub(crate) fn value_error(err: impl std::fmt::Display) -> PyErr {
    PyValueError::new_err(err.to_string())
}

pub(crate) fn parse_error(err: ParseError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

pub(crate) fn parse_range_arg(obj: &Bound<'_, PyAny>) -> PyResult<AddressRange> {
    if let Ok(text) = obj.extract::<String>() {
        return parse_single_range_text(&text);
    }
    Err(PyTypeError::new_err("expected range string"))
}

pub(crate) fn parse_ranges_arg(obj: &Bound<'_, PyAny>) -> PyResult<Vec<AddressRange>> {
    if obj.extract::<String>().is_ok() {
        return Err(PyTypeError::new_err(
            "expected a list of range strings, not a single range string",
        ));
    }
    let items = obj
        .try_iter()
        .map_err(|_| PyTypeError::new_err("expected a list of range strings"))?;
    items
        .map(|item| {
            let item = item?;
            parse_range_arg(&item)
        })
        .collect()
}

fn parse_single_range_text(text: &str) -> PyResult<AddressRange> {
    let ranges = parse_compat_ranges(text).map_err(value_error)?;
    let count = ranges.len();
    if count == 1 {
        Ok(ranges[0])
    } else {
        Err(PyValueError::new_err(format!(
            "expected a single range, got {count} ranges"
        )))
    }
}

pub(crate) fn parse_fill_pattern(pattern: Option<&[u8]>) -> PyResult<Vec<u8>> {
    let pattern = pattern.unwrap_or(&[0xFF]);
    if pattern.is_empty() {
        return Err(PyValueError::new_err("fill pattern cannot be empty"));
    }
    Ok(pattern.to_vec())
}

pub(crate) fn parse_merge_mode(mode: Option<&str>) -> PyResult<MergeMode> {
    match mode.unwrap_or("overwrite").to_ascii_lowercase().as_str() {
        "overwrite" | "opaque" => Ok(MergeMode::Overwrite),
        "preserve" | "transparent" => Ok(MergeMode::Preserve),
        other => Err(PyValueError::new_err(format!(
            "unknown merge mode '{other}', expected 'overwrite' or 'preserve'"
        ))),
    }
}

pub(crate) fn parse_swap_mode(mode: &str) -> PyResult<SwapMode> {
    match mode.to_ascii_lowercase().as_str() {
        "word" | "swapword" => Ok(SwapMode::Word),
        "dword" | "long" | "swaplong" => Ok(SwapMode::DWord),
        other => Err(PyValueError::new_err(format!(
            "unknown swap mode '{other}', expected 'word' or 'dword'"
        ))),
    }
}

pub(crate) fn parse_intel_mode(mode: Option<&str>) -> PyResult<IntelHexMode> {
    match mode.unwrap_or("auto").to_ascii_lowercase().as_str() {
        "auto" => Ok(IntelHexMode::Auto),
        "linear" | "extended_linear" => Ok(IntelHexMode::ExtendedLinear),
        "segment" | "extended_segment" => Ok(IntelHexMode::ExtendedSegment),
        other => Err(PyValueError::new_err(format!(
            "unknown Intel HEX mode '{other}'"
        ))),
    }
}

pub(crate) fn parse_srec_type(record_type: Option<&str>) -> PyResult<Option<SRecordType>> {
    match record_type.map(|v| v.to_ascii_lowercase()) {
        None => Ok(None),
        Some(value) if value == "auto" => Ok(None),
        Some(value) if value == "s1" || value == "1" => Ok(Some(SRecordType::S1)),
        Some(value) if value == "s2" || value == "2" => Ok(Some(SRecordType::S2)),
        Some(value) if value == "s3" || value == "3" => Ok(Some(SRecordType::S3)),
        Some(other) => Err(PyValueError::new_err(format!(
            "unknown S-Record type '{other}'"
        ))),
    }
}

pub(crate) fn py_bytes(py: Python<'_>, data: &[u8]) -> Py<PyBytes> {
    PyBytes::new(py, data).unbind()
}

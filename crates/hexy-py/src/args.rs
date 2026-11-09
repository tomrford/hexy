//! Python arguments as core values: ranges, placements, selector names, checksum
//! options and keys.

use hexy_core::{
    AddressRange, ChecksumAlgorithm, ChecksumOptions, ForcedRange, IntelHexMode, MergeMode,
    Placement, SRecordType, SwapMode,
};
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyString;

use crate::errors::py_err;
use crate::types::PyAddressRange;

/// The value `name` selects from `choices`, which are named for errors as `what`.
pub(crate) fn choice<T: Clone>(what: &str, name: &str, choices: &[(&str, T)]) -> PyResult<T> {
    choices
        .iter()
        .find(|(choice, _)| *choice == name)
        .map(|(_, value)| value.clone())
        .ok_or_else(|| {
            let names: Vec<String> = choices
                .iter()
                .map(|(name, _)| format!("'{name}'"))
                .collect();
            PyValueError::new_err(format!(
                "unknown {what} '{name}', expected one of {}",
                names.join(", ")
            ))
        })
}

/// An `AddressRange`, or range text as HexView reads it.
pub(crate) fn range(obj: &Bound<'_, PyAny>) -> PyResult<AddressRange> {
    if let Ok(range) = obj.extract::<PyAddressRange>() {
        return Ok(range.inner);
    }
    let text: String = obj
        .extract()
        .map_err(|_| PyTypeError::new_err("expected an AddressRange or range text"))?;
    text.parse().map_err(py_err)
}

/// An iterable of ranges.
pub(crate) fn ranges(obj: &Bound<'_, PyAny>) -> PyResult<Vec<AddressRange>> {
    if obj.is_instance_of::<PyString>() {
        return Err(PyTypeError::new_err(
            "expected a list of ranges, not a single range text",
        ));
    }
    obj.try_iter()
        .map_err(|_| PyTypeError::new_err("expected a list of ranges"))?
        .map(|item| range(&item?))
        .collect()
}

pub(crate) fn optional_range(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Option<AddressRange>> {
    obj.map(range).transpose()
}

/// An address, or `"append"`, `"begin"`, `"prepend"` or `"overwrite-end"`.
pub(crate) fn placement(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Placement>> {
    let Some(obj) = obj else {
        return Ok(None);
    };
    if let Ok(address) = obj.extract::<u32>() {
        return Ok(Some(Placement::Address(address)));
    }
    let name: String = obj
        .extract()
        .map_err(|_| PyTypeError::new_err("expected an address or a placement name"))?;
    choice(
        "placement",
        &name,
        &[
            ("append", Placement::Append),
            ("begin", Placement::Begin),
            ("prepend", Placement::Prepend),
            ("overwrite-end", Placement::OverwriteEnd),
        ],
    )
    .map(Some)
}

pub(crate) fn merge_mode(name: &str) -> PyResult<MergeMode> {
    choice(
        "merge mode",
        name,
        &[
            ("overwrite", MergeMode::Overwrite),
            ("preserve", MergeMode::Preserve),
        ],
    )
}

pub(crate) fn swap_mode(name: &str) -> PyResult<SwapMode> {
    choice(
        "swap mode",
        name,
        &[("word", SwapMode::Word), ("dword", SwapMode::DWord)],
    )
}

pub(crate) fn intel_hex_mode(name: &str) -> PyResult<IntelHexMode> {
    choice(
        "Intel HEX mode",
        name,
        &[
            ("auto", IntelHexMode::Auto),
            ("linear", IntelHexMode::ExtendedLinear),
            ("segment", IntelHexMode::ExtendedSegment),
        ],
    )
}

pub(crate) fn srec_type(name: &str) -> PyResult<Option<SRecordType>> {
    choice(
        "S-Record type",
        name,
        &[
            ("auto", None),
            ("s1", Some(SRecordType::S1)),
            ("s2", Some(SRecordType::S2)),
            ("s3", Some(SRecordType::S3)),
        ],
    )
}

/// A checksum method by its HexView `/CS` index; method 16 writes `constant`.
pub(crate) fn checksum_algorithm(
    index: u8,
    constant: Option<&[u8]>,
) -> PyResult<ChecksumAlgorithm> {
    match (
        ChecksumAlgorithm::try_from(index).map_err(py_err)?,
        constant,
    ) {
        (ChecksumAlgorithm::Constant(_), Some(bytes)) => {
            Ok(ChecksumAlgorithm::Constant(bytes.to_vec()))
        }
        (_, Some(_)) => Err(PyValueError::new_err("only method 16 takes a constant")),
        (algorithm, None) => Ok(algorithm),
    }
}

/// The keyword arguments of `checksum`.
pub(crate) struct ChecksumArgs<'a, 'py> {
    pub(crate) algorithm: u8,
    pub(crate) range: Option<&'a Bound<'py, PyAny>>,
    pub(crate) reverse: bool,
    pub(crate) exclude: Option<&'a Bound<'py, PyAny>>,
    pub(crate) forced_range: Option<&'a Bound<'py, PyAny>>,
    pub(crate) forced_pattern: Option<&'a [u8]>,
    pub(crate) constant: Option<&'a [u8]>,
}

impl ChecksumArgs<'_, '_> {
    pub(crate) fn options(&self) -> PyResult<ChecksumOptions> {
        Ok(ChecksumOptions {
            algorithm: checksum_algorithm(self.algorithm, self.constant)?,
            range: optional_range(self.range)?,
            little_endian_output: self.reverse,
            forced_range: optional_range(self.forced_range)?.map(|range| ForcedRange {
                range,
                pattern: self.forced_pattern.unwrap_or_default().to_vec(),
            }),
            exclude_ranges: self.exclude.map(ranges).transpose()?.unwrap_or_default(),
        })
    }
}

/// A non-empty fill pattern, 0xFF by default.
pub(crate) fn fill_pattern(pattern: Option<&[u8]>) -> PyResult<Vec<u8>> {
    match pattern {
        None => Ok(vec![0xFF]),
        Some([]) => Err(PyValueError::new_err("the fill pattern is empty")),
        Some(pattern) => Ok(pattern.to_vec()),
    }
}

/// An asymmetric key's file content: bytes as they are, key text as its bytes.
pub(crate) fn key_file(obj: &Bound<'_, PyAny>) -> PyResult<Vec<u8>> {
    if let Ok(text) = obj.cast::<PyString>() {
        return Ok(text.to_str()?.as_bytes().to_vec());
    }
    obj.extract()
        .map_err(|_| PyTypeError::new_err("expected key bytes or key text"))
}

/// A symmetric key: the raw key as bytes, or key text as HexView reads it from a key
/// file.
pub(crate) enum SymmetricKey {
    Raw(Vec<u8>),
    Text(String),
}

impl SymmetricKey {
    pub(crate) fn extract(obj: &Bound<'_, PyAny>) -> PyResult<Self> {
        if let Ok(text) = obj.cast::<PyString>() {
            return Ok(Self::Text(text.to_str()?.to_owned()));
        }
        obj.extract()
            .map(Self::Raw)
            .map_err(|_| PyTypeError::new_err("expected key bytes or key text"))
    }
}

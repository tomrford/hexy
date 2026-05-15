mod hexfile;
mod pipeline;
mod types;
mod util;

use pyo3::exceptions::{PyIndexError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyModule;

use crate::hexfile::PyHexFile;
use crate::pipeline::{PyHexViewPipeline, PyPipeline};
use crate::types::{PyAddressRange, PySegment};

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PyAddressRange>()?;
    module.add_class::<PySegment>()?;
    module.add_class::<PyHexFile>()?;
    module.add_class::<PyPipeline>()?;
    module.add_class::<PyHexViewPipeline>()?;
    module.add("HexyError", module.py().get_type::<PyValueError>())?;
    module.add("RangeError", module.py().get_type::<PyValueError>())?;
    module.add("ParseError", module.py().get_type::<PyValueError>())?;
    module.add("OperationError", module.py().get_type::<PyValueError>())?;
    module.add("IndexError", module.py().get_type::<PyIndexError>())?;
    Ok(())
}

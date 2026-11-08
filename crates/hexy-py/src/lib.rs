mod args;
mod errors;
mod hexfile;
mod pipeline;
mod processing;
mod types;
mod validation;

use pyo3::prelude::*;

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<types::PyAddressRange>()?;
    module.add_class::<types::PySegment>()?;
    module.add_class::<hexfile::PyHexFile>()?;
    module.add_class::<processing::PyDataProcessing>()?;
    module.add_class::<validation::PyValidationStructure>()?;
    module.add_class::<pipeline::PyPipeline>()?;
    module.add_class::<pipeline::PyPipelineResult>()?;
    errors::register(module)
}

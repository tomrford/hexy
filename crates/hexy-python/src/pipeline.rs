use hexy_core::{
    AddressRange, AlignOptions, FillOptions, HexFile, MergeMode, MergeOptions, RemapOptions,
    SwapMode,
};
use pyo3::prelude::*;

use crate::hexfile::PyHexFile;
use crate::util::{
    parse_fill_pattern, parse_merge_mode, parse_range_arg, parse_ranges_arg, parse_swap_mode,
    value_error,
};

#[derive(Clone)]
pub(crate) enum PipelineOp {
    MapStar12,
    MapStar12x,
    MapStar08,
    Remap(RemapOptions),
    DspicExpand {
        range: AddressRange,
        target: Option<u32>,
    },
    DspicShrink {
        range: AddressRange,
        target: Option<u32>,
    },
    DspicClearGhost(AddressRange),
    Fill {
        ranges: Vec<AddressRange>,
        options: FillOptions,
    },
    Cut(Vec<AddressRange>),
    Merge {
        other: HexFile,
        options: MergeOptions,
    },
    Filter(Vec<AddressRange>),
    FillGaps(u8),
    Align(AlignOptions),
    Split(u32),
    Swap(SwapMode),
}

fn apply_op(hexfile: &mut HexFile, op: &PipelineOp) -> PyResult<()> {
    match op {
        PipelineOp::MapStar12 => hexfile.map_star12().map_err(value_error),
        PipelineOp::MapStar12x => hexfile.map_star12x().map_err(value_error),
        PipelineOp::MapStar08 => hexfile.map_star08().map_err(value_error),
        PipelineOp::Remap(options) => hexfile.remap(options).map_err(value_error),
        PipelineOp::DspicExpand { range, target } => {
            hexfile.dspic_expand(*range, *target).map_err(value_error)
        }
        PipelineOp::DspicShrink { range, target } => {
            hexfile.dspic_shrink(*range, *target).map_err(value_error)
        }
        PipelineOp::DspicClearGhost(range) => {
            hexfile.dspic_clear_ghost(*range).map_err(value_error)
        }
        PipelineOp::Fill { ranges, options } => {
            hexfile.fill_ranges(ranges, options);
            Ok(())
        }
        PipelineOp::Cut(ranges) => {
            hexfile.cut_ranges(ranges);
            Ok(())
        }
        PipelineOp::Merge { other, options } => hexfile.merge(other, options).map_err(value_error),
        PipelineOp::Filter(ranges) => {
            hexfile.filter_ranges(ranges);
            Ok(())
        }
        PipelineOp::FillGaps(fill) => {
            hexfile.fill_gaps(*fill);
            Ok(())
        }
        PipelineOp::Align(options) => hexfile.align(options).map_err(value_error),
        PipelineOp::Split(size) => {
            hexfile.split(*size);
            Ok(())
        }
        PipelineOp::Swap(mode) => hexfile.swap_bytes(*mode).map_err(value_error),
    }
}

fn apply_ops(source: &PyHexFile, ops: &[PipelineOp]) -> PyResult<PyHexFile> {
    let mut inner = source.inner.clone();
    for op in ops {
        apply_op(&mut inner, op)?;
    }
    Ok(PyHexFile { inner })
}

#[pyclass(name = "Pipeline", skip_from_py_object)]
#[derive(Clone, Default)]
pub(crate) struct PyPipeline {
    map_star12_ops: Vec<PipelineOp>,
    map_star12x_ops: Vec<PipelineOp>,
    map_star08_ops: Vec<PipelineOp>,
    remap_ops: Vec<PipelineOp>,
    dspic_expand_ops: Vec<PipelineOp>,
    dspic_shrink_ops: Vec<PipelineOp>,
    dspic_clear_ghost_ops: Vec<PipelineOp>,
    fill_ops: Vec<PipelineOp>,
    cut_ops: Vec<PipelineOp>,
    merge_mode: Option<MergeMode>,
    merge_ops: Vec<PipelineOp>,
    filter_ops: Vec<PipelineOp>,
    fill_gap_ops: Vec<PipelineOp>,
    align_ops: Vec<PipelineOp>,
    split_ops: Vec<PipelineOp>,
    swap_word_ops: Vec<PipelineOp>,
    swap_dword_ops: Vec<PipelineOp>,
}

#[pymethods]
impl PyPipeline {
    #[new]
    fn new() -> Self {
        Self::default()
    }

    fn __len__(&self) -> usize {
        self.map_star12_ops.len()
            + self.map_star12x_ops.len()
            + self.map_star08_ops.len()
            + self.remap_ops.len()
            + self.dspic_expand_ops.len()
            + self.dspic_shrink_ops.len()
            + self.dspic_clear_ghost_ops.len()
            + self.fill_ops.len()
            + self.cut_ops.len()
            + self.merge_ops.len()
            + self.filter_ops.len()
            + self.fill_gap_ops.len()
            + self.align_ops.len()
            + self.split_ops.len()
            + self.swap_word_ops.len()
            + self.swap_dword_ops.len()
    }

    fn clear(&mut self) {
        *self = Self::default();
    }

    fn apply(&self, source: PyRef<'_, PyHexFile>) -> PyResult<PyHexFile> {
        let mut ordered = Vec::with_capacity(self.__len__());
        ordered.extend_from_slice(&self.map_star12_ops);
        ordered.extend_from_slice(&self.map_star12x_ops);
        ordered.extend_from_slice(&self.map_star08_ops);
        ordered.extend_from_slice(&self.remap_ops);
        ordered.extend_from_slice(&self.dspic_expand_ops);
        ordered.extend_from_slice(&self.dspic_shrink_ops);
        ordered.extend_from_slice(&self.dspic_clear_ghost_ops);
        ordered.extend_from_slice(&self.fill_ops);
        ordered.extend_from_slice(&self.cut_ops);
        ordered.extend_from_slice(&self.merge_ops);
        ordered.extend_from_slice(&self.filter_ops);
        ordered.extend_from_slice(&self.fill_gap_ops);
        ordered.extend_from_slice(&self.align_ops);
        ordered.extend_from_slice(&self.split_ops);
        ordered.extend_from_slice(&self.swap_word_ops);
        ordered.extend_from_slice(&self.swap_dword_ops);
        apply_ops(&source, &ordered)
    }

    fn map_star12(&mut self) {
        self.map_star12_ops.push(PipelineOp::MapStar12);
    }

    fn map_star12x(&mut self) {
        self.map_star12x_ops.push(PipelineOp::MapStar12x);
    }

    fn map_star08(&mut self) {
        self.map_star08_ops.push(PipelineOp::MapStar08);
    }

    fn remap(&mut self, start: u32, end: u32, linear: u32, size: u32, inc: u32) {
        self.remap_ops.push(PipelineOp::Remap(RemapOptions {
            start,
            end,
            linear,
            size,
            inc,
        }));
    }

    fn dspic_expand(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        self.dspic_expand_ops.push(PipelineOp::DspicExpand {
            range: parse_range_arg(range)?,
            target,
        });
        Ok(())
    }

    fn dspic_shrink(&mut self, range: &Bound<'_, PyAny>, target: Option<u32>) -> PyResult<()> {
        self.dspic_shrink_ops.push(PipelineOp::DspicShrink {
            range: parse_range_arg(range)?,
            target,
        });
        Ok(())
    }

    fn dspic_clear_ghost(&mut self, range: &Bound<'_, PyAny>) -> PyResult<()> {
        self.dspic_clear_ghost_ops
            .push(PipelineOp::DspicClearGhost(parse_range_arg(range)?));
        Ok(())
    }

    #[pyo3(signature = (ranges, *, pattern=None, overwrite=false))]
    fn fill(
        &mut self,
        ranges: &Bound<'_, PyAny>,
        pattern: Option<&[u8]>,
        overwrite: bool,
    ) -> PyResult<()> {
        self.fill_ops.push(PipelineOp::Fill {
            ranges: parse_ranges_arg(ranges)?,
            options: FillOptions {
                pattern: parse_fill_pattern(pattern)?,
                overwrite,
            },
        });
        Ok(())
    }

    fn cut(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.cut_ops
            .push(PipelineOp::Cut(parse_ranges_arg(ranges)?));
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
        let merge_mode = parse_merge_mode(mode)?;
        if let Some(existing) = self.merge_mode
            && existing != merge_mode
        {
            return Err(value_error(
                "cannot combine preserve and overwrite merges in Pipeline",
            ));
        }
        self.merge_mode = Some(merge_mode);
        self.merge_ops.push(PipelineOp::Merge {
            other: other.inner.clone(),
            options: MergeOptions {
                mode: merge_mode,
                offset,
                range: range.map(parse_range_arg).transpose()?,
            },
        });
        Ok(())
    }

    fn filter(&mut self, ranges: &Bound<'_, PyAny>) -> PyResult<()> {
        self.filter_ops
            .push(PipelineOp::Filter(parse_ranges_arg(ranges)?));
        Ok(())
    }

    #[pyo3(signature = (*, fill=0xFF))]
    fn fill_gaps(&mut self, fill: u8) {
        self.fill_gap_ops.push(PipelineOp::FillGaps(fill));
    }

    #[pyo3(signature = (alignment, *, fill=0xFF, length=false))]
    fn align(&mut self, alignment: u32, fill: u8, length: bool) {
        self.align_ops.push(PipelineOp::Align(AlignOptions {
            alignment,
            fill_byte: fill,
            align_length: length,
        }));
    }

    fn split(&mut self, max_size: u32) {
        self.split_ops.push(PipelineOp::Split(max_size));
    }

    fn swap(&mut self, mode: &str) -> PyResult<()> {
        match parse_swap_mode(mode)? {
            SwapMode::Word => self.swap_word_ops.push(PipelineOp::Swap(SwapMode::Word)),
            SwapMode::DWord => self.swap_dword_ops.push(PipelineOp::Swap(SwapMode::DWord)),
        }
        Ok(())
    }
}

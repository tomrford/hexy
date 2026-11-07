//! HexView's fixed processing order as one typed recipe.
//!
//! A [`Pipeline`] holds the parameters for each stage; [`Pipeline::run`] applies the
//! configured stages in [`Pipeline::stages`] order, whatever order they were set in.
//! Callers that act between stages (the compat CLI runs `/L` log commands and writes
//! checksum and signature files) drive [`Pipeline::run_stage`] themselves.

use thiserror::Error;

use crate::{
    AddressRange, AlignOptions, ChecksumOptions, DEFAULT_DENSE_SPAN_LIMIT, FillOptions, HexFile,
    MergeOptions, OpsError, Placement, RemapOptions, SignatureError, SignatureSignOptions,
    SignatureVerifyOptions, SwapMode,
};

/// One address-mapping operation; HexView applies at most one per run.
#[derive(Debug, Clone)]
pub enum AddressMap {
    Star12,
    Star12x,
    Star08,
    Remap(RemapOptions),
}

/// A dsPIC conversion source range and optional target address.
#[derive(Debug, Clone, Copy)]
pub struct DspicOp {
    pub range: AddressRange,
    pub target: Option<u32>,
}

/// Bytes written into the gaps of the fill ranges.
#[derive(Debug, Clone)]
pub enum FillData {
    /// Repeating pattern anchored at each range start.
    Pattern(Vec<u8>),
    /// Pseudo-random bytes, reproducible for a given seed.
    Random { seed: u64 },
}

#[derive(Debug, Clone)]
pub struct Fill {
    pub ranges: Vec<AddressRange>,
    pub data: FillData,
}

/// Another image merged into the working image.
#[derive(Debug, Clone)]
pub struct Merge {
    pub file: HexFile,
    pub options: MergeOptions,
}

#[derive(Debug, Clone)]
pub struct ChecksumStage {
    pub options: ChecksumOptions,
    pub placement: Option<Placement>,
}

/// Stage identifiers in execution order. `Checksum(i)` is `checksums[i]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    AddressMap,
    DspicExpand,
    DspicShrink,
    DspicClearGhost,
    Fill,
    Cut,
    Merge,
    AddressFilter,
    FillGaps,
    Align,
    Split,
    Swap,
    Checksum(usize),
    Sign,
    Verify,
}

const BEFORE_CHECKSUMS: [Stage; 12] = [
    Stage::AddressMap,
    Stage::DspicExpand,
    Stage::DspicShrink,
    Stage::DspicClearGhost,
    Stage::Fill,
    Stage::Cut,
    Stage::Merge,
    Stage::AddressFilter,
    Stage::FillGaps,
    Stage::Align,
    Stage::Split,
    Stage::Swap,
];

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error(transparent)]
    Ops(#[from] OpsError),
    #[error(transparent)]
    Signature(#[from] SignatureError),
}

/// Bytes produced by the run, for callers that write them elsewhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipelineOutput {
    /// One result per checksum stage, in order.
    pub checksums: Vec<Vec<u8>>,
    pub signature: Option<Vec<u8>>,
}

/// Stage parameters; unset stages are skipped.
#[derive(Debug, Clone, Default)]
pub struct Pipeline {
    pub address_map: Option<AddressMap>,
    pub dspic_expand: Vec<DspicOp>,
    pub dspic_shrink: Vec<DspicOp>,
    pub dspic_clear_ghost: Vec<AddressRange>,
    /// Fills only the gaps; existing data wins.
    pub fill: Option<Fill>,
    pub cut: Vec<AddressRange>,
    pub merges: Vec<Merge>,
    /// Keep only data inside these ranges; an empty list keeps nothing.
    pub address_filter: Option<Vec<AddressRange>>,
    /// Fill byte for joining all data into one block, up to [`DEFAULT_DENSE_SPAN_LIMIT`].
    pub fill_gaps: Option<u8>,
    pub align: Option<AlignOptions>,
    pub split: Option<u32>,
    pub swap_word: bool,
    pub swap_dword: bool,
    pub checksums: Vec<ChecksumStage>,
    pub sign: Option<SignatureSignOptions>,
    pub verify: Option<SignatureVerifyOptions>,
}

impl Pipeline {
    /// Every stage of this pipeline in execution order, configured or not.
    pub fn stages(&self) -> impl Iterator<Item = Stage> + use<> {
        BEFORE_CHECKSUMS
            .into_iter()
            .chain((0..self.checksums.len()).map(Stage::Checksum))
            .chain([Stage::Sign, Stage::Verify])
    }

    /// Apply all stages to `hexfile` in order.
    pub fn run(&self, hexfile: &mut HexFile) -> Result<PipelineOutput, PipelineError> {
        let mut output = PipelineOutput::default();
        for stage in self.stages() {
            self.run_stage(stage, hexfile, &mut output)?;
        }
        Ok(output)
    }

    /// Apply one stage, recording any bytes it produces in `output`.
    pub fn run_stage(
        &self,
        stage: Stage,
        hexfile: &mut HexFile,
        output: &mut PipelineOutput,
    ) -> Result<(), PipelineError> {
        match stage {
            Stage::AddressMap => match &self.address_map {
                Some(AddressMap::Star12) => hexfile.map_star12()?,
                Some(AddressMap::Star12x) => hexfile.map_star12x()?,
                Some(AddressMap::Star08) => hexfile.map_star08()?,
                Some(AddressMap::Remap(options)) => hexfile.remap(options)?,
                None => {}
            },
            Stage::DspicExpand => {
                for op in &self.dspic_expand {
                    hexfile.dspic_expand(op.range, op.target)?;
                }
            }
            Stage::DspicShrink => {
                for op in &self.dspic_shrink {
                    hexfile.dspic_shrink(op.range, op.target)?;
                }
            }
            Stage::DspicClearGhost => {
                for &range in &self.dspic_clear_ghost {
                    hexfile.dspic_clear_ghost(range)?;
                }
            }
            Stage::Fill => match &self.fill {
                Some(Fill {
                    ranges,
                    data: FillData::Pattern(pattern),
                }) => hexfile.fill_ranges(
                    ranges,
                    &FillOptions {
                        pattern: pattern.clone(),
                        overwrite: false,
                    },
                )?,
                Some(Fill {
                    ranges,
                    data: FillData::Random { seed },
                }) => hexfile.fill_random(ranges, *seed)?,
                None => {}
            },
            Stage::Cut => hexfile.cut_ranges(&self.cut),
            Stage::Merge => {
                for merge in &self.merges {
                    hexfile.merge(&merge.file, &merge.options)?;
                }
            }
            Stage::AddressFilter => {
                if let Some(ranges) = &self.address_filter {
                    hexfile.filter_ranges(ranges);
                }
            }
            Stage::FillGaps => {
                if let Some(fill_byte) = self.fill_gaps {
                    hexfile.fill_gaps(fill_byte, DEFAULT_DENSE_SPAN_LIMIT)?;
                }
            }
            Stage::Align => {
                if let Some(options) = &self.align {
                    hexfile.align(options)?;
                }
            }
            Stage::Split => {
                if let Some(size) = self.split {
                    hexfile.split(size);
                }
            }
            Stage::Swap => {
                if self.swap_word {
                    hexfile.swap_bytes(SwapMode::Word);
                }
                if self.swap_dword {
                    hexfile.swap_bytes(SwapMode::DWord);
                }
            }
            Stage::Checksum(index) => {
                if let Some(stage) = self.checksums.get(index) {
                    let bytes = hexfile.checksum(&stage.options, stage.placement)?;
                    output.checksums.push(bytes);
                }
            }
            Stage::Sign => {
                if let Some(options) = &self.sign {
                    output.signature = Some(hexfile.sign(options)?);
                }
            }
            Stage::Verify => {
                if let Some(options) = &self.verify {
                    hexfile.verify_signature(options)?;
                }
            }
        }
        Ok(())
    }
}

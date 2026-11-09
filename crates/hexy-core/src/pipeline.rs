//! HexView's fixed processing order as one typed recipe.
//!
//! A [`Pipeline`] holds the parameters for each stage; [`Pipeline::run`] applies the
//! configured stages in [`Pipeline::stages`] order, whatever order they were set in.
//! Callers that act between stages (the compat CLI runs `/L` log commands and writes
//! checksum and data processing files) drive [`Pipeline::run_stage`] themselves.
//!
//! The image is kept as HexView keeps its blocks: every configured stage that adds,
//! removes or moves data leaves it normalized, so adjacent data forms one block. Split
//! pieces stay separate blocks (see [`HexFile::blocks`]) until a later stage places
//! data. HexView also joins adjacent data when it loads a file; normalize the input
//! first (`HexFile::normalize`) to reproduce that.

use thiserror::Error;

use crate::{
    AddressRange, AlignOptions, ChecksumOptions, DEFAULT_DENSE_SPAN_LIMIT, DataProcessing,
    FillOptions, HexFile, MergeOptions, OpsError, Placement, ProcessingError, RemapOptions,
    SignatureMethod, SwapMode, VerifyingKey,
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

#[derive(Debug, Clone)]
pub struct DataProcessingStage {
    pub operation: DataProcessing,
    /// Where the operation's output is written into the image.
    pub placement: Option<Placement>,
}

#[derive(Debug, Clone)]
pub struct VerifyStage {
    pub method: SignatureMethod,
    pub key: VerifyingKey,
    pub signature: Vec<u8>,
}

/// Stage identifiers in execution order. `Merge(i)` and `Checksum(i)` address their
/// respective pipeline entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    AddressMap,
    DspicExpand,
    DspicShrink,
    DspicClearGhost,
    Fill,
    Cut,
    Merge(usize),
    AddressFilter,
    FillGaps,
    Align,
    Split,
    Swap,
    RemoveSmallBlocks,
    Checksum(usize),
    DataProcessing,
    Verify,
}

impl Stage {
    /// Every stage in execution order, including stages that have not been configured.
    pub fn in_order(merge_count: usize, checksum_count: usize) -> impl Iterator<Item = Self> {
        [
            Self::AddressMap,
            Self::DspicExpand,
            Self::DspicShrink,
            Self::DspicClearGhost,
            Self::Fill,
            Self::Cut,
        ]
        .into_iter()
        .chain((0..merge_count).map(Self::Merge))
        .chain([
            Self::AddressFilter,
            Self::FillGaps,
            Self::Align,
            Self::Split,
            Self::Swap,
            Self::RemoveSmallBlocks,
        ])
        .chain((0..checksum_count).map(Self::Checksum))
        .chain([Self::DataProcessing, Self::Verify])
    }
}

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error(transparent)]
    Ops(#[from] OpsError),
    #[error(transparent)]
    Processing(#[from] ProcessingError),
}

/// Bytes produced by the run, for callers that write them elsewhere.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PipelineOutput {
    /// One result per checksum stage, in order.
    pub checksums: Vec<Vec<u8>>,
    /// The data processing output, such as a signature.
    pub data_processing: Option<Vec<u8>>,
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
    /// Remove blocks shorter than this many bytes.
    pub remove_small_blocks: Option<u32>,
    pub swap_word: bool,
    pub swap_dword: bool,
    pub checksums: Vec<ChecksumStage>,
    pub data_processing: Option<DataProcessingStage>,
    pub verify: Option<VerifyStage>,
}

impl Pipeline {
    /// Every stage of this pipeline in execution order, configured or not.
    pub fn stages(&self) -> impl Iterator<Item = Stage> + use<> {
        Stage::in_order(self.merges.len(), self.checksums.len())
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
        // Only normalize a failed stage if it committed data before failing.
        let mut wrote_data = false;
        let result = self.apply(stage, hexfile, output, &mut wrote_data);
        if result.is_err() && !wrote_data {
            return result;
        }
        let places_data = match stage {
            Stage::Split | Stage::RemoveSmallBlocks | Stage::Swap | Stage::Verify => false,
            Stage::AddressMap => self.address_map.is_some(),
            Stage::DspicExpand => !self.dspic_expand.is_empty(),
            Stage::DspicShrink => !self.dspic_shrink.is_empty(),
            Stage::DspicClearGhost => !self.dspic_clear_ghost.is_empty(),
            Stage::Fill => self.fill.is_some(),
            Stage::Cut => !self.cut.is_empty(),
            Stage::Merge(index) => self.merges.get(index).is_some(),
            Stage::AddressFilter => self.address_filter.is_some(),
            Stage::FillGaps => self.fill_gaps.is_some(),
            Stage::Align => self.align.is_some(),
            Stage::Checksum(index) => self
                .checksums
                .get(index)
                .is_some_and(|stage| stage.placement.is_some()),
            Stage::DataProcessing => self.data_processing.as_ref().is_some_and(|stage| {
                stage.placement.is_some() || stage.operation.transforms_data()
            }),
        };
        if places_data {
            hexfile.normalize();
        }
        result
    }

    fn apply(
        &self,
        stage: Stage,
        hexfile: &mut HexFile,
        output: &mut PipelineOutput,
        wrote_data: &mut bool,
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
            Stage::Merge(index) => {
                if let Some(merge) = self.merges.get(index) {
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
            Stage::RemoveSmallBlocks => {
                if let Some(min_len) = self.remove_small_blocks {
                    hexfile.remove_small_blocks(min_len as usize);
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
            Stage::DataProcessing => {
                if let Some(stage) = &self.data_processing {
                    output.data_processing = hexfile.process_data_tracked(
                        &stage.operation,
                        stage.placement,
                        wrote_data,
                    )?;
                }
            }
            Stage::Verify => {
                if let Some(stage) = &self.verify {
                    hexfile.verify_signature(stage.method, &stage.key, &stage.signature)?;
                }
            }
        }
        Ok(())
    }
}

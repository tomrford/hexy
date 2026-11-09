use crate::{
    AddressMap, AlignOptions, ChecksumStage, Fill, FillData, HexFile, Merge, MergeMode,
    MergeOptions, Pipeline, PipelineOutput, Stage,
};

use super::error::CliError;
use super::io::{
    FsProvider, ReadProvider, checksum_options, load_binary_input, load_hex_ascii_input,
    load_input, load_intel_hex_16bit_input, validate_porsche_output_args, write_checksum_text,
    write_output_for_args, write_signature_text,
};
use super::log::execute_log;
use super::signature::{
    data_processing_method, sign_options, signature_verify_method, verify_options,
};
use super::types::{Args, ChecksumParams, ChecksumTarget, OutputFormat, ParseArgError};
use std::time::{SystemTime, UNIX_EPOCH};

impl Args {
    fn validate_supported_features(&self) -> Result<(), CliError> {
        if !self.merge_transparent.is_empty() && !self.merge_opaque.is_empty() {
            return Err(CliError::Unsupported(
                "cannot combine /MT and /MO in one command".into(),
            ));
        }
        if self.s12_map && self.s12x_map {
            return Err(CliError::Unsupported(
                "cannot combine /S12MAP and /S12XMAP".into(),
            ));
        }
        if self.s08_map && (self.s12_map || self.s12x_map) {
            return Err(CliError::Unsupported(
                "cannot combine /S08MAP with /S12MAP or /S12XMAP".into(),
            ));
        }
        if self.remap.is_some() && (self.s12_map || self.s12x_map || self.s08_map) {
            return Err(CliError::Unsupported(
                "cannot combine /REMAP with /S08MAP, /S12MAP, or /S12XMAP".into(),
            ));
        }
        if self.postbuild.is_some() {
            return Err(CliError::Unsupported(
                "postbuild (/PB) is not supported yet".into(),
            ));
        }
        if let Some(ref params) = self.data_processing {
            data_processing_method(params.method)?;
        }
        if let Some(ref params) = self.signature_verify {
            signature_verify_method(params.method)?;
        }
        if let (Some(dp), Some(sv)) = (&self.data_processing, &self.signature_verify)
            && dp.placement.is_some()
        {
            return Err(CliError::Unsupported(format!(
                "placed data processing (/DP{}) cannot be combined with signature verification (/SV{}) in one command",
                dp.method, sv.method
            )));
        }
        if self.import_binary.is_some() && self.import_hex_ascii.is_some() {
            return Err(CliError::Unsupported(
                "binary import (/IN) cannot be combined with HEX ASCII import (/IA)".into(),
            ));
        }
        if self.import_i16.is_some()
            && (self.import_binary.is_some() || self.import_hex_ascii.is_some())
        {
            return Err(CliError::Unsupported(
                "16-bit Intel HEX import (/II2) cannot be combined with /IN or /IA".into(),
            ));
        }
        if (self.import_binary.is_some() || self.import_i16.is_some()) && self.input_file.is_some()
        {
            return Err(CliError::Unsupported(
                "explicit import (/IN, /II2) cannot be combined with input file".into(),
            ));
        }
        if self.checksum.is_some() && !self.checksum_multi.is_empty() {
            return Err(CliError::Unsupported(
                "cannot combine /CS* with /CSM* in one command".into(),
            ));
        }
        Ok(())
    }

    /// Execute the parsed arguments in compatibility processing order.
    pub fn execute(&self) -> Result<(), CliError> {
        self.execute_with_provider(&FsProvider)
    }

    pub(super) fn execute_with_provider<P: ReadProvider>(
        &self,
        provider: &P,
    ) -> Result<(), CliError> {
        self.validate_supported_features()?;
        validate_porsche_output_args(self, provider)?;

        let mut hexfile = self.load_hexfile(provider)?;
        hexfile.normalize();
        let mut pipeline = self.pipeline();
        let mut output = PipelineOutput::default();
        let mut checksum_error = None;
        let checksum_count = if matches!(self.output_format, Some(OutputFormat::Porsche)) {
            0
        } else {
            self.checksum_params().len()
        };
        let merge_count = self.merge_transparent.len() + self.merge_opaque.len();
        for stage in Stage::in_order(merge_count, checksum_count) {
            self.before_stage(stage, &mut pipeline, provider)?;
            match pipeline.run_stage(stage, &mut hexfile, &mut output) {
                Ok(()) => self.after_stage(stage, &mut hexfile, &output, provider)?,
                Err(e) => {
                    let error = CliError::Other(format!("{}: {e}", self.stage_flag(stage)));
                    if !matches!(stage, Stage::Checksum(_)) {
                        return Err(error);
                    }
                    checksum_error.get_or_insert(error);
                    output.checksums.push(Vec::new());
                }
            }
        }
        write_output_for_args(self, &hexfile, provider)?;
        checksum_error.map_or(Ok(()), Err)
    }

    /// The core pipeline for these flags; each field is set only from its own flags.
    fn pipeline(&self) -> Pipeline {
        let address_map = if self.s12_map {
            Some(AddressMap::Star12)
        } else if self.s12x_map {
            Some(AddressMap::Star12x)
        } else if self.s08_map {
            Some(AddressMap::Star08)
        } else {
            self.remap.clone().map(AddressMap::Remap)
        };
        let fill = (!self.fill_ranges.is_empty()).then(|| Fill {
            ranges: self.fill_ranges.clone(),
            data: if self.fill_pattern_set {
                FillData::Pattern(self.fill_pattern.clone())
            } else {
                FillData::Random {
                    seed: random_seed(),
                }
            },
        });
        Pipeline {
            address_map,
            dspic_expand: self.dspic_expand.clone(),
            dspic_shrink: self.dspic_shrink.clone(),
            dspic_clear_ghost: self.dspic_clear_ghost.clone(),
            fill,
            cut: self.cut_ranges.clone(),
            address_filter: self.address_range.clone(),
            fill_gaps: self.fill_all.then_some(self.align_fill),
            align: self.align_address.map(|alignment| AlignOptions {
                alignment,
                fill_byte: self.align_fill,
                align_length: self.align_length,
            }),
            split: self.split(),
            remove_small_blocks: self.remove_blocks_below,
            swap_word: self.swap_word,
            swap_dword: self.swap_long,
            ..Default::default()
        }
    }

    /// Resolve fallible inputs when their stage is reached, after earlier side effects.
    fn before_stage<P: ReadProvider>(
        &self,
        stage: Stage,
        pipeline: &mut Pipeline,
        provider: &P,
    ) -> Result<(), CliError> {
        match stage {
            Stage::Merge(index) => {
                let (params, mode) = if self.merge_transparent.is_empty() {
                    (&self.merge_opaque[index], MergeMode::Overwrite)
                } else {
                    (&self.merge_transparent[index], MergeMode::Preserve)
                };
                pipeline.merges.push(Merge {
                    file: load_input(provider, &params.file)?,
                    options: MergeOptions {
                        mode,
                        offset: params.offset.unwrap_or(0),
                        range: params.range,
                    },
                });
            }
            Stage::Checksum(index) => {
                let (params, flag) = self.checksum_stage(index);
                pipeline.checksums.push(ChecksumStage {
                    options: checksum_options(params, &flag, provider)?,
                    placement: match params.target {
                        ChecksumTarget::Place(placement) => Some(placement),
                        ChecksumTarget::None | ChecksumTarget::File(_) => None,
                    },
                });
            }
            Stage::Sign => {
                pipeline.sign = self
                    .data_processing
                    .as_ref()
                    .map(sign_options)
                    .transpose()?;
            }
            Stage::Verify => {
                pipeline.verify = self
                    .signature_verify
                    .as_ref()
                    .map(verify_options)
                    .transpose()?;
            }
            _ => {}
        }
        Ok(())
    }

    /// Compat side effects between stages: `/L` runs after `/AR`, and checksum and
    /// signature file targets are written as soon as their bytes exist.
    fn after_stage<P: ReadProvider>(
        &self,
        stage: Stage,
        hexfile: &mut HexFile,
        output: &PipelineOutput,
        provider: &P,
    ) -> Result<(), CliError> {
        match stage {
            Stage::AddressFilter => {
                if let Some(ref path) = self.log_file {
                    let content = provider
                        .read_string(path)
                        .map_err(|e| CliError::Other(format!("/L: {e}")))?;
                    execute_log(hexfile, &content)?;
                }
            }
            Stage::Checksum(index) => {
                let (params, flag) = self.checksum_stage(index);
                if let (ChecksumTarget::File(path), Some(bytes)) =
                    (&params.target, output.checksums.get(index))
                {
                    write_checksum_text(path, bytes)
                        .map_err(|e| CliError::Other(format!("{flag}: {e}")))?;
                }
            }
            Stage::Sign => {
                if let (Some(dp), Some(signature)) = (&self.data_processing, &output.signature)
                    && let Some(path) = &dp.output_file
                {
                    write_signature_text(path, signature)
                        .map_err(|e| CliError::Other(format!("/DP{}: {e}", dp.method)))?;
                }
            }
            _ => {}
        }
        Ok(())
    }

    /// The flag named in errors from `stage`.
    fn stage_flag(&self, stage: Stage) -> String {
        let flag = match stage {
            Stage::AddressMap if self.s12_map => "/S12MAP",
            Stage::AddressMap if self.s12x_map => "/S12XMAP",
            Stage::AddressMap if self.s08_map => "/S08MAP",
            Stage::AddressMap => "/REMAP",
            Stage::DspicExpand => "/CDSPX",
            Stage::DspicShrink => "/CDSPS",
            Stage::DspicClearGhost => "/CDSPG",
            Stage::Fill => "/FR",
            Stage::Cut => "/CR",
            Stage::Merge(_) if self.merge_transparent.is_empty() => "/MO",
            Stage::Merge(_) => "/MT",
            Stage::AddressFilter => "/AR",
            Stage::FillGaps => "/FA",
            Stage::Align => "/AD/AL",
            Stage::Split => "/SB",
            Stage::RemoveSmallBlocks => "/RB",
            Stage::Swap => "/SWAPWORD/SWAPLONG",
            Stage::Checksum(index) => return self.checksum_stage(index).1,
            Stage::Sign => {
                let method = self.data_processing.as_ref().map_or(0, |dp| dp.method);
                return format!("/DP{method}");
            }
            Stage::Verify => {
                let method = self.signature_verify.as_ref().map_or(0, |sv| sv.method);
                return format!("/SV{method}");
            }
        };
        flag.to_owned()
    }

    /// HexView ignores `/SB` below 0x100 bytes with a warning.
    fn split(&self) -> Option<u32> {
        let size = self.split_block_size?;
        if size < 0x100 {
            if !self.silent {
                eprintln!("Warning: invalid parameter for /SB; ignoring it");
            }
            return None;
        }
        Some(size)
    }

    /// `/CS` and `/CSM` are exclusive, so checksum stages come from one of them.
    fn checksum_params(&self) -> &[ChecksumParams] {
        self.checksum
            .as_ref()
            .map_or(self.checksum_multi.as_slice(), std::slice::from_ref)
    }

    /// Parameters and flag name of checksum stage `index`.
    fn checksum_stage(&self, index: usize) -> (&ChecksumParams, String) {
        let params = &self.checksum_params()[index];
        let base = match (self.checksum.is_some(), params.little_endian) {
            (true, false) => "/CS",
            (true, true) => "/CSR",
            (false, false) => "/CSM",
            (false, true) => "/CSMR",
        };
        (params, format!("{base}{}", params.algorithm))
    }

    fn load_hexfile<P: ReadProvider>(&self, provider: &P) -> Result<HexFile, CliError> {
        if let Some(ref import) = self.import_binary {
            return load_binary_input(provider, &import.file, import.offset);
        }
        if let Some(ref import) = self.import_hex_ascii {
            let ascii = load_hex_ascii_input(provider, &import.file, import.offset)?;
            if let Some(ref path) = self.input_file {
                let mut base = load_input(provider, path)?;
                if super::io::hexfiles_overlap(&base, &ascii) {
                    if !self.silent {
                        eprintln!("Warning: /IA overlaps input file; ignoring input file");
                    }
                    return Ok(ascii);
                }
                for segment in ascii.segments() {
                    base.append_segment(segment.clone());
                }
                return Ok(base);
            }
            return Ok(ascii);
        }
        if let Some(ref import) = self.import_i16 {
            return load_intel_hex_16bit_input(provider, import);
        }
        if let Some(ref path) = self.input_file {
            return load_input(provider, path);
        }
        if self.log_file.is_some()
            || !self.merge_transparent.is_empty()
            || !self.merge_opaque.is_empty()
        {
            return Ok(HexFile::new());
        }
        Err(ParseArgError::MissingInputFile.into())
    }
}

/// `/FR` without `/FP` fills with fresh random bytes on every run.
fn random_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

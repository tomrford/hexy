use std::path::{Path, PathBuf};

use crate::{
    AddressMap, AlignOptions, ChecksumOptions, ChecksumStage, Fill, FillData, HexFile, Merge,
    MergeMode, MergeOptions, Pipeline, PipelineOutput, Stage,
};

use super::error::CliError;
use super::export::write_output_for_args;
use super::io::{checksum_options, load_input, write_checksum_text};
use super::log::execute_log;
use super::processing::{
    data_processing_stage, validate_data_processing, validate_signature_verify, verify_stage,
    write_data_processing_output,
};
use super::report::Report;
use super::types::{Args, ChecksumParams, ChecksumTarget, ImportKind};
use super::validation::{Validation, hsm_signature_params, hsm_validation_stage};
use std::time::{SystemTime, UNIX_EPOCH};

impl Args {
    fn validate_supported_features(&self, report: &Report) -> Result<(), CliError> {
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
        if let Some(ref params) = self.data_processing {
            validate_data_processing(params, report)?;
        }
        if let Some(ref params) = self.signature_verify {
            validate_signature_verify(params)?;
        }
        Ok(())
    }

    /// Execute the parsed arguments in compatibility processing order.
    pub(super) fn execute(&self, report: &Report) -> Result<(), CliError> {
        self.validate_supported_features(report)?;

        let mut hexfile = self.load_hexfile(report)?;
        // HexView joins adjacent data into one block when it loads a file.
        hexfile.normalize();
        let mut pipeline = self.pipeline(report);
        let mut validation: Option<Validation> = None;
        let mut output = PipelineOutput::default();
        let dir = self.processing_dir();
        let mut stage_error = None;
        for stage in pipeline.stages() {
            let result = if let Stage::Merge(index) = stage {
                self.merge_stage(index, &mut pipeline, &mut hexfile, &mut output)?;
                Ok(())
            } else {
                self.prepare_stage(stage, &mut pipeline, &mut validation, report, &dir)
                    .and_then(|deferred| {
                        pipeline
                            .run_stage(stage, &mut hexfile, &mut output)
                            .map_err(|e| e.to_string())?;
                        deferred.map_or(Ok(()), Err)
                    })
            };
            let result = result.and_then(|()| match (stage, &validation, &output.validation) {
                (Stage::Validation, Some(validation), Some(structure)) => {
                    validation.finish(structure).map_err(|e| e.to_string())
                }
                _ => Ok(()),
            });
            match result {
                Ok(()) => {
                    if let Err(error) = self.after_stage(stage, &mut hexfile, &output, &dir) {
                        if !matches!(stage, Stage::Merge(_) | Stage::AddressFilter) {
                            return Err(error);
                        }
                        // HexView reports a rejected merge range or a failed log
                        // command and carries on.
                        stage_error.get_or_insert(error);
                    }
                }
                Err(e) => {
                    let error = CliError::Other(format!("{}: {e}", self.stage_flag(stage)));
                    if !matches!(
                        stage,
                        Stage::Checksum(_)
                            | Stage::DataProcessing
                            | Stage::Verify
                            | Stage::HsmValidation
                            | Stage::Validation
                    ) {
                        return Err(error);
                    }
                    // HexView reports a failed stage but runs the remaining stages
                    // and exports; the placeholder keeps later checksum results at
                    // their stage index.
                    stage_error.get_or_insert(error);
                    if let Stage::Checksum(_) = stage {
                        output.checksums.push(Vec::new());
                    }
                }
            }
        }
        write_output_for_args(self, &hexfile, report)?;
        stage_error.map_or(Ok(()), Err)
    }

    /// The folder `/DP` and `/SV` file references resolve against.
    fn processing_dir(&self) -> PathBuf {
        self.input_file
            .as_deref()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap_or_default()
    }

    /// Checksum, `/DP`, `/SV` and validation parameters are read when their stage runs,
    /// so that a method HexView does not know fails only its stage and `/SV` can read
    /// `/DP`'s output. `Ok(Some(error))` runs the stage and then fails it.
    fn prepare_stage(
        &self,
        stage: Stage,
        pipeline: &mut Pipeline,
        validation: &mut Option<Validation>,
        report: &Report,
        dir: &Path,
    ) -> Result<Option<String>, String> {
        match stage {
            Stage::Checksum(index) => {
                pipeline.checksums[index].options = checksum_options(self.checksum_stage(index).0)?;
            }
            Stage::Validation if self.validation => {
                *validation = Validation::from_ini(self, report).map_err(|e| e.to_string())?;
                pipeline.validation = validation.as_ref().map(|v| v.stage.clone());
            }
            Stage::HsmValidation => {
                if let Some(placement) = self.hsm_validation {
                    let (stage, error) = hsm_validation_stage(self, placement, dir)?;
                    pipeline.hsm_validation = Some(stage);
                    return Ok(error);
                }
            }
            Stage::DataProcessing => {
                pipeline.data_processing = self
                    .data_processing
                    .as_ref()
                    .map(|params| data_processing_stage(params, dir))
                    .transpose()?
                    .flatten();
            }
            Stage::Verify => {
                pipeline.verify = self
                    .signature_verify
                    .as_ref()
                    .map(|params| verify_stage(params, dir))
                    .transpose()?;
            }
            _ => {}
        }
        Ok(None)
    }

    /// The core pipeline for these flags; each field is set only from its own flags.
    /// Checksum options and the processing and validation stages are set by
    /// [`Self::prepare_stage`].
    fn pipeline(&self, report: &Report) -> Pipeline {
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
            data: match &self.fill_pattern {
                Some(pattern) => FillData::Pattern(pattern.clone()),
                None => FillData::Random {
                    seed: random_seed(),
                },
            },
        });
        // One slot per parameter group; wildcard matches replace it as they run.
        let merges = self
            .merge
            .iter()
            .flat_map(|spec| {
                spec.files.iter().map(move |_| Merge {
                    file: HexFile::new(),
                    options: MergeOptions {
                        mode: spec.mode,
                        ..Default::default()
                    },
                })
            })
            .collect();
        let checksums = self
            .checksum_params()
            .iter()
            .map(|params| ChecksumStage {
                options: ChecksumOptions::default(),
                placement: match params.target {
                    ChecksumTarget::Place(placement) => Some(placement),
                    ChecksumTarget::None | ChecksumTarget::File(_) => None,
                },
            })
            .collect();

        Pipeline {
            address_map,
            dspic_expand: self.dspic_expand.clone(),
            dspic_shrink: self.dspic_shrink.clone(),
            dspic_clear_ghost: self.dspic_clear_ghost.clone(),
            fill,
            cut: self.cut_ranges.clone(),
            merges,
            address_filter: self.address_range.clone(),
            fill_gaps: self.fill_all.then_some(self.align_fill),
            align: self.align(report),
            split: self.split(report),
            remove_small_blocks: self.remove_blocks_below,
            swap_word: self.swap_word,
            swap_dword: self.swap_long,
            checksums,
            data_processing: None,
            verify: None,
            hsm_validation: None,
            validation: None,
        }
    }

    /// Resolve each wildcard group at its stage and apply matches before reading
    /// later files. Only the first match receives the group's offset and range.
    fn merge_stage(
        &self,
        index: usize,
        pipeline: &mut Pipeline,
        hexfile: &mut HexFile,
        output: &mut PipelineOutput,
    ) -> Result<(), CliError> {
        let Some(spec) = &self.merge else {
            return Ok(());
        };
        let params = &spec.files[index];
        let stage = Stage::Merge(index);
        for (match_index, path) in merge_files(&params.file)?.iter().enumerate() {
            let first = match_index == 0;
            pipeline.merges[index] = Merge {
                file: load_input(path)?,
                options: MergeOptions {
                    mode: spec.mode,
                    offset: params.offset.filter(|_| first).unwrap_or(0),
                    range: params.range.filter(|_| first),
                },
            };
            pipeline
                .run_stage(stage, hexfile, output)
                .map_err(|error| CliError::Other(format!("{}: {error}", self.stage_flag(stage))))?;
        }
        Ok(())
    }

    /// Compat side effects between stages: `/L` runs after `/AR`, and checksum and
    /// data processing files are written as soon as their bytes exist.
    fn after_stage(
        &self,
        stage: Stage,
        hexfile: &mut HexFile,
        output: &PipelineOutput,
        dir: &Path,
    ) -> Result<(), CliError> {
        match stage {
            Stage::Merge(index) => {
                let spec = self.merge.as_ref();
                if spec.is_some_and(|spec| spec.files[index].invalid_range) {
                    return Err(CliError::Other(format!(
                        "{}: invalid merge range; merged the whole file",
                        self.stage_flag(stage)
                    )));
                }
            }
            // HexView runs /L after /AR and ignores a log file it cannot read.
            Stage::AddressFilter => {
                if let Some(content) = self
                    .log_file
                    .as_deref()
                    .and_then(|path| std::fs::read(path).ok())
                {
                    execute_log(hexfile, &String::from_utf8_lossy(&content))?;
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
            Stage::HsmValidation => {
                if let Some(signature) = &output.hsm_signature
                    && let Some(params) = hsm_signature_params(self)
                        .map_err(|e| CliError::Other(format!("/vshsm: {e}")))?
                {
                    write_data_processing_output(&params, dir, signature)
                        .map_err(|e| CliError::Other(format!("/vshsm: {e}")))?;
                }
            }
            Stage::DataProcessing => {
                if let (Some(dp), Some(bytes)) = (&self.data_processing, &output.data_processing) {
                    write_data_processing_output(dp, dir, bytes)
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
            Stage::Merge(_) => match self.merge.as_ref().map(|spec| spec.mode) {
                Some(MergeMode::Preserve) => "/MT",
                _ => "/MO",
            },
            Stage::AddressFilter => "/AR",
            Stage::FillGaps => "/FA",
            Stage::Align => "/AD/AL",
            Stage::Split => "/SB",
            Stage::RemoveSmallBlocks => "/RB",
            Stage::Swap => "/SWAPWORD/SWAPLONG",
            Stage::Checksum(index) => return self.checksum_stage(index).1,
            Stage::DataProcessing => {
                let method = self.data_processing.as_ref().map_or(0, |dp| dp.method);
                return format!("/DP{method}");
            }
            Stage::Verify => {
                let method = self.signature_verify.as_ref().map_or(0, |sv| sv.method);
                return format!("/SV{method}");
            }
            Stage::HsmValidation => "/vshsm",
            Stage::Validation => "/vs",
        };
        flag.to_owned()
    }

    /// HexView ignores `/SB` below 0x100 bytes with a warning.
    fn split(&self, report: &Report) -> Option<u32> {
        let size = self.split_block_size?;
        if size < 0x100 {
            report.warn("invalid parameter for /SB; ignoring it");
            return None;
        }
        Some(size)
    }

    /// `/AD` aligns block starts and `/AL` block lengths, to its own value or without
    /// one to the `/AD` value. HexView warns about an `/AD` that is not a power of two.
    fn align(&self, report: &Report) -> Option<AlignOptions> {
        let address_alignment = self.align_address.unwrap_or(0);
        if address_alignment > 1 && !address_alignment.is_power_of_two() {
            report.warn(&format!(
                "/AD: 0x{address_alignment:X} is not a power of two; alignment may not be what you expect"
            ));
        }
        let length_alignment = match self.align_length {
            None => 0,
            Some(0) => address_alignment,
            Some(length) => length,
        };
        (address_alignment != 0 || length_alignment != 0).then_some(AlignOptions {
            address_alignment,
            length_alignment,
            fill_byte: self.align_fill,
        })
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

    /// The positional input file, or without one the last import. HexView ignores an
    /// import next to an input file with a warning, and starts empty without either.
    fn load_hexfile(&self, report: &Report) -> Result<HexFile, CliError> {
        if let Some(ref path) = self.input_file {
            if self.import.is_some() {
                report.warn("cannot import a file next to an input file; ignoring the import");
            }
            return load_input(path);
        }
        let Some(import) = &self.import else {
            return Ok(HexFile::new());
        };
        let content = std::fs::read(&import.file)?;
        Ok(match import.kind {
            ImportKind::Binary => crate::parse_binary(&content, import.offset)?,
            ImportKind::HexAscii => crate::parse_hex_ascii(&content, import.offset)?,
            ImportKind::IntelHex16 => crate::parse_intel_hex_16bit(&content)?,
        })
    }
}

/// The files a `/MO` or `/MT` name refers to: itself, or with `*` or `?` in the file
/// name every match in its folder, ordered by name and matched without regard to case.
fn merge_files(path: &Path) -> Result<Vec<PathBuf>, CliError> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    if !name.contains(['*', '?']) {
        return Ok(vec![path.to_path_buf()]);
    }
    let dir = path.parent().filter(|dir| !dir.as_os_str().is_empty());
    let pattern: Vec<char> = name.to_lowercase().chars().collect();
    let mut matches = Vec::new();
    for entry in std::fs::read_dir(dir.unwrap_or(Path::new(".")))? {
        let entry = entry?;
        let file_name = entry.file_name().to_string_lossy().to_lowercase();
        let chars: Vec<char> = file_name.chars().collect();
        if entry.file_type()?.is_file() && wildcard_match(&pattern, &chars) {
            matches.push((
                file_name,
                dir.map_or_else(
                    || entry.file_name().into(),
                    |dir| dir.join(entry.file_name()),
                ),
            ));
        }
    }
    matches.sort();
    Ok(matches.into_iter().map(|(_, path)| path).collect())
}

/// `*` matches any run of characters and `?` any one character.
fn wildcard_match(pattern: &[char], name: &[char]) -> bool {
    match pattern.split_first() {
        None => name.is_empty(),
        Some(('*', rest)) => (0..=name.len()).any(|skip| wildcard_match(rest, &name[skip..])),
        Some((&c, rest)) => name
            .split_first()
            .is_some_and(|(&n, name)| (c == '?' || c == n) && wildcard_match(rest, name)),
    }
}

/// `/FR` without `/FP` fills with fresh random bytes on every run.
fn random_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos() as u64)
}

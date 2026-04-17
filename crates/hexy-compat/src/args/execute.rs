use crate::{
    AlignOptions, ChecksumAlgorithm, FillOptions, MergeMode, MergeOptions, RemapOptions, Segment,
    SwapMode, execute_log_commands, parse_log_commands,
};

use super::error::{CliError, ExecuteOutput};
use super::io::{
    FsProvider, ReadProvider, load_binary_input, load_hex_ascii_input, load_input,
    load_intel_hex_16bit_input, write_output_for_args,
};
use super::signature::{
    apply_data_processing, apply_signature_verification, is_supported_data_processing_method,
    is_supported_signature_verify_method,
};
use super::types::{Args, ChecksumParams, ChecksumTarget, ParseArgError};
use std::time::{SystemTime, UNIX_EPOCH};

impl Args {
    fn wrap_error<T, E: std::fmt::Display>(
        &self,
        opt: &str,
        res: Result<T, E>,
    ) -> Result<T, CliError> {
        res.map_err(|e| CliError::Other(format!("{opt}: {e}")))
    }

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
        if let Some(ref params) = self.data_processing
            && !is_supported_data_processing_method(params.method)
        {
            return Err(CliError::Unsupported(format!(
                "data processing (/DP{}) is not supported yet",
                params.method
            )));
        }
        if let Some(ref params) = self.signature_verify
            && !is_supported_signature_verify_method(params.method)
        {
            return Err(CliError::Unsupported(format!(
                "signature verification (/SV{}) is not supported yet",
                params.method
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

    /// Execute the parsed arguments in HexView processing order.
    pub fn execute(&self) -> Result<ExecuteOutput, CliError> {
        let provider = FsProvider;
        self.execute_with_provider(&provider)
    }

    pub(super) fn execute_with_provider<P: ReadProvider>(
        &self,
        provider: &P,
    ) -> Result<ExecuteOutput, CliError> {
        self.validate_supported_features()?;

        let mut hexfile = self.load_hexfile(provider)?;
        self.execute_operations(&mut hexfile, provider)?;

        let checksum_bytes = self.apply_checksums(&mut hexfile)?;
        let _signature_bytes = self.apply_data_processing(&mut hexfile)?;
        self.apply_signature_verification(&hexfile)?;
        self.write_outputs(&hexfile, provider)?;

        Ok(ExecuteOutput { checksum_bytes })
    }

    fn execute_operations<P: ReadProvider>(
        &self,
        hexfile: &mut crate::HexFile,
        provider: &P,
    ) -> Result<(), CliError> {
        if self.s12_map {
            self.wrap_error("/S12MAP", hexfile.map_star12())?;
        }
        if self.s12x_map {
            self.wrap_error("/S12XMAP", hexfile.map_star12x())?;
        }
        if self.s08_map {
            self.wrap_error("/S08MAP", hexfile.map_star08())?;
        }
        if let Some(ref remap) = self.remap {
            let options = RemapOptions {
                start: remap.start,
                end: remap.end,
                linear: remap.linear,
                size: remap.size,
                inc: remap.inc,
            };
            self.wrap_error("/REMAP", hexfile.remap(&options))?;
        }

        for op in &self.dspic_expand {
            self.wrap_error("/CDSPX", hexfile.dspic_expand(op.range, op.target))?;
        }
        for op in &self.dspic_shrink {
            self.wrap_error("/CDSPS", hexfile.dspic_shrink(op.range, op.target))?;
        }
        for range in &self.dspic_clear_ghost {
            self.wrap_error("/CDSPG", hexfile.dspic_clear_ghost(*range))?;
        }

        if self.fill_pattern_set {
            let options = FillOptions {
                pattern: self.fill_pattern.clone(),
                overwrite: false,
            };
            hexfile.fill_ranges(&self.fill_ranges, &options);
        } else {
            for range in &self.fill_ranges {
                let data = random_fill_bytes(*range);
                hexfile.prepend_segment(Segment::new(range.start(), data));
            }
        }

        hexfile.cut_ranges(&self.cut_ranges);

        for merge in &self.merge_transparent {
            let other = load_input(provider, &merge.file)?;
            let options = MergeOptions {
                mode: MergeMode::Preserve,
                offset: merge.offset.unwrap_or(0),
                range: merge.range,
            };
            self.wrap_error("/MT", hexfile.merge(&other, &options))?;
        }
        for merge in &self.merge_opaque {
            let other = load_input(provider, &merge.file)?;
            let options = MergeOptions {
                mode: MergeMode::Overwrite,
                offset: merge.offset.unwrap_or(0),
                range: merge.range,
            };
            self.wrap_error("/MO", hexfile.merge(&other, &options))?;
        }

        if !self.address_range.is_empty() {
            hexfile.filter_ranges(&self.address_range);
        }

        if let Some(ref path) = self.log_file {
            let content = provider
                .read_string(path)
                .map_err(|e| CliError::Other(format!("/L: {e}")))?;
            let commands =
                parse_log_commands(&content).map_err(|e| CliError::Other(format!("/L: {e}")))?;
            execute_log_commands(hexfile, &commands, |log_path| {
                load_input(provider, log_path)
            })
            .map_err(|e| CliError::Other(format!("/L: {e}")))?;
        }

        if self.fill_all {
            hexfile.fill_gaps(self.align_fill);
        }

        if let Some(alignment) = self.align_address {
            let options = AlignOptions {
                alignment,
                fill_byte: self.align_fill,
                align_length: self.align_length,
            };
            self.wrap_error("/AD/AL", hexfile.align(&options))?;
        }

        if let Some(size) = self.split_block_size {
            hexfile.split(size);
        }

        if self.swap_word {
            self.wrap_error("/SWAPWORD", hexfile.swap_bytes(SwapMode::Word))?;
        }
        if self.swap_long {
            self.wrap_error("/SWAPLONG", hexfile.swap_bytes(SwapMode::DWord))?;
        }

        Ok(())
    }

    fn load_hexfile<P: ReadProvider>(&self, provider: &P) -> Result<crate::HexFile, CliError> {
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
            return Ok(crate::HexFile::new());
        }
        Err(ParseArgError::MissingInputFile.into())
    }

    fn apply_checksums(&self, hexfile: &mut crate::HexFile) -> Result<Option<Vec<u8>>, CliError> {
        let mut legacy_bytes = None;
        if let Some(cs_params) = self.checksum.as_ref() {
            legacy_bytes = Some(self.run_checksum(hexfile, cs_params, false)?);
        }
        for cs_params in &self.checksum_multi {
            self.run_checksum(hexfile, cs_params, true)?;
        }
        Ok(legacy_bytes)
    }

    fn run_checksum(
        &self,
        hexfile: &mut crate::HexFile,
        cs_params: &ChecksumParams,
        is_multi: bool,
    ) -> Result<Vec<u8>, CliError> {
        let opt_base = if is_multi {
            if cs_params.little_endian {
                "/CSMR"
            } else {
                "/CSM"
            }
        } else if cs_params.little_endian {
            "/CSR"
        } else {
            "/CS"
        };
        let opt = format!("{opt_base}{}", cs_params.algorithm);
        let algorithm =
            self.wrap_error(&opt, ChecksumAlgorithm::from_index(cs_params.algorithm))?;
        let forced_range = cs_params
            .forced_range
            .as_ref()
            .map(|forced| crate::ForcedRange {
                range: forced.range,
                pattern: forced.pattern.clone(),
            });
        let options = crate::ChecksumOptions {
            algorithm,
            range: cs_params.range,
            little_endian_output: cs_params.little_endian,
            forced_range,
            exclude_ranges: cs_params.exclude_ranges.clone(),
            target_exclude: None,
        };
        let target = self.resolve_checksum_target(hexfile, &cs_params.target);
        let result = self.wrap_error(&opt, hexfile.checksum(&options, &target))?;
        if let ChecksumTarget::File(path) = &cs_params.target {
            let formatted = result
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(",");
            self.wrap_error(&opt, std::fs::write(path, formatted))?;
        }
        Ok(result)
    }

    fn resolve_checksum_target(
        &self,
        hexfile: &crate::HexFile,
        target: &ChecksumTarget,
    ) -> crate::ChecksumTarget {
        match target {
            ChecksumTarget::Address(addr) => crate::ChecksumTarget::Address(*addr),
            ChecksumTarget::Append => crate::ChecksumTarget::Append,
            ChecksumTarget::Begin => {
                if let Some(start) = hexfile.min_address() {
                    crate::ChecksumTarget::Address(start)
                } else {
                    crate::ChecksumTarget::Append
                }
            }
            ChecksumTarget::Prepend => crate::ChecksumTarget::Prepend,
            ChecksumTarget::OverwriteEnd => crate::ChecksumTarget::OverwriteEnd,
            ChecksumTarget::File(path) => crate::ChecksumTarget::File(path.clone()),
        }
    }

    fn apply_data_processing(
        &self,
        hexfile: &mut crate::HexFile,
    ) -> Result<Option<Vec<u8>>, CliError> {
        let Some(ref params) = self.data_processing else {
            return Ok(None);
        };
        apply_data_processing(hexfile, params)
    }

    fn apply_signature_verification(&self, hexfile: &crate::HexFile) -> Result<(), CliError> {
        let Some(ref params) = self.signature_verify else {
            return Ok(());
        };
        apply_signature_verification(hexfile, params)
    }

    fn write_outputs<P: ReadProvider>(
        &self,
        hexfile: &crate::HexFile,
        provider: &P,
    ) -> Result<(), CliError> {
        write_output_for_args(self, hexfile, provider)
    }
}

fn random_fill_bytes(range: crate::AddressRange) -> Vec<u8> {
    let len = range.length() as usize;
    if len == 0 {
        return Vec::new();
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let mut state = {
        let seed = now ^ ((range.start() as u64) << 32) ^ (range.length() as u64);
        if seed == 0 { 0x9E3779B97F4A7C15 } else { seed }
    };

    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        out.push((state >> 32) as u8);
    }
    out
}

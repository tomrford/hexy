use std::path::PathBuf;

use crate::{
    AddressRange, DspicOp, ForcedRange, HexAsciiWriteOptions, IntelHexWriteOptions, MergeMode,
    Placement, RemapOptions, SRecordWriteOptions,
};

use super::parse::parse_option;
use super::processing::{DataProcessingParams, SignatureVerifyParams};

#[derive(Debug, Default)]
pub struct Args {
    // Input
    pub input_file: Option<PathBuf>,

    // Output (special: uses space separator)
    pub output_file: Option<PathBuf>,

    // INI file: /P:file
    pub ini_file: Option<PathBuf>,

    // Error log: /E=file
    pub error_log: Option<PathBuf>,

    // Silent mode: /S
    pub silent: bool,
    // Write version string to error log: /V
    pub write_version: bool,

    // Explicit import: /IN:file[;offset], /IA:file[;offset] or /II2=file; the last wins
    pub import: Option<Import>,

    // Address mapping
    pub remap: Option<RemapOptions>,
    pub s08_map: bool,
    pub s12_map: bool,
    pub s12x_map: bool,

    // Fill ranges: /FR:'range' with /FP:pattern; without a pattern the fill is random
    pub fill_ranges: Vec<AddressRange>,
    pub fill_pattern: Option<Vec<u8>>,

    // Cut ranges: /CR:'range1':'range2'
    pub cut_ranges: Vec<AddressRange>,

    // Merge: /MO:file[;offset][:range][+...] or /MT:...; the last of them wins
    pub merge: Option<MergeSpec>,

    // Address range filter: /AR:'range'[:'range']; an empty list keeps nothing
    pub address_range: Option<Vec<AddressRange>>,

    // Log file: /L:file
    pub log_file: Option<PathBuf>,

    // Single region: /FA
    pub fill_all: bool,

    // Alignment: /AD:xx, /AL[:len], /AF:xx; a bare /AL is Some(0) and aligns to /AD
    pub align_address: Option<u32>,
    pub align_length: Option<u32>,
    pub align_fill: u8,
    pub align_erase: Option<u32>, // /AE:zzzz

    // Checksum: /CSx[:target] or /CSRx[:target] (little-endian, default target @append)
    pub checksum: Option<ChecksumParams>,
    // Multi-checksum: /CSMx[:target] or /CSMRx[:target] (repeatable, ordered)
    pub checksum_multi: Vec<ChecksumParams>,

    // Data processing: /DPn[:@placement]:param1[,param2,param3][;param4][#NAME=value]...
    pub data_processing: Option<DataProcessingParams>,
    // Signature verification: /SVn:keyinfo!signatureinfo
    pub signature_verify: Option<SignatureVerifyParams>,

    // Split blocks: /sb:size
    pub split_block_size: Option<u32>,
    // Remove blocks shorter than this: /RB=size
    pub remove_blocks_below: Option<u32>,

    // Byte swap: /swapword or /swaplong
    pub swap_word: bool,
    pub swap_long: bool,

    // dsPIC operations
    pub dspic_expand: Vec<DspicOp>,
    pub dspic_shrink: Vec<DspicOp>,
    pub dspic_clear_ghost: Vec<AddressRange>,

    // Validation structures: /vs and /vshsm:@placement; a placement HexView does not
    // know inserts nothing
    pub validation: bool,
    pub hsm_validation: Option<Option<Placement>>,

    // Output format; the last /Xx flag wins
    pub output_format: Option<OutputFormat>,

    // Options HexView does not know, and extra positional arguments: reported, not run
    pub unrecognized: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct MergeSpec {
    pub mode: MergeMode,
    pub files: Vec<MergeParam>,
}

/// One `/MO` or `/MT` file. A file name with `*` or `?` merges every matching file, the
/// offset and range applying to the first.
#[derive(Debug, Clone)]
pub struct MergeParam {
    pub file: PathBuf,
    pub offset: Option<i64>,
    pub range: Option<AddressRange>,
    /// A range HexView rejects: the whole file is merged and the command fails.
    pub invalid_range: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImportKind {
    Binary,
    HexAscii,
    IntelHex16,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub kind: ImportKind,
    pub file: PathBuf,
    pub offset: u32,
}

#[derive(Debug, Clone)]
pub struct ChecksumParams {
    pub algorithm: u8,
    pub target: ChecksumTarget,
    pub little_endian: bool,
    pub range: Option<AddressRange>,
    pub forced_range: Option<ForcedRange>,
    pub exclude_ranges: Vec<AddressRange>,
}

#[derive(Debug, Clone)]
pub enum ChecksumTarget {
    None,
    Place(Placement),
    File(PathBuf),
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    IntelHex(IntelHexWriteOptions), // /XI[:len[:type]]
    /// `/XS[:len[:type]]`; a record length of 0 writes no data records, as HexView does.
    SRecord(SRecordWriteOptions),
    Binary,                         // /XN
    HexAscii(HexAsciiWriteOptions), // /XA[:len[:separator]]
    CCode,                          // /XC
    FordIntelHex,                   // /XF
    FlashKernel,                    // /XK
    GacSwil,                        // /XGACSWIL
    Porsche,                        // /XP
    SeparateBinary,                 // /XSB
}

impl OutputFormat {
    /// Appended to the input file name without its extension when `-o` is absent.
    pub fn default_suffix(&self) -> &'static str {
        match self {
            Self::IntelHex(_) => ".hex",
            Self::SRecord(_) => ".s19",
            Self::Binary | Self::GacSwil | Self::Porsche | Self::SeparateBinary => ".bin",
            Self::HexAscii(_) => ".asc",
            Self::CCode => ".c",
            Self::FordIntelHex => "_f.hex",
            Self::FlashKernel => ".fkl",
        }
    }
}

#[derive(Debug)]
pub enum ParseArgError {
    InvalidOption(String),
    InvalidRange(String),
    InvalidNumber(String),
    MissingValue(String),
}

impl std::fmt::Display for ParseArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidOption(s) => write!(f, "invalid option: {s}"),
            Self::InvalidRange(s) => write!(f, "invalid range: {s}"),
            Self::InvalidNumber(s) => write!(f, "invalid number: {s}"),
            Self::MissingValue(s) => write!(f, "missing value for {s}"),
        }
    }
}

impl std::error::Error for ParseArgError {}

impl Args {
    pub fn parse() -> Result<Self, ParseArgError> {
        Self::parse_from(std::env::args().skip(1).collect())
    }

    pub fn parse_from(args: Vec<String>) -> Result<Self, ParseArgError> {
        Self::parse_from_with(args, |arg| {
            let path = std::path::Path::new(arg);
            arg.starts_with('/') && path.is_absolute() && path.exists()
        })
    }

    pub fn parse_from_with<F>(
        args: Vec<String>,
        is_existing_abs_path: F,
    ) -> Result<Self, ParseArgError>
    where
        F: Fn(&str) -> bool,
    {
        let mut result = Args {
            align_fill: 0xFF,
            ..Default::default()
        };

        let mut args_iter = args.iter();
        let mut force_positional = false;

        while let Some(arg) = args_iter.next() {
            if arg == "--" {
                force_positional = true;
                continue;
            }

            if arg.eq_ignore_ascii_case("-o") {
                let next = args_iter
                    .next()
                    .ok_or(ParseArgError::MissingValue("-o".into()))?;
                result.output_file = Some(PathBuf::from(next));
                continue;
            }

            let option = (!force_positional)
                .then(|| arg.strip_prefix('/').or_else(|| arg.strip_prefix('-')))
                .flatten();
            if let Some(opt) = option {
                if parse_option(&mut result, opt)? {
                    continue;
                }
                if !(result.input_file.is_none() && is_existing_abs_path(arg)) {
                    // HexView reports unknown options and carries on.
                    result.unrecognized.push(format!("-{opt}"));
                    continue;
                }
            }
            if result.input_file.is_none() {
                result.input_file = Some(PathBuf::from(arg));
            } else {
                // HexView reads the first positional argument and ignores the others.
                result.unrecognized.push(arg.clone());
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::Args;
    use std::path::PathBuf;

    #[test]
    fn test_parse_double_dash_forces_positional() {
        let args = vec!["--".to_owned(), "/tmp/input.hex".to_owned()];
        let parsed = Args::parse_from(args).unwrap();
        assert_eq!(parsed.input_file, Some(PathBuf::from("/tmp/input.hex")));
    }

    #[test]
    fn test_parse_absolute_path_existing_file() {
        let dir = std::env::temp_dir();
        let path = dir.join("hexy_parse_input_test.bin");
        std::fs::write(&path, [0xAA]).unwrap();
        let args = vec![path.to_string_lossy().to_string()];
        let parsed = Args::parse_from(args).unwrap();
        assert_eq!(parsed.input_file, Some(path.clone()));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn test_parse_positional_windows_path() {
        let args = vec![r"C:\temp\input.hex".to_owned()];
        let parsed = Args::parse_from_with(args, |_| false).unwrap();
        assert_eq!(parsed.input_file, Some(PathBuf::from(r"C:\temp\input.hex")));
    }

    #[test]
    fn test_parse_dash_o_with_windows_path() {
        let args = vec![
            "-o".to_owned(),
            r"C:\temp\out.hex".to_owned(),
            "input.hex".to_owned(),
        ];
        let parsed = Args::parse_from_with(args, |_| false).unwrap();
        assert_eq!(parsed.output_file, Some(PathBuf::from(r"C:\temp\out.hex")));
        assert_eq!(parsed.input_file, Some(PathBuf::from("input.hex")));
    }

    #[test]
    fn test_parse_dash_prefix_case_and_equal_separator() -> Result<(), Box<dyn std::error::Error>> {
        let args = vec![
            "-afcd".to_owned(),
            "/aD=0x10".to_owned(),
            "input.hex".to_owned(),
        ];
        let parsed = Args::parse_from_with(args, |_| false)?;
        assert_eq!(parsed.align_fill, 0xCD);
        assert_eq!(parsed.align_address, Some(0x10));
        assert_eq!(parsed.input_file, Some(PathBuf::from("input.hex")));
        Ok(())
    }
}

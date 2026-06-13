use std::path::PathBuf;

use crate::AddressRange;

use super::parse::parse_option;

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

    // Import 16-bit Intel HEX: /II2=file
    pub import_i16: Option<PathBuf>,
    // Import binary data: /IN:file[;offset]
    pub import_binary: Option<ImportParam>,
    // Import HEX ASCII: /IA:file[;offset]
    pub import_hex_ascii: Option<ImportParam>,

    // Address mapping
    pub remap: Option<RemapParams>,
    pub s08_map: bool,
    pub s12_map: bool,
    pub s12x_map: bool,

    // Fill ranges: /FR:'range' with /FP:pattern
    pub fill_ranges: Vec<AddressRange>,
    pub fill_pattern: Vec<u8>,
    pub fill_pattern_set: bool,

    // Cut ranges: /CR:'range1':'range2'
    pub cut_ranges: Vec<AddressRange>,

    // Merge: /MO:file[;offset] or /MT:file[;offset]
    pub merge_opaque: Vec<MergeParam>,
    pub merge_transparent: Vec<MergeParam>,

    // Address range filter: /AR:'range'
    pub address_range: Vec<AddressRange>,
    pub address_range_empty_output: bool,

    // Log file: /L:file
    pub log_file: Option<PathBuf>,

    // Single region: /FA
    pub fill_all: bool,

    // Postbuild: /PB:"file"
    pub postbuild: Option<PathBuf>,

    // Alignment: /AD:xx, /AL, /AF:xx
    pub align_address: Option<u32>,
    pub align_length: bool,
    pub align_fill: u8,
    pub align_erase: Option<u32>, // /AE:zzzz

    // Checksum: /CSx[:target] or /CSRx[:target] (little-endian, default target @append)
    pub checksum: Option<ChecksumParams>,
    // Multi-checksum: /CSMx[:target] or /CSMRx[:target] (repeatable, ordered)
    pub checksum_multi: Vec<ChecksumParams>,

    // Data processing (signature subset): /DPn[:@placement]:param[,section,key][;outfilename]
    pub data_processing: Option<DataProcessingParams>,
    // Signature verification: /SVn:keyinfo!signatureinfo
    pub signature_verify: Option<SignatureVerifyParams>,

    // Split blocks: /sb:size
    pub split_block_size: Option<u32>,

    // Byte swap: /swapword or /swaplong
    pub swap_word: bool,
    pub swap_long: bool,

    // dsPIC operations
    pub dspic_expand: Vec<DspicOp>,
    pub dspic_shrink: Vec<DspicOp>,
    pub dspic_clear_ghost: Vec<AddressRange>,

    // Output format (only one allowed)
    pub output_format: Option<OutputFormat>,

    // Output format options
    pub bytes_per_line: Option<u8>,
}

#[derive(Debug, Clone)]
pub struct MergeParam {
    pub file: PathBuf,
    pub offset: Option<i64>,
    pub range: Option<AddressRange>,
}

#[derive(Debug, Clone)]
pub struct ImportParam {
    pub file: PathBuf,
    pub offset: u32,
}

#[derive(Debug, Clone)]
pub struct RemapParams {
    pub start: u32,
    pub end: u32,
    pub linear: u32,
    pub size: u32,
    pub inc: u32,
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
pub struct ForcedRange {
    pub range: AddressRange,
    pub pattern: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum ChecksumTarget {
    None,
    Address(u32),
    Append,
    Begin,
    Prepend,
    OverwriteEnd,
    File(PathBuf),
}

#[derive(Debug, Clone)]
pub struct DataProcessingParams {
    pub method: u8,
    pub placement: Option<ChecksumTarget>,
    pub key_info: String,
    pub output_file: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct SignatureVerifyParams {
    pub method: u8,
    pub key_info: String,
    pub signature_info: String,
}

#[derive(Debug, Clone)]
pub struct DspicOp {
    pub range: AddressRange,
    pub target: Option<u32>,
}

#[derive(Debug, Clone)]
pub enum OutputFormat {
    IntelHex {
        record_type: Option<u8>,
    }, // /XI[:len[:type]]
    SRecord {
        record_type: Option<u8>,
    }, // /XS[:len[:type]]
    Binary, // /XN
    HexAscii {
        line_length: Option<u32>,
        separator: Option<String>,
    }, // /XA
    CCode,  // /XC
    FordIntelHex, // /XF
    Porsche, // /XP
    SeparateBinary, // /XSB
}

#[derive(Debug)]
pub enum ParseArgError {
    MissingInputFile,
    InvalidOption(String),
    InvalidRange(String),
    InvalidNumber(String),
    DuplicateOutputFormat,
    MissingValue(String),
}

impl std::fmt::Display for ParseArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingInputFile => write!(f, "missing input file"),
            Self::InvalidOption(s) => write!(f, "invalid option: {s}"),
            Self::InvalidRange(s) => write!(f, "invalid range: {s}"),
            Self::InvalidNumber(s) => write!(f, "invalid number: {s}"),
            Self::DuplicateOutputFormat => write!(f, "multiple output formats specified"),
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
            fill_pattern: vec![0xFF],
            fill_pattern_set: false,
            align_fill: 0xFF,
            ..Default::default()
        };

        let mut args_iter = args.iter().peekable();
        let mut force_positional = false;
        let is_existing_abs_path = &is_existing_abs_path;

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

            if force_positional {
                if result.input_file.is_none() {
                    result.input_file = Some(PathBuf::from(arg));
                    continue;
                }
                return Err(ParseArgError::InvalidOption(arg.clone()));
            }

            if let Some(opt) = arg.strip_prefix('/').or_else(|| arg.strip_prefix('-')) {
                match parse_option(&mut result, opt) {
                    Ok(()) => {}
                    Err(ParseArgError::InvalidOption(_)) => {
                        if result.input_file.is_none() && is_existing_abs_path(arg) {
                            result.input_file = Some(PathBuf::from(arg));
                        } else {
                            return Err(ParseArgError::InvalidOption(arg.clone()));
                        }
                    }
                    Err(e) => return Err(e),
                }
            } else if result.input_file.is_none() {
                result.input_file = Some(PathBuf::from(arg));
            } else {
                return Err(ParseArgError::InvalidOption(arg.clone()));
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
        let args = vec!["--".to_string(), "/tmp/input.hex".to_string()];
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

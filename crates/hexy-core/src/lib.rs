#![cfg_attr(
    not(test),
    deny(
        clippy::expect_used,
        clippy::panic,
        clippy::print_stderr,
        clippy::print_stdout,
        clippy::str_to_string,
        clippy::todo,
        clippy::unimplemented,
        clippy::unwrap_used
    )
)]

pub mod hexfile;
pub mod io;
pub mod ops;
pub mod range;
pub mod segment;
pub mod signature;

pub use hexfile::HexFile;
pub use io::{
    AutoFormat, BinaryWriteOptions, CCodeOutput, CCodeWordType, CCodeWriteOptions, FileIoError,
    HexAsciiWriteOptions, SRecordType, SRecordWriteOptions, detect_format, parse_auto,
    parse_binary, parse_hex_ascii, parse_srec, write_binary, write_c_code, write_hex_ascii,
    write_srec,
};
pub use io::{
    IntelHexMode, IntelHexWriteOptions, ParseError, parse_intel_hex, parse_intel_hex_16bit,
    write_intel_hex,
};
pub use ops::{
    AlignOptions, BankedMapOptions, ChecksumAlgorithm, ChecksumJob, ChecksumOptions,
    ChecksumTarget, FillOptions, ForcedRange, MergeMode, MergeOptions, OpsError, RemapOptions,
    SwapMode,
};
pub use range::{AddressRange, AddressRangeError, merge_ranges, parse_compat_ranges, parse_ranges};
pub use segment::Segment;
pub use signature::{
    SignatureBytesSource, SignatureError, SignatureKeySource, SignatureMethod, SignaturePlacement,
    SignatureSignOptions, SignatureVerifyOptions,
};

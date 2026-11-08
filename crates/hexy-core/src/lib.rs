pub mod hexfile;
pub mod io;
pub mod ops;
pub mod pipeline;
pub mod range;
pub mod segment;
pub mod signature;

pub use hexfile::{HexFile, Placement};
pub use io::{
    AutoFormat, BinaryWriteOptions, CCodeOutput, CCodeWordType, CCodeWriteOptions,
    DEFAULT_INTEL_HEX_BYTES_PER_LINE, DEFAULT_SREC_BYTES_PER_LINE, FileIoError,
    HexAsciiWriteOptions, IntelHexMode, IntelHexWriteOptions, ParseError, SRecordType,
    SRecordWriteOptions, WriteError, detect_format, parse_auto, parse_binary, parse_hex_ascii,
    parse_intel_hex, parse_intel_hex_16bit, parse_srec, write_binary, write_c_code,
    write_hex_ascii, write_intel_hex, write_srec,
};
pub use ops::{
    AlignOptions, BankedMapOptions, ChecksumAlgorithm, ChecksumOptions, DEFAULT_DENSE_SPAN_LIMIT,
    FillOptions, ForcedRange, MapCollision, MergeMode, MergeOptions, OpsError, RemapOptions,
    SwapMode,
};
pub use pipeline::{
    AddressMap, ChecksumStage, DspicOp, Fill, FillData, Merge, Pipeline, PipelineError,
    PipelineOutput, Stage,
};
pub use range::{AddressRange, AddressRangeError, merge_ranges, parse_compat_ranges, parse_ranges};
pub use segment::{Segment, SegmentError};
pub use signature::{
    SignatureBytesSource, SignatureError, SignatureKeySource, SignatureMethod,
    SignatureSignOptions, SignatureVerifyOptions,
};

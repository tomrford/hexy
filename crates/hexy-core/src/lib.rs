pub mod hexfile;
pub mod io;
pub mod ops;
pub mod pipeline;
pub mod processing;
pub mod range;
pub mod segment;

pub use hexfile::{HexFile, Placement};
pub use io::{
    AutoFormat, BinaryWriteOptions, CCodeOutput, CCodeWordSize, CCodeWordType, CCodeWriteOptions,
    DEFAULT_INTEL_HEX_BYTES_PER_LINE, DEFAULT_SREC_BYTES_PER_LINE, FileIoError, FlashKernelHeader,
    FordHeader, HexAsciiWriteOptions, IntelHexMode, IntelHexWriteOptions, ParseError, SRecordType,
    SRecordWriteOptions, ValidationCOptions, WriteError, detect_format, parse_auto, parse_binary,
    parse_hex_ascii, parse_intel_hex, parse_intel_hex_16bit, parse_srec, write_binary,
    write_c_code, write_flash_kernel, write_ford_intel_hex, write_gac_swil, write_hex_ascii,
    write_intel_hex, write_srec, write_validation_c,
};
pub use ops::{
    AlignOptions, BankedMapOptions, ChecksumAlgorithm, ChecksumOptions, DEFAULT_DENSE_SPAN_LIMIT,
    FillOptions, ForcedRange, HsmValidationOptions, MapCollision, MergeMode, MergeOptions,
    OpsError, RemapOptions, SwapMode, ValidationBlock, ValidationOptions, ValidationStructure,
};
pub use pipeline::{
    AddressMap, ChecksumStage, DataProcessingStage, DspicOp, Fill, FillData, HsmValidationStage,
    Merge, Pipeline, PipelineError, PipelineOutput, Stage, ValidationStage, VerifyStage,
};
pub use processing::{
    AesGcm, AesKey, AesMode, AesPadding, Compression, DataProcessing, Ed25519PrivateKey,
    Ed25519PublicKey, GcmTag, Lzss, LzssAes, MacAlgorithm, MacKey, MacMethod, P256PrivateKey,
    P256PublicKey, ProcessingError, RsaPadding, RsaPrivateKey, RsaPublicKey, SignatureMethod,
    SignatureScheme, SigningKey, VerifyingKey, decode_hex_text,
};
pub use range::{AddressRange, AddressRangeError};
pub use segment::{Segment, SegmentError};

from collections.abc import Iterable
from datetime import datetime
from os import PathLike
from typing import Literal, TypeAlias

Pathish = str | bytes | PathLike[str] | PathLike[bytes]
RangeLike: TypeAlias = "AddressRange | str"
"""An `AddressRange`, or range text as HexView reads it: `start-end` or
`start,length`, each number `0x` hex or decimal."""
RangesLike = Iterable[RangeLike]
Placement = int | Literal["append", "begin", "prepend", "overwrite-end"]
"""Where output bytes go: an address, directly after the last data byte, over the first
data bytes, directly before the first data byte, or over the last data bytes."""
ChecksumMethod = int
"""A HexView `/CS` method index, 0 to 22."""
MergeMode = Literal["overwrite", "preserve"]
SwapMode = Literal["word", "dword"]
IntelHexMode = Literal["auto", "linear", "segment"]
SRecordType = Literal["auto", "s1", "s2", "s3"]
SignatureMethod = Literal[
    "rsa-pkcs1v15-md5",
    "rsa-pkcs1v15-sha1",
    "rsa-pkcs1v15-ripemd160",
    "rsa-pkcs1v15-sha256",
    "rsa-pss-sha256",
    "ecdsa-p256-sha256",
    "ed25519",
    "ed25519ph",
    "ed25519ph-sha512",
]
MacMethod = Literal[
    "hmac-md5", "hmac-sha1", "hmac-ripemd160", "hmac-sha256", "cmac-aes128"
]
CipherMode = Literal[
    "ecb", "cbc", "ctr", "gcm", "rsa-pkcs1v15", "rsa-oaep-sha1", "rsa-oaep-sha256"
]
AesPadding = Literal["pkcs7", "ansix923", "rfc1321"]
Compression = Literal["lzss", "arle"]
KeyFile = bytes | str
"""An asymmetric key: a key file's content, or key text."""
SymmetricKey = bytes | str
"""A symmetric key: the raw key as bytes, or key text read as HexView reads a key file."""

class HexyError(Exception):
    """Base class of hexy's errors."""

class RangeError(HexyError):
    """An address range or segment that does not fit the 32-bit address space, or
    range text that does not read as one."""

class ParseError(HexyError):
    """Input that is not valid in its file format."""

class OperationError(HexyError):
    """An image operation or export that cannot be carried out."""

class ProcessingError(HexyError):
    """A data processing step that cannot be carried out, such as one with an invalid
    key."""

class VerificationError(ProcessingError):
    """A signature or AES-GCM tag that does not match the data."""

class AddressRange:
    """An inclusive address range inside the 32-bit address space."""

    def __init__(
        self, start: int, end: int | None = None, *, length: int | None = None
    ) -> None: ...
    @staticmethod
    def parse(text: str) -> AddressRange:
        """Read range text as HexView does; raises `RangeError` for text HexView
        skips or rejects."""
    @property
    def start(self) -> int: ...
    @property
    def end(self) -> int: ...
    @property
    def length(self) -> int: ...
    def __contains__(self, address: int) -> bool: ...

class Segment:
    """A non-empty run of bytes inside the 32-bit address space."""

    def __init__(self, start: int, data: bytes) -> None: ...
    @property
    def start(self) -> int: ...
    @property
    def end(self) -> int: ...
    @property
    def data(self) -> bytes: ...
    def __len__(self) -> int: ...

class DataProcessing:
    """A HexView `/DP` operation for `HexFile.process_data`,
    `Pipeline.process_data` and the signature of
    `Pipeline.hsm_validation_structure`. Signatures and MACs cover the block data in
    address order and output their bytes; ciphers and compression replace each
    block's data from its start address."""

    @staticmethod
    def sign(
        method: SignatureMethod,
        key: KeyFile,
        *,
        metadata: bool = False,
        salt: bytes | None = None,
    ) -> DataProcessing:
        """A signature. `metadata` precedes each block with its big-endian start
        address and length. `key` is read as HexView reads it: HIS or PKCS #1 hex
        text, PKCS #8 or PKCS #1 PEM or DER for RSA; a raw hex key, or an ECC key in
        PEM, DER or hex text DER, for Ed25519 and P-256. `salt` is the RSA-PSS salt,
        a random 32 bytes without it. ECDSA is deterministic (RFC 6979) and outputs r
        and s; `ed25519` signs a single block."""
    @staticmethod
    def mac(
        method: MacMethod, key: SymmetricKey, *, metadata: bool = False
    ) -> DataProcessing:
        """HMAC or CMAC over the block data, as `sign` covers it. HMAC uses at most
        the first 64 bytes of `key`; CMAC needs a 16-byte key. Key text may be a HIS
        MAC key."""
    @staticmethod
    def xor(key: SymmetricKey | None = None) -> DataProcessing:
        """XOR the data with `key`, repeated across the blocks; without a key, invert
        the data (`/DP1`)."""
    @staticmethod
    def encrypt(
        mode: CipherMode,
        key: SymmetricKey | KeyFile,
        *,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
        aad: bytes | None = None,
    ) -> DataProcessing:
        """AES or RSA encryption as HexView does it. The AES key length picks
        AES-128, -192 or -256. ECB, CBC and CTR encrypt each block on its own, after
        adding `padding`; without `iv`, CBC and CTR take the first 16 bytes of the
        first block as the IV and leave them in place. GCM encrypts all blocks as one
        stream with `iv` as the nonce and `aad` as additional data, and outputs the
        tag; each block takes the whole 16-byte units done by its end and the last
        block the rest. RSA modes take a public or private key file and encrypt each
        block on its own with random padding; `rsa-pkcs1v15` encrypts a whole number
        of key lengths without padding, and other blocks must fit one padded key
        length."""
    @staticmethod
    def decrypt(
        mode: CipherMode,
        key: SymmetricKey | KeyFile,
        *,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
        aad: bytes | None = None,
        tag: bytes | RangeLike | None = None,
    ) -> DataProcessing:
        """Reverse `encrypt`; padding is checked and removed, except after CTR. GCM
        checks `tag`, given as bytes or as an image range at the start or end of a
        block that stays in place; a mismatch raises `VerificationError` after the
        data is decrypted. RSA modes take a private key. OAEP needs exactly one key
        length per block; `rsa-pkcs1v15` also accepts whole numbers of key lengths,
        and decrypts one key length without padding when its padding is not valid."""
    @staticmethod
    def compress(
        method: Compression = "lzss",
        *,
        window_bits: int | None = None,
        length_bits: int | None = None,
        key: SymmetricKey | None = None,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
    ) -> DataProcessing:
        """Compress each block as HexView does (`/DP26`, `/DP36`, `/DP57`); a block
        keeps its start address and takes the compressed length. LZSS uses a
        `window_bits` window and `length_bits` lengths, 10 and 4 by default, with
        0 < length_bits < window_bits < 16; with 8 or more length bits it codes
        literals only. With `key`, each compressed block is then AES-CBC encrypted
        from `iv` (zero bytes by default) after adding `padding` (`/DP34`,
        `/DP59`). ARLE codes byte, word and long word runs."""
    @staticmethod
    def decompress(
        method: Compression = "lzss",
        *,
        window_bits: int | None = None,
        length_bits: int | None = None,
        key: SymmetricKey | None = None,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
    ) -> DataProcessing:
        """Reverse `compress` (`/DP27`, `/DP37`, `/DP58`; with `key`, `/DP35`,
        `/DP60`). LZSS reads any data, taking missing bits as zero; a block that
        decompresses to nothing keeps its data. ARLE raises `ProcessingError` on an
        incomplete token or empty output."""

class ValidationStructure:
    """HexView's `/vs` validation structure and the parts it was built from."""

    @property
    def data(self) -> bytes:
        """The encoded structure."""
    def __bytes__(self) -> bytes: ...
    @property
    def blocks(self) -> list[tuple[int, int, bytes | None]]:
        """Each block's address, length and checksum."""
    @property
    def file_checksum(self) -> bytes | None: ...
    @property
    def validate_sum(self) -> int | None: ...
    @property
    def wide(self) -> bool:
        """Whether addresses and lengths take 32 bits."""
    def to_c(
        self,
        c_file_name: str,
        h_file_name: str,
        *,
        tag_begin_value: int | None = None,
        tag_end_value: int | None = None,
        created: datetime | None = None,
    ) -> tuple[bytes, bytes]:
        """The `.c` and `.h` files of the structure in HexView's layout, written as
        valid C where HexView's `.c` file does not compile. Tags of 1, 2 or 4 bytes
        are one number and other tags a byte array of their length; each is the tag
        bytes read big-endian, or `tag_begin_value` and `tag_end_value`. `created`
        is an aware datetime, the current local time by default."""

class HexFile:
    """A memory image: segments in insertion order, later segments winning where they
    overlap. Operations work on its blocks, as HexView does."""

    def __init__(self, segments: Iterable[Segment] = ()) -> None: ...
    @staticmethod
    def from_binary(data: bytes, base_address: int = 0) -> HexFile: ...
    @staticmethod
    def from_hex_ascii(data: bytes, base_address: int = 0) -> HexFile: ...
    @staticmethod
    def from_intel_hex(data: bytes) -> HexFile: ...
    @staticmethod
    def from_intel_hex_16bit(data: bytes) -> HexFile:
        """Intel HEX with 16-bit addresses, as `/II2` reads it."""
    @staticmethod
    def from_srec(data: bytes) -> HexFile: ...
    @staticmethod
    def from_file(path: Pathish) -> HexFile:
        """Read Intel HEX, S-Record or raw binary, detected from the content as the
        CLI detects it."""
    @staticmethod
    def from_file_bytes(data: bytes) -> HexFile: ...
    def segments(self) -> list[Segment]:
        """The segments in insertion order."""
    def blocks(self) -> list[Segment]:
        """The blocks operations and exports work on: sorted, overlaps resolved, and
        `split` pieces kept apart."""
    def normalized(self) -> HexFile:
        """A copy with adjacent and overlapping data joined into one block, as HexView
        joins data when it loads a file."""
    def copy(self) -> HexFile: ...
    def is_empty(self) -> bool: ...
    @property
    def min_address(self) -> int | None: ...
    @property
    def max_address(self) -> int | None: ...
    @property
    def total_bytes(self) -> int: ...
    @property
    def gap_count(self) -> int: ...
    def append_segment(self, segment: Segment) -> None:
        """Add a segment that wins where it overlaps data."""
    def prepend_segment(self, segment: Segment) -> None:
        """Add a segment that loses where it overlaps data."""
    def write(self, address: int, data: bytes) -> None: ...
    def read_byte(self, address: int) -> int | None: ...
    def read(self, address: int, length: int) -> bytes | None:
        """The bytes at `address`, or `None` unless data covers them all."""
    def read_sparse(self, address: int, length: int) -> list[int | None]: ...
    def to_binary(self, *, fill_gaps: int | None = None) -> bytes:
        """The data in address order (`/XN`); with `fill_gaps`, the span from the
        lowest to the highest address with gaps filled."""
    def to_intel_hex(
        self, *, bytes_per_line: int = 32, mode: IntelHexMode = "auto"
    ) -> bytes: ...
    def to_srec(
        self, *, bytes_per_line: int = 32, record_type: SRecordType = "auto"
    ) -> bytes:
        """Motorola S-Record (`/XS`); a `bytes_per_line` of 0 writes only the
        termination record."""
    def to_hex_ascii(self, *, line_length: int = 16, separator: str = "") -> bytes:
        """HEX ASCII (`/XA`); a `line_length` of 0 writes one line."""
    def to_c_code(
        self,
        file_name: str,
        *,
        prefix: str = "",
        word_size: Literal[1, 2, 4] = 1,
        motorola: bool = False,
        xor: int | None = None,
        created: datetime | None = None,
    ) -> tuple[bytes, bytes]:
        """HexView's `/XC` C arrays of the blocks, as the `.c` and `.h` file contents.
        `file_name` names the `.c` file in its comment and the `.h` file it includes,
        and `xor` is applied to every element. `created`, an aware datetime and the
        current local time by default, is written as the creation time and seeds the
        `_GEN_RAND` check as HexView seeds it."""
    def to_flash_kernel(
        self,
        name: str,
        *,
        comment: str | None = None,
        file_address: str | None = None,
        size: str | None = None,
        ram_address: str | None = None,
        ram_start: str | None = None,
    ) -> bytes:
        """A CCP/XCP flash kernel file (`/XK`) of a single-block image. Header values
        are written as given; by default they describe the block."""
    def to_ford_intel_hex(
        self,
        file_name: str,
        release_date: str,
        *,
        application: str | None = None,
        mask_number: str | None = None,
        module_type: str | None = None,
        part_number: str | None = None,
        wers_notice: str | None = None,
        comments: str | None = None,
        released_by: str | None = None,
        module_name: str | None = None,
        module_id: str | None = None,
        download_format: str = "0x01",
        flash_indicator: str = "1",
        erase_sectors: str | None = None,
        erase_alignment: int = 0,
    ) -> bytes:
        """Ford Intel HEX (`/XF`): the `[FORDHEADER]` lines, then the data. Fields left
        out leave out their line; without `part_number` or `module_id` the file stops
        before that line. Without `erase_sectors`, the blocks widened to
        `erase_alignment` (`/AE`) are listed."""
    def to_gac_swil(self) -> bytes:
        """A GAC software interlock file (`/XGACSWIL`): the block count, each block's
        big-endian address and length, then the data."""
    def write_binary(self, path: Pathish, *, fill_gaps: int | None = None) -> None: ...
    def write_intel_hex(
        self, path: Pathish, *, bytes_per_line: int = 32, mode: IntelHexMode = "auto"
    ) -> None: ...
    def write_srec(
        self,
        path: Pathish,
        *,
        bytes_per_line: int = 32,
        record_type: SRecordType = "auto",
    ) -> None:
        """Write Motorola S-Record to `path`; a `bytes_per_line` of 0 writes only the
        termination record."""
    def write_hex_ascii(
        self, path: Pathish, *, line_length: int = 16, separator: str = ""
    ) -> None: ...
    def map_star12(self) -> None:
        """Map HC12 banked addresses to linear ones (`/S12MAP`)."""
    def map_star12x(self) -> None:
        """Map HCS12X banked addresses to linear ones (`/S12XMAP`)."""
    def map_star08(self) -> None:
        """Map HC08 pages to linear addresses (`/S08MAP`)."""
    def remap(self, start: int, end: int, linear: int, size: int, inc: int) -> None:
        """Map `size`-byte banks every `inc` bytes from `start` to `end` to linear
        addresses from `linear` (`/REMAP`)."""
    def dspic_expand(self, range: RangeLike, target: int | None = None) -> None:
        """Expand dsPIC data to two bytes in four (`/CDSPX`)."""
    def dspic_shrink(self, range: RangeLike, target: int | None = None) -> None:
        """Keep the two low bytes of every four (`/CDSPS`)."""
    def dspic_clear_ghost(self, range: RangeLike) -> None:
        """Clear the dsPIC ghost byte of every four (`/CDSPG`)."""
    def fill(
        self,
        ranges: RangesLike,
        *,
        pattern: bytes | None = None,
        overwrite: bool = False,
    ) -> None:
        """Fill the gaps of `ranges` with `pattern` repeated from each range start,
        0xFF by default (`/FR`, `/FP`); with `overwrite`, the data too."""
    def fill_random(self, ranges: RangesLike, *, seed: int) -> None:
        """Fill the gaps of `ranges` with bytes reproducible from `seed` (`/FR`
        without `/FP`)."""
    def cut(self, ranges: RangesLike) -> None:
        """Remove the data inside `ranges` (`/CR`)."""
    def merge(
        self,
        other: HexFile,
        *,
        mode: MergeMode = "overwrite",
        offset: int = 0,
        range: RangeLike | None = None,
    ) -> None:
        """Merge `other`, moved by `offset` and limited to `range`, over the data
        (`/MO`) or into its gaps (`/MT`)."""
    def filter(self, ranges: RangesLike) -> None:
        """Keep only the data inside `ranges` (`/AR`)."""
    def offset(self, delta: int) -> None:
        """Move all data by `delta` bytes."""
    def fill_gaps(self, *, fill: int = 0xFF) -> None:
        """Join all data into one block, filling the gaps (`/FA`)."""
    def align(self, alignment: int, *, length: int = 0, fill: int = 0xFF) -> None:
        """Move block starts down to `alignment` and grow block lengths, counted from
        the aligned start, to `length` (`/AD`, `/AL`, `/AF`); 0 leaves them. HexView
        aligns with the bit mask of the value minus one."""
    def split(self, max_size: int) -> None:
        """Split each block into pieces of at most `max_size` bytes; the pieces stay
        separate blocks (`/SB`)."""
    def swap(self, mode: SwapMode) -> None:
        """Reverse the bytes of every aligned word or double word (`/SWAPWORD`,
        `/SWAPLONG`)."""
    def remove_small_blocks(self, min_length: int) -> None:
        """Remove blocks shorter than `min_length` bytes (`/RB`)."""
    def checksum(
        self,
        algorithm: ChecksumMethod,
        *,
        placement: Placement | None = None,
        range: RangeLike | None = None,
        reverse: bool = False,
        exclude: RangesLike | None = None,
        forced_range: RangeLike | None = None,
        forced_pattern: bytes | None = None,
        constant: bytes | None = None,
    ) -> bytes:
        """A `/CS` checksum over the data inside `range`, leaving out `exclude`.
        `reverse` reverses the method's byte order (`/CSR`); `forced_range` counts
        even where it holds no data, its gaps taking `forced_pattern` (0xFF by
        default). Method 16 writes `constant` (08 15 by default). With `placement`,
        the checksum is also written into the image, over bytes it leaves out of
        the calculation."""
    def process_data(
        self, operation: DataProcessing, *, placement: Placement | None = None
    ) -> bytes | None:
        """Run `operation` (`/DP`) and return its output: a signature, MAC or AES-GCM
        tag, which `placement` also writes into the image."""
    def verify(
        self,
        method: SignatureMethod,
        key: KeyFile,
        signature: bytes,
        *,
        metadata: bool = False,
    ) -> None:
        """Verify `signature` over the block data (`/SV`); raises
        `VerificationError` if it does not match. `key` is a public or private key in
        the forms `DataProcessing.sign` reads (an ECC private key must include its
        public key), a PKCS #1 or SPKI public key, or an X.509 certificate. RSA-PSS
        accepts any salt length."""
    def validation_structure(
        self,
        *,
        tag_begin: bytes,
        tag_end: bytes,
        block_checksum: ChecksumMethod | None = None,
        file_checksum: ChecksumMethod | None = None,
        validate_sum: bool = False,
        big_endian: bool = False,
        force_32bit: bool = False,
        alfi: bool = False,
        one_byte_count: bool = False,
        spare: RangesLike | None = None,
    ) -> ValidationStructure:
        """HexView's `/vs` validation structure over the blocks, leaving out `spare`:
        the tags, block count, each block's address, length and `block_checksum`
        result, the `file_checksum` result over all blocks, and with `validate_sum`
        the 16-bit sum of those bytes. Addresses and lengths take 32 bits when forced
        or when a block ends above 0xFFFF."""
    def hsm_validation_structure(
        self, *, group_id: int = 0, mode: int = 0, hash: ChecksumMethod = 20
    ) -> bytes:
        """HexView's `/vshsm` structure over the blocks: big-endian group ID, segment
        count, and each block's address, length, mode and `hash` result."""

class PipelineResult:
    @property
    def hexfile(self) -> HexFile: ...
    @property
    def checksums(self) -> list[bytes]:
        """One result per checksum stage, in order."""
    @property
    def data_processing(self) -> bytes | None:
        """The data processing output: a signature, MAC or AES-GCM tag."""
    @property
    def validation(self) -> ValidationStructure | None: ...
    @property
    def hsm_validation(self) -> bytes | None:
        """The vHSM structure, after any cipher of its signature stage."""
    @property
    def hsm_signature(self) -> bytes | None: ...

class Pipeline:
    """HexView-ordered recipe: each method configures the stage of the `HexFile`
    method of the same name, and `apply` runs the configured stages in HexView order,
    whatever order they were set in. Methods for single stages replace earlier
    settings; `dspic_*`, `cut`, `merge` and `checksum` add to their stage. Configured
    data stages join adjacent data into one block; pass `source.normalized()` to also
    join it on input, as HexView does when it loads a file."""

    def __init__(self) -> None: ...
    def apply(self, source: HexFile) -> PipelineResult:
        """Run the stages on a copy of `source`."""
    def map_star12(self) -> None: ...
    def map_star12x(self) -> None: ...
    def map_star08(self) -> None: ...
    def remap(self, start: int, end: int, linear: int, size: int, inc: int) -> None: ...
    def dspic_expand(self, range: RangeLike, target: int | None = None) -> None: ...
    def dspic_shrink(self, range: RangeLike, target: int | None = None) -> None: ...
    def dspic_clear_ghost(self, range: RangeLike) -> None: ...
    def fill(self, ranges: RangesLike, *, pattern: bytes | None = None) -> None:
        """Fill the gaps of `ranges`; existing data wins."""
    def fill_random(self, ranges: RangesLike, *, seed: int) -> None: ...
    def cut(self, ranges: RangesLike) -> None: ...
    def merge(
        self,
        other: HexFile,
        *,
        mode: MergeMode = "overwrite",
        offset: int = 0,
        range: RangeLike | None = None,
    ) -> None: ...
    def filter(self, ranges: RangesLike) -> None: ...
    def fill_gaps(self, *, fill: int = 0xFF) -> None:
        """Join all data into one block, up to a span of 256 MiB."""
    def align(self, alignment: int, *, length: int = 0, fill: int = 0xFF) -> None: ...
    def split(self, max_size: int) -> None: ...
    def swap(self, mode: SwapMode) -> None:
        """Swap words or double words; set both to swap words, then double words."""
    def remove_small_blocks(self, min_length: int) -> None: ...
    def checksum(
        self,
        algorithm: ChecksumMethod,
        *,
        placement: Placement | None = None,
        range: RangeLike | None = None,
        reverse: bool = False,
        exclude: RangesLike | None = None,
        forced_range: RangeLike | None = None,
        forced_pattern: bytes | None = None,
        constant: bytes | None = None,
    ) -> None: ...
    def process_data(
        self, operation: DataProcessing, *, placement: Placement | None = None
    ) -> None: ...
    def verify(
        self,
        method: SignatureMethod,
        key: KeyFile,
        signature: bytes,
        *,
        metadata: bool = False,
    ) -> None: ...
    def validation_structure(
        self,
        *,
        tag_begin: bytes,
        tag_end: bytes,
        block_checksum: ChecksumMethod | None = None,
        file_checksum: ChecksumMethod | None = None,
        validate_sum: bool = False,
        big_endian: bool = False,
        force_32bit: bool = False,
        alfi: bool = False,
        one_byte_count: bool = False,
        spare: RangesLike | None = None,
        address: int | None = None,
    ) -> None:
        """Build the `/vs` structure after the other stages; with `address`, insert
        it there as a block of its own unless it would overlap data or there are no
        blocks."""
    def hsm_validation_structure(
        self,
        *,
        group_id: int = 0,
        mode: int = 0,
        hash: ChecksumMethod = 20,
        placement: Placement | None = None,
        signature: DataProcessing | None = None,
    ) -> None:
        """Build the `/vshsm` structure after `/vs`, with an optional `signature`
        over it at the placement address; with `placement`, insert the signature and
        structure as one block unless it would overlap data, the signature ending at
        that address or, without room below it, starting there. Signature failures
        raise an exception; `apply` returns a result only on success."""

from os import PathLike
from typing import Literal

Pathish = str | bytes | PathLike[str] | PathLike[bytes]
RangeLike = str
RangesLike = list[str]
MergeMode = Literal["overwrite", "opaque", "preserve", "transparent"]
SwapMode = Literal["word", "swapword", "dword", "long", "swaplong"]
IntelHexMode = Literal[
    "auto", "linear", "extended_linear", "segment", "extended_segment"
]
SRecordType = Literal["auto", "s1", "s2", "s3", "1", "2", "3"]
Placement = Literal["append", "begin", "prepend", "overwrite_end"]
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
Key = bytes | str
MacMethod = Literal[
    "hmac-md5", "hmac-sha1", "hmac-ripemd160", "hmac-sha256", "cmac-aes128"
]
CipherMode = Literal[
    "ecb", "cbc", "ctr", "gcm", "rsa-pkcs1v15", "rsa-oaep-sha1", "rsa-oaep-sha256"
]
AesPadding = Literal["pkcs7", "ansix923", "rfc1321"]
Compression = Literal["lzss", "arle"]

class AddressRange:
    def __init__(
        self, start: int, end: int | None = None, *, length: int | None = None
    ) -> None: ...
    @staticmethod
    def from_start_end(start: int, end: int) -> AddressRange: ...
    @staticmethod
    def from_start_length(start: int, length: int) -> AddressRange: ...
    @staticmethod
    def parse(text: str) -> AddressRange: ...
    @property
    def start(self) -> int: ...
    @property
    def end(self) -> int: ...
    @property
    def length(self) -> int: ...
    def contains(self, addr: int) -> bool: ...

class Segment:
    def __init__(self, start: int, data: bytes) -> None: ...
    @property
    def start(self) -> int: ...
    @property
    def end(self) -> int: ...
    @property
    def data(self) -> bytes: ...
    def __len__(self) -> int: ...

class HexFile:
    def __init__(self) -> None: ...
    @staticmethod
    def from_segments(segments: list[Segment]) -> HexFile: ...
    @staticmethod
    def from_binary(data: bytes, base_address: int = 0) -> HexFile: ...
    @staticmethod
    def from_hex_ascii(data: bytes, base_address: int = 0) -> HexFile: ...
    @staticmethod
    def from_intel_hex(data: bytes) -> HexFile: ...
    @staticmethod
    def from_intel_hex_16bit(data: bytes) -> HexFile: ...
    @staticmethod
    def from_srec(data: bytes) -> HexFile: ...
    @staticmethod
    def from_file(path: Pathish) -> HexFile: ...
    @staticmethod
    def from_file_bytes(data: bytes) -> HexFile: ...
    def segments(self, *, normalized: bool = False) -> list[Segment]: ...
    def normalized(self) -> HexFile: ...
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
    def append_segment(self, segment: Segment) -> None: ...
    def prepend_segment(self, segment: Segment) -> None: ...
    def write(self, addr: int, data: bytes) -> None: ...
    def read_byte(self, addr: int) -> int | None: ...
    def read(self, addr: int, length: int) -> bytes | None: ...
    def read_sparse(self, addr: int, length: int) -> list[int | None]: ...
    def to_bytes(self, *, fill: int = 0xFF) -> bytes | None: ...
    def to_binary(self, *, fill_gaps: int | None = None) -> bytes: ...
    def to_intel_hex(
        self, *, bytes_per_line: int = 32, mode: IntelHexMode | None = None
    ) -> bytes: ...
    def to_srec(
        self, *, bytes_per_line: int = 16, record_type: SRecordType | None = None
    ) -> bytes: ...
    def to_hex_ascii(
        self, *, line_length: int = 16, separator: str | None = None
    ) -> bytes: ...
    def to_c_code(
        self,
        file_name: str,
        *,
        prefix: str = "",
        word_size: Literal[1, 2, 4] = 1,
        motorola: bool = False,
        xor: int | None = None,
        created: str = "",
        generation: int = 0,
    ) -> tuple[bytes, bytes]:
        """HexView's `/XC` C arrays of the blocks, as the `.c` and `.h` file contents.
        `file_name` names the `.c` file in its comment and the `.h` file it includes,
        `xor` is applied to every element, and `created` and `generation` fill the
        creation date and the `_GEN_RAND` check."""
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
    def validation_structure(
        self,
        *,
        tag_begin: bytes,
        tag_end: bytes,
        block_checksum: int | None = None,
        file_checksum: int | None = None,
        validate_sum: bool = False,
        big_endian: bool = False,
        force_32bit: bool = False,
        alfi: bool = False,
        one_byte_count: bool = False,
        spare: RangesLike | None = None,
    ) -> bytes:
        """HexView's `/vs` validation structure over the blocks, leaving out `spare`:
        the tags, block count, each block's address, length and `block_checksum`
        method result, the `file_checksum` result over all blocks, and with
        `validate_sum` the 16-bit sum of those bytes. Addresses and lengths take 32
        bits when forced or when a block ends above 0xFFFF."""
    def hsm_validation_structure(
        self, *, group_id: int = 0, mode: int = 0, hash: int = 20
    ) -> bytes:
        """HexView's `/vshsm` structure over the blocks: big-endian group ID, segment
        count, and each block's address, length, mode and `hash` checksum method
        result."""
    def to_gac_swil(self) -> bytes:
        """A GAC software interlock file (`/XGACSWIL`): the block count, each block's
        big-endian address and length, then the data."""
    def write_binary(self, path: Pathish, *, fill_gaps: int | None = None) -> None: ...
    def write_intel_hex(
        self,
        path: Pathish,
        *,
        bytes_per_line: int = 32,
        mode: IntelHexMode | None = None,
    ) -> None: ...
    def write_srec(
        self,
        path: Pathish,
        *,
        bytes_per_line: int = 16,
        record_type: SRecordType | None = None,
    ) -> None: ...
    def write_hex_ascii(
        self, path: Pathish, *, line_length: int = 16, separator: str | None = None
    ) -> None: ...
    def filter(self, ranges: RangesLike) -> None: ...
    def cut(self, ranges: RangesLike) -> None: ...
    def fill(
        self,
        ranges: RangesLike,
        *,
        pattern: bytes | None = None,
        overwrite: bool = False,
    ) -> None: ...
    def fill_gaps(self, *, fill: int = 0xFF) -> None: ...
    def merge(
        self,
        other: HexFile,
        *,
        mode: MergeMode | None = None,
        offset: int = 0,
        range: RangeLike | None = None,
    ) -> None: ...
    def offset(self, offset: int) -> None: ...
    def align(self, alignment: int, *, length: int = 0, fill: int = 0xFF) -> None:
        """Move block starts down to `alignment` and grow block lengths, counted from the
        aligned start, to `length` (`/AD`, `/AL`); 0 leaves them. HexView aligns with
        the bit mask of the value minus one."""
    def split(self, max_size: int) -> None:
        """Split each block into pieces of at most `max_size` bytes; the pieces stay
        separate blocks."""
    def remove_small_blocks(self, min_len: int) -> None:
        """Remove blocks shorter than `min_len` bytes (`/RB`)."""
    def swap(self, mode: SwapMode) -> None: ...
    def dspic_expand(self, range: RangeLike, target: int | None = None) -> None: ...
    def dspic_shrink(self, range: RangeLike, target: int | None = None) -> None: ...
    def dspic_clear_ghost(self, range: RangeLike) -> None: ...
    def remap(self, start: int, end: int, linear: int, size: int, inc: int) -> None: ...
    def map_star12(self) -> None: ...
    def map_star12x(self) -> None: ...
    def map_star08(self) -> None: ...
    def sign(
        self,
        method: SignatureMethod,
        key: Key,
        *,
        metadata: bool = False,
        placement: int | Placement | None = None,
        salt: bytes | None = None,
    ) -> bytes:
        """Sign the block data in address order and return the signature (`/DP`).
        `metadata` precedes each block with its big-endian start address and
        length. `key` is a key file's content or key text, read as HexView reads
        it: HIS or PKCS #1 hex text, PKCS #8 or PKCS #1 PEM or DER for RSA; a raw
        hex key, or an ECC key in PEM, DER or hex text DER, for Ed25519 and P-256.
        `salt` is the RSA-PSS salt, a random 32 bytes without it. ECDSA is
        deterministic (RFC 6979) and returns r and s; `ed25519` signs a single
        block. With `placement`, the signature is also written into the image."""
    def mac(
        self,
        method: MacMethod,
        key: bytes,
        *,
        metadata: bool = False,
        placement: int | Placement | None = None,
    ) -> bytes:
        """HMAC or CMAC over the block data, as `sign` covers it (`/DP`). HMAC uses
        at most the first 64 bytes of `key`; CMAC needs a 16-byte key."""
    def xor(self, key: bytes | None = None) -> None:
        """XOR the data with `key`, repeated across the blocks; without a key, invert
        the data (`/DP1`)."""
    def encrypt(
        self,
        mode: CipherMode,
        key: Key,
        *,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
        aad: bytes | None = None,
        placement: int | Placement | None = None,
    ) -> bytes | None:
        """Encrypt with AES or RSA as HexView does (`/DP`). AES takes the raw key
        as bytes, whose length picks AES-128, -192 or -256. ECB, CBC and CTR
        encrypt each block on its own, after adding `padding`; without `iv`, CBC
        and CTR take the first 16 bytes of the first block as the IV and leave
        them in place. GCM encrypts all blocks as one stream with `iv` as the nonce
        and `aad` as additional data, and returns the tag, which `placement` also
        writes into the image; each block takes the whole 16-byte units done by
        its end and the last block the rest. RSA modes take a public or private
        key as `sign` reads it and encrypt each block on its own with random
        padding; `rsa-pkcs1v15` encrypts a whole number of key lengths without
        padding, and other blocks must fit one padded key length."""
    def decrypt(
        self,
        mode: CipherMode,
        key: Key,
        *,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
        aad: bytes | None = None,
        tag: bytes | RangeLike | None = None,
    ) -> None:
        """Reverse `encrypt` (`/DP`); padding is checked and removed, except after
        CTR. GCM checks `tag`, given as bytes or as an image range at the start or
        end of a block that stays in place; on a mismatch it raises `ValueError`,
        and the data stays decrypted. RSA modes take a private key. OAEP needs
        exactly one key length per block; `rsa-pkcs1v15` also accepts whole
        numbers of key lengths, and decrypts a single key length without padding
        when its padding is not valid."""
    def compress(
        self,
        method: Compression = "lzss",
        *,
        window_bits: int | None = None,
        length_bits: int | None = None,
        key: bytes | None = None,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
    ) -> None:
        """Compress each block in place as HexView does (`/DP26`, `/DP36`, `/DP57`);
        a block keeps its start address and takes the compressed length. LZSS uses a
        `window_bits` window and `length_bits` lengths, 10 and 4 by default, with
        0 < length_bits < window_bits < 16; with 8 or more length bits it codes
        literals only, as HexView does. With `key`, each compressed block is then
        AES-CBC encrypted from `iv` (zero bytes by default) after adding `padding`
        (`/DP34`, `/DP59`). ARLE codes byte, word and long word runs."""
    def decompress(
        self,
        method: Compression = "lzss",
        *,
        window_bits: int | None = None,
        length_bits: int | None = None,
        key: bytes | None = None,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
    ) -> None:
        """Reverse `compress` (`/DP27`, `/DP37`, `/DP58`; with `key`, `/DP35`,
        `/DP60`). LZSS reads any data, taking missing bits as zero; a block that
        decompresses to nothing keeps its data. ARLE raises `ValueError` on an
        incomplete token or empty output."""
    def verify_signature(
        self,
        method: SignatureMethod,
        key: Key,
        signature: bytes,
        *,
        metadata: bool = False,
    ) -> None:
        """Verify `signature` over the block data (`/SV`); raises `ValueError` if it
        does not match. `key` is a public or private key in the forms `sign` reads
        (an ECC private key must include its public key), a PKCS #1 or SPKI public
        key, or an X.509 certificate. RSA-PSS accepts any salt length."""

class PipelineResult:
    @property
    def hexfile(self) -> HexFile: ...
    @property
    def checksums(self) -> list[bytes]: ...
    @property
    def data_processing(self) -> bytes | None:
        """The data processing output: a signature, MAC or AES-GCM tag."""

class Pipeline:
    """HexView-ordered recipe: each method configures one stage, and `apply` runs
    the configured stages in HexView order, whatever order they were set in.
    Methods for single stages replace earlier settings; `sign`, `mac`, `xor`,
    `encrypt` and `decrypt` share the data processing stage; `dspic_*`, `cut`,
    `merge` and `checksum` add to their stage. Configured data stages join adjacent data
    into one block; pass `source.normalized()` to also join it on input, as
    HexView does when it loads a file."""

    def __init__(self) -> None: ...
    def apply(self, source: HexFile) -> PipelineResult: ...
    def map_star12(self) -> None: ...
    def map_star12x(self) -> None: ...
    def map_star08(self) -> None: ...
    def remap(self, start: int, end: int, linear: int, size: int, inc: int) -> None: ...
    def dspic_expand(self, range: RangeLike, target: int | None = None) -> None: ...
    def dspic_shrink(self, range: RangeLike, target: int | None = None) -> None: ...
    def dspic_clear_ghost(self, range: RangeLike) -> None: ...
    def fill(self, ranges: RangesLike, *, pattern: bytes | None = None) -> None: ...
    def fill_random(self, ranges: RangesLike, *, seed: int) -> None: ...
    def cut(self, ranges: RangesLike) -> None: ...
    def merge(
        self,
        other: HexFile,
        *,
        mode: MergeMode | None = None,
        offset: int = 0,
        range: RangeLike | None = None,
    ) -> None: ...
    def filter(self, ranges: RangesLike) -> None: ...
    def fill_gaps(self, *, fill: int = 0xFF) -> None: ...
    def align(self, alignment: int, *, length: int = 0, fill: int = 0xFF) -> None: ...
    def split(self, max_size: int) -> None: ...
    def remove_small_blocks(self, min_len: int) -> None:
        """Remove blocks shorter than `min_len` bytes after the split and swap stages (`/RB`)."""
    def swap(self, mode: SwapMode) -> None: ...
    def checksum(
        self,
        algorithm: int,
        *,
        placement: int | Placement | None = None,
        range: RangeLike | None = None,
        reverse: bool = False,
        exclude: RangesLike | None = None,
        forced_range: RangeLike | None = None,
        forced_pattern: bytes | None = None,
        constant: bytes | None = None,
    ) -> None:
        """Add a checksum stage using a HexView `/CS` algorithm index. `reverse`
        reverses the algorithm's native byte order (`/CSR`); `forced_range` is
        included even where it holds no data, with gaps taking `forced_pattern`
        (default 0xFF). Algorithm 16 writes `constant` (default 08 15) instead of
        a checksum."""
    def sign(
        self,
        method: SignatureMethod,
        key: Key,
        *,
        metadata: bool = False,
        placement: int | Placement | None = None,
        salt: bytes | None = None,
    ) -> None:
        """Sign after the checksum stages (`/DP`); see `HexFile.sign`."""
    def mac(
        self,
        method: MacMethod,
        key: bytes,
        *,
        metadata: bool = False,
        placement: int | Placement | None = None,
    ) -> None:
        """MAC after the checksum stages (`/DP`); see `HexFile.mac`."""
    def xor(self, key: bytes | None = None) -> None:
        """XOR after the checksum stages (`/DP`); see `HexFile.xor`."""
    def encrypt(
        self,
        mode: CipherMode,
        key: Key,
        *,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
        aad: bytes | None = None,
        placement: int | Placement | None = None,
    ) -> None:
        """Encrypt after the checksum stages (`/DP`); see `HexFile.encrypt`."""
    def decrypt(
        self,
        mode: CipherMode,
        key: Key,
        *,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
        aad: bytes | None = None,
        tag: bytes | RangeLike | None = None,
    ) -> None:
        """Decrypt after the checksum stages (`/DP`); see `HexFile.decrypt`."""
    def compress(
        self,
        method: Compression = "lzss",
        *,
        window_bits: int | None = None,
        length_bits: int | None = None,
        key: bytes | None = None,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
    ) -> None:
        """Compress after the checksum stages (`/DP`); see `HexFile.compress`."""
    def decompress(
        self,
        method: Compression = "lzss",
        *,
        window_bits: int | None = None,
        length_bits: int | None = None,
        key: bytes | None = None,
        iv: bytes | None = None,
        padding: AesPadding | None = None,
    ) -> None:
        """Decompress after the checksum stages (`/DP`); see `HexFile.decompress`."""
    def verify(
        self,
        method: SignatureMethod,
        key: Key,
        signature: bytes,
        *,
        metadata: bool = False,
    ) -> None:
        """Verify after the data processing stage (`/SV`); see
        `HexFile.verify_signature`."""

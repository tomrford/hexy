from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

import hexy
from hexy import DataProcessing


def _pat(length, seed):
    return bytes((seed + i * 7) & 0xFF for i in range(length))


def _from_pats(*segments):
    return hexy.HexFile(
        [hexy.Segment(start, _pat(length, seed)) for start, length, seed in segments]
    )


def test_file_autodetect_and_write_helpers(tmp_path):
    source = hexy.HexFile.from_binary(b"\xde\xad\xbe\xef", 0x1000)
    paths = {
        "intel": tmp_path / "firmware.hex",
        "srec": tmp_path / "firmware.s19",
        "binary": tmp_path / "firmware.bin",
    }
    source.write_intel_hex(paths["intel"])
    source.write_srec(paths["srec"])
    source.write_binary(paths["binary"])

    for path in paths.values():
        assert hexy.HexFile.from_file(path).to_binary() == b"\xde\xad\xbe\xef"
    assert hexy.HexFile.from_file(paths["intel"]).read(0x1000, 4) == b"\xde\xad\xbe\xef"
    with pytest.raises(FileNotFoundError):
        hexy.HexFile.from_file(tmp_path / "missing.hex")


def test_segments_keep_insertion_order_and_blocks_resolve_overlaps():
    hf = hexy.HexFile(
        segment for segment in [
            hexy.Segment(0x1000, b"\xaa\xbb"), hexy.Segment(0x1001, b"\xcc")
        ]
    )

    assert [(s.start, s.data) for s in hf.segments()] == [
        (0x1000, b"\xaa\xbb"),
        (0x1001, b"\xcc"),
    ]
    assert [(s.start, s.data) for s in hf.blocks()] == [(0x1000, b"\xaa\xcc")]


def test_errors_map_to_hexy_exceptions():
    with pytest.raises(hexy.RangeError):
        hexy.Segment(0xFFFFFFFF, b"\xaa\xbb")
    with pytest.raises(hexy.RangeError):
        hexy.AddressRange.parse("1000h,4")
    with pytest.raises(hexy.ParseError):
        hexy.HexFile.from_intel_hex(b":0100000000FE\n")
    with pytest.raises(hexy.OperationError):
        hexy.HexFile.from_binary(b"\xaa", 0x100000).to_intel_hex(mode="segment")
    with pytest.raises(ValueError, match="unknown merge mode 'opaque'"):
        hexy.HexFile().merge(hexy.HexFile(), mode="opaque")


def test_ranges_accept_address_ranges_and_hexview_text():
    hf = hexy.HexFile.from_binary(bytes(range(8)), 0x1000)
    hf.cut([hexy.AddressRange(0x1001, 0x1002), "0x1005,2"])
    assert hf.read_sparse(0x1000, 8) == [0, None, None, 3, 4, None, None, 7]

    assert hexy.AddressRange.parse("+ 4096,4x") == hexy.AddressRange(0x1000, length=4)
    with pytest.raises(TypeError, match="not a single range text"):
        hf.cut("0x1001-0x1002")


def test_pipeline_matches_hexview_multistage_checksum():
    # HexView 1.15.2: gaps.hex /CS9:cs.txt /SWAPWORD /SB:0x40 /AL /AD:0x40 /AF:00
    # /AR:0x0F00-0x1FFF /MT:merge.hex;0x100 /CR:0x1010-0x101F /FP:A55A /FR:0x0F00-0x0F3F
    # writes 0x4E, 0x5E, 0x64, 0x5E. Stages are configured in reverse order on purpose.
    source = _from_pats(
        (0x1000, 0x100, 1), (0x1180, 0x80, 2), (0x1301, 0x3E, 3), (0x2000, 6, 4)
    )
    merge = _from_pats((0x10F0, 0x40, 9), (0x1500, 0x10, 10))
    pipeline = hexy.Pipeline()
    pipeline.checksum(9)
    pipeline.swap("word")
    pipeline.split(0x40)
    pipeline.align(0x40, length=0x40, fill=0x00)
    pipeline.filter(["0x0F00-0x1FFF"])
    pipeline.merge(merge, mode="preserve", offset=0x100)
    pipeline.cut(["0x1010-0x101F"])
    pipeline.fill(["0x0F00-0x0F3F"], pattern=b"\xa5\x5a")

    result = pipeline.apply(source)

    assert result.checksums == [b"\x4e\x5e\x64\x5e"]
    assert result.hexfile.read(0x0F00, 4) == b"\x5a\xa5\x5a\xa5"
    assert source.read(0x0F00, 1) is None


def test_pipeline_removes_split_pieces_and_places_constant():
    # HexView 1.15.2: /SB:0x100 /RB=0x101 removes every piece; /CS16 writes its constant.
    pipeline = hexy.Pipeline()
    pipeline.remove_small_blocks(0x101)
    pipeline.split(0x100)
    pipeline.checksum(16, placement=0x5000)

    result = pipeline.apply(hexy.HexFile.from_binary(bytes(0x300), 0x1000))

    assert result.checksums == [b"\x08\x15"]
    assert [s.start for s in result.hexfile.segments()] == [0x5000]


KEYS = Path(__file__).parents[2] / "hexy-core" / "tests" / "fixtures" / "keys"
# HexView 1.15.2 /DP33 with rsa_his_private.txt over 0x1000 (0x30 bytes) and 0x2000 (0x10).
RSA_METADATA = bytes.fromhex(
    "a699f342ff9fccb1d2874797cb78b069a535ecc983fcca83cd317640fa7ab725"
    "f7d0d9423f9aae0d44434e22c8589ea8a073038ea46094da2a7a07570e7c7fcc"
    "4d12974f94a1fcfd4c0e8535a2701476aabae9868948f91248b99f9ebf74b59f"
    "1577f394e9652626e2e0a41db94b03ea0b694c8dd83e966243137633ecfe2c78"
)


def test_sign_and_verify_match_hexview():
    source = _from_pats((0x1000, 0x30, 1), (0x2000, 0x10, 2))
    private = (KEYS / "rsa_his_private.txt").read_text()
    public = (KEYS / "rsa_his_public.txt").read_bytes()
    sign = DataProcessing.sign("rsa-pkcs1v15-sha256", private, metadata=True)

    assert source.copy().process_data(sign) == RSA_METADATA
    source.verify("rsa-pkcs1v15-sha256", public, RSA_METADATA, metadata=True)
    with pytest.raises(hexy.VerificationError):
        source.verify("rsa-pkcs1v15-sha256", public, RSA_METADATA)

    pipeline = hexy.Pipeline()
    pipeline.verify("rsa-pkcs1v15-sha256", public, RSA_METADATA, metadata=True)
    pipeline.process_data(sign, placement=0x3000)
    with pytest.raises(hexy.VerificationError):
        pipeline.apply(source)

    pipeline = hexy.Pipeline()
    pipeline.process_data(sign, placement=0x3000)
    result = pipeline.apply(source)
    assert result.data_processing == RSA_METADATA
    assert result.hexfile.read(0x3000, 128) == RSA_METADATA


def test_asymmetric_methods_match_hexview():
    source = _from_pats((0x1000, 0x30, 1), (0x2000, 0x10, 2))
    # HexView 1.15.2 /DP38 with #SALT=0102030405, and /DP48.
    private = (KEYS / "rsa_pkcs8.pem").read_bytes()
    pss = DataProcessing.sign("rsa-pss-sha256", private, salt=bytes(range(1, 6)))
    assert source.copy().process_data(pss)[:8] == bytes.fromhex("3691474c28b26247")
    seed = (KEYS / "ed25519_seed.txt").read_text()
    ed25519ph = DataProcessing.sign("ed25519ph-sha512", seed)
    assert source.copy().process_data(ed25519ph)[:8] == bytes.fromhex(
        "4461b57de6c357df"
    )
    with pytest.raises(hexy.ProcessingError):
        source.copy().process_data(DataProcessing.sign("ed25519", seed))

    p256 = (KEYS / "p256_sec1.pem").read_bytes()
    signature = source.copy().process_data(
        DataProcessing.sign("ecdsa-p256-sha256", p256, metadata=True)
    )
    source.verify("ecdsa-p256-sha256", p256, signature, metadata=True)

    public = (KEYS / "rsa_his_public.txt").read_text()
    encrypted = source.copy()
    encrypted.process_data(DataProcessing.encrypt("rsa-oaep-sha256", public))
    assert encrypted.read(0x2000, 0x10) != source.read(0x2000, 0x10)
    encrypted.process_data(DataProcessing.decrypt("rsa-oaep-sha256", private))
    assert encrypted.read(0x2000, 0x10) == source.read(0x2000, 0x10)


AES_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def test_symmetric_methods_match_hexview():
    gaps = _from_pats(
        (0x1000, 0x100, 1), (0x1180, 0x80, 2), (0x1301, 0x3E, 3), (0x2000, 6, 4)
    )
    # HexView 1.15.2 /DP4 and /DP44 over gaps.hex; key text reads as a key file.
    assert gaps.process_data(DataProcessing.mac("hmac-sha1", AES_KEY)) == bytes.fromhex(
        "3A8E6287A8443A03FC254B861702942BDB06E871"
    )
    cmac = DataProcessing.mac("cmac-aes128", AES_KEY.hex())
    assert gaps.process_data(cmac) == bytes.fromhex("8609A186AB2B6FA9165CBFEC95D179DF")

    # HexView 1.15.2 /DP11 without #IV: the first 16 bytes stay as the IV.
    source = _from_pats((0x1000, 0x40, 1), (0x2000, 0x20, 2))
    encrypted = source.copy()
    encrypted.process_data(DataProcessing.encrypt("cbc", AES_KEY, padding="pkcs7"))
    assert encrypted.read(0x1010, 16) == bytes.fromhex(
        "f436b5ea403cd5018f7ae5880ebae1b2"
    )
    assert encrypted.read(0x2000, 16) == bytes.fromhex(
        "d5c6df82d76aa57c6438b5b074c613e7"
    )
    encrypted.process_data(DataProcessing.decrypt("cbc", AES_KEY, padding="pkcs7"))
    assert encrypted.to_binary() == source.to_binary()

    pipeline = hexy.Pipeline()
    gcm = DataProcessing.encrypt("gcm", AES_KEY, iv=bytes(12), aad=b"AB")
    pipeline.process_data(gcm, placement="append")
    result = pipeline.apply(source)
    tagged = result.hexfile
    assert tagged.read(0x2020, 16) == result.data_processing
    tagged.process_data(
        DataProcessing.decrypt(
            "gcm", AES_KEY, iv=bytes(12), aad=b"AB", tag="0x2020-0x202F"
        )
    )
    assert tagged.read(0x2000, 0x20) == source.read(0x2000, 0x20)
    with pytest.raises(hexy.VerificationError):
        tagged.process_data(
            DataProcessing.decrypt("gcm", AES_KEY, iv=bytes(12), tag=bytes(16))
        )


def test_compression_matches_hexview():
    # HexView 1.15.2 /DP26, /DP36 and /DP59 (no #IV: a zero IV).
    packed = hexy.HexFile.from_binary(b"ABCDEFGH", 0x1000)
    packed.process_data(DataProcessing.compress())
    assert packed.to_binary() == bytes.fromhex("a0d0a8744a2d1a8f480000")
    packed.process_data(
        DataProcessing.decompress("lzss", window_bits=10, length_bits=4)
    )
    assert packed.to_binary() == b"ABCDEFGH"

    runs = hexy.HexFile.from_binary(b"AAAABAB", 0x1000)
    runs.process_data(DataProcessing.compress("arle"))
    assert runs.to_binary() == bytes.fromhex("82414103424142")

    pipeline = hexy.Pipeline()
    pipeline.process_data(DataProcessing.compress(key=AES_KEY, padding="pkcs7"))
    encrypted = pipeline.apply(hexy.HexFile.from_binary(b"ABC" * 6, 0x1000)).hexfile
    assert encrypted.to_binary() == bytes.fromhex("b9f09bea7f33b9812a576f2d1a3ae0e1")
    encrypted.process_data(DataProcessing.decompress(key=AES_KEY, padding="pkcs7"))
    assert encrypted.to_binary() == b"ABC" * 6

    with pytest.raises(hexy.ProcessingError):
        hexy.HexFile.from_binary(b"\x40\x00").process_data(
            DataProcessing.decompress("arle")
        )
    with pytest.raises(hexy.ProcessingError):
        DataProcessing.compress(window_bits=4, length_bits=4)


def test_exports_match_hexview():
    """HexView 1.15.2 `/XC`, `/XK` and `/XGACSWIL` of the same two blocks."""
    hf = _from_pats((0x1000, 0x13, 1), (0x2001, 6, 2))
    created = datetime(2026, 11, 7, 21, 36, 7, tzinfo=timezone(timedelta(hours=1)))
    c, h = hf.to_c_code("out.c", prefix="fd", word_size=4, xor=0xCC, created=created)
    assert (
        b"\t0x160F08CDul, 0x322B24D1ul, 0x4E4740F5ul, 0x6A635C99ul,\r\n\t0x007F78BDul\r\n};"
        in c
    )
    assert b"#include <out.h>\r\n" in c
    assert b"*  File created:  Sat Nov  7 21:36:07 2026\r\n" in h
    assert b"#define FD_GEN_RAND 921\r\n" in h
    assert b"#define FD_BLOCK0_CHECKSUM\t0x164411Dul\r\n" in h

    assert (
        hf.to_gac_swil()
        == bytes.fromhex("02 00001000 00000013 00002001 00000006") + hf.to_binary()
    )

    with pytest.raises(hexy.OperationError):
        hf.to_flash_kernel("k.fkl")
    hf.cut(["0x2000-0x2FFF"])
    kernel = hf.to_flash_kernel("k.fkl", ram_start="0x38EB")
    assert kernel.startswith(
        b'\r\n[FLASH_KERNEL_CONFIG]\r\n\r\nFLASH_KERNEL_NAME="k.fkl"\r\n'
    )
    assert (
        b"FLASH_KERNEL_SIZE=0x13\r\nFLASH_KERNEL_RAM_ADDR=0x1000\r\nFLASH_KERNEL_RAM_START=0x38EB\r\n"
        in kernel
    )


def test_validation_structures_match_hexview():
    """HexView 1.15.2 `/vs` with the manual's `[VALIDATION]` example and `/vshsm` with
    `HASH_METHOD=9`."""
    hf = _from_pats((0x1000, 0x13, 1), (0x2000, 0x20, 2))
    structure = hf.validation_structure(
        tag_begin=b"\x12\x34",
        tag_end=b"\x43\x21",
        block_checksum=0,
        file_checksum=9,
        validate_sum=True,
    )
    assert bytes(structure) == bytes.fromhex(
        "1234 02 0010 1300 04C0 0020 2000 0DD0 BA9FF711 4321 1105"
    )
    assert structure.blocks[0] == (0x1000, 0x13, b"\x04\xc0")
    c, _ = structure.to_c("v.c", "v.h")
    assert b"\t0x1234u,\t\t/* Magic Tag begin */\r\n" in c
    assert hf.hsm_validation_structure(
        group_id=0x1234, mode=1, hash=9
    ) == bytes.fromhex(
        "00001234 0002 00001000 00000013 0001 103080A3 00002000 00000020 0001 AA35EDB3"
    )

    pipeline = hexy.Pipeline()
    pipeline.hsm_validation_structure(
        group_id=0x1234,
        mode=1,
        hash=9,
        placement=0x8000,
        signature=DataProcessing.mac("hmac-sha1", AES_KEY),
    )
    result = pipeline.apply(hf)
    assert result.hsm_validation == hf.hsm_validation_structure(
        group_id=0x1234, mode=1, hash=9
    )
    assert result.hexfile.read(0x8000 - 20, 20) == result.hsm_signature


def test_zero_line_length_srec_exports_only_termination(tmp_path):
    source = hexy.HexFile.from_binary(b"\xaa", 0xFFFF_FFFF)
    for record_type, expected in [
        ("auto", b"S9030000FC\r\n"),
        ("s1", b"S9030000FC\r\n"),
        ("s2", b"S804000000FB\r\n"),
        ("s3", b"S70500000000FA\r\n"),
    ]:
        assert source.to_srec(bytes_per_line=0, record_type=record_type) == expected
        path = tmp_path / f"{record_type}.s19"
        source.write_srec(path, bytes_per_line=0, record_type=record_type)
        assert path.read_bytes() == expected


def test_pipeline_places_checksums_in_order():
    pipeline = hexy.Pipeline()
    pipeline.checksum(0, placement="append")
    pipeline.checksum(0, placement=0x2000, reverse=True)

    result = pipeline.apply(hexy.HexFile.from_binary(b"\x01\x02\x03\x04", 0x1000))

    assert result.checksums == [b"\x00\x0a", b"\x14\x00"]
    assert result.hexfile.read(0x1004, 2) == b"\x00\x0a"
    assert result.hexfile.read(0x2000, 2) == b"\x14\x00"


def test_large_dword_swap_matches_direct_and_pipeline_results():
    data = bytes(range(16)) * (0x100_0000 // 16)
    direct = hexy.HexFile.from_binary(data)
    direct.swap("dword")
    pipeline = hexy.Pipeline()
    pipeline.swap("dword")
    pipeline.checksum(0)

    result = pipeline.apply(hexy.HexFile.from_binary(data))

    expected = b"\x03\x02\x01\x00" + b"\x07\x06\x05\x04" * 3
    assert direct.read(0, 16) == expected
    assert result.hexfile.read(0, 16) == expected
    assert result.checksums == [b"\xff\xf0"]


def test_validation_c_preserves_long_tags_and_explicit_overrides():
    structure = hexy.HexFile.from_binary(b"\xaa\xbb", 0x10).validation_structure(
        tag_begin=b"\x01\x02\x03\x04\x05",
        tag_end=b"\x06\x07\x08\x09\x0a",
        validate_sum=True,
    )
    c, _ = structure.to_c("v.c", "v.h")
    assert b"{0x01, 0x02, 0x03, 0x04, 0x05}" in c
    assert b"{0x06, 0x07, 0x08, 0x09, 0x0A}" in c
    c, _ = structure.to_c("v.c", "v.h", tag_begin_value=1, tag_end_value=2)
    assert b"{0x00, 0x00, 0x00, 0x00, 0x01}" in c
    assert b"{0x00, 0x00, 0x00, 0x00, 0x02}" in c

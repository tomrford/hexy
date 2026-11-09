from pathlib import Path

import pytest

import hexy


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


def test_file_autodetect_and_write_helpers(tmp_path):
    source = hexy.HexFile.from_binary(b"\xde\xad\xbe\xef", 0x1000)
    intel_path = tmp_path / "firmware.hex"
    source.write_intel_hex(intel_path)

    from_path = hexy.HexFile.from_file(intel_path)
    assert from_path.read(0x1000, 4) == b"\xde\xad\xbe\xef"

    from_bytes = hexy.HexFile.from_file_bytes(intel_path.read_bytes())
    assert from_bytes.read(0x1000, 4) == b"\xde\xad\xbe\xef"

    srec_path = tmp_path / "firmware.s19"
    binary_path = tmp_path / "firmware.bin"
    ascii_path = tmp_path / "firmware.txt"
    from_path.write_srec(srec_path)
    from_path.write_binary(binary_path)
    from_path.write_hex_ascii(ascii_path, separator=", ")

    assert hexy.HexFile.from_file(srec_path).read(0x1000, 4) == b"\xde\xad\xbe\xef"
    assert binary_path.read_bytes() == b"\xde\xad\xbe\xef"
    assert (
        hexy.HexFile.from_hex_ascii(ascii_path.read_bytes(), 0x1000).read(0x1000, 4)
        == b"\xde\xad\xbe\xef"
    )


def test_segments_preserve_raw_order_and_normalize_last_wins():
    hf = hexy.HexFile.from_segments(
        [
            hexy.Segment(0x1000, b"\xaa\xbb"),
            hexy.Segment(0x1001, b"\xcc"),
        ]
    )

    raw = hf.segments()
    assert [(segment.start, segment.data) for segment in raw] == [
        (0x1000, b"\xaa\xbb"),
        (0x1001, b"\xcc"),
    ]
    assert hf.read(0x1000, 2) == b"\xaa\xcc"
    assert hf.segments(normalized=True)[0].data == b"\xaa\xcc"


def test_segment_constructor_rejects_overflow():
    try:
        hexy.Segment(0xFFFFFFFF, b"\xaa\xbb")
    except ValueError as error:
        assert "exceeds u32 address space" in str(error)
    else:
        raise AssertionError("expected overflowing segment to be rejected")


def test_read_single_byte_at_u32_max():
    hf = hexy.HexFile.from_binary(b"\xaa", 0xFFFFFFFF)

    assert hf.read(0xFFFFFFFF, 1) == b"\xaa"
    assert hf.read(0xFFFFFFFE, 2) is None


def test_forced_intel_hex_segment_mode_rejects_high_address():
    hf = hexy.HexFile.from_binary(b"\xaa", 0x100000)

    try:
        hf.to_intel_hex(mode="segment")
    except ValueError as error:
        assert "extended segment" in str(error)
    else:
        raise AssertionError("expected high address to be rejected for segment mode")


def test_binary_hex_ascii_intel_hex_and_srec_roundtrip_in_memory():
    hf = hexy.HexFile.from_binary(b"\xde\xad\xbe\xef", 0x1000)

    intel = hexy.HexFile.from_intel_hex(hf.to_intel_hex())
    assert intel.read(0x1000, 4) == b"\xde\xad\xbe\xef"

    srec = hexy.HexFile.from_srec(hf.to_srec())
    assert srec.read(0x1000, 4) == b"\xde\xad\xbe\xef"

    ascii_hex = hexy.HexFile.from_hex_ascii(hf.to_hex_ascii(separator=", "), 0x1000)
    assert ascii_hex.read(0x1000, 4) == b"\xde\xad\xbe\xef"

    assert hf.to_binary() == b"\xde\xad\xbe\xef"


def test_binary_and_hex_ascii_default_to_zero_base_address():
    binary = hexy.HexFile.from_binary(b"\xde\xad")
    assert binary.read(0, 2) == b"\xde\xad"

    ascii_hex = hexy.HexFile.from_hex_ascii(b"DE AD")
    assert ascii_hex.read(0, 2) == b"\xde\xad"


def test_memory_operations_cover_filter_cut_fill_merge_align_split_swap():
    hf = hexy.HexFile.from_binary(bytes(range(16)), 0x1000)
    hf.cut(["0x1004-0x1007"])
    hf.fill(["0x1004-0x1007"], pattern=b"\xff", overwrite=False)
    hf.filter(["0x1000-0x100B"])

    overlay = hexy.HexFile.from_binary(b"\xaa\xbb", 0x1002)
    hf.merge(overlay, mode="overwrite")
    hf.align(4, fill=0xEE, length=True)
    hf.split(4)
    hf.swap("word")

    assert [len(segment) for segment in hf.segments()] == [4, 4, 4]
    assert hf.read(0x1000, 4) == b"\x01\x00\xbb\xaa"
    assert hf.read(0x1004, 4) == b"\xff\xff\xff\xff"


def test_empty_fill_pattern_is_rejected():
    hf = hexy.HexFile.from_binary(b"\x00", 0x1000)

    try:
        hf.fill(["0x1000-0x1000"], pattern=b"")
    except ValueError as error:
        assert "fill pattern cannot be empty" in str(error)
    else:
        raise AssertionError("expected empty fill pattern to be rejected")

    pipeline = hexy.Pipeline()
    try:
        pipeline.fill(["0x1000-0x1000"], pattern=b"")
    except ValueError as error:
        assert "fill pattern cannot be empty" in str(error)
    else:
        raise AssertionError("expected empty pipeline fill pattern to be rejected")


def test_range_lists_parse_each_compat_range_string():
    hf = hexy.HexFile.from_binary(bytes(range(8)), 0x1000)

    hf.cut(["'0x1001-0x1002'", "0x1005-0x1006"])

    assert hf.read_sparse(0x1000, 8) == [0, None, None, 3, 4, None, None, 7]


def test_range_list_apis_reject_packed_range_strings():
    hf = hexy.HexFile.from_binary(bytes(range(8)), 0x1000)

    try:
        hf.cut("'0x1001-0x1002:0x1005-0x1006'")
    except TypeError as error:
        assert "expected a list of range strings" in str(error)
    else:
        raise AssertionError("expected packed range string to be rejected")


def test_single_range_apis_accept_quoted_range_strings():
    base = hexy.HexFile.from_binary(b"\x00\x00", 0x1000)
    overlay = hexy.HexFile.from_binary(b"\xaa\xbb", 0x2000)

    base.merge(overlay, mode="overwrite", range="'0x2001-0x2001'")
    assert base.read_sparse(0x1000, 2) == [0, 0]
    assert base.read(0x2001, 1) == b"\xbb"

    hf = hexy.HexFile.from_binary(b"\x01\x02", 0x3000)
    hf.dspic_expand("'0x3000-0x3001'", 0x4000)
    assert hf.read(0x4000, 4) == b"\x01\x02\x00\x00"


def test_single_range_apis_reject_multiple_ranges_in_one_string():
    hf = hexy.HexFile.from_binary(b"\x01\x02", 0x1000)

    try:
        hf.dspic_expand("'0x1000-0x1000:0x1001-0x1001'")
    except ValueError as error:
        assert "expected a single range, got 2 ranges" in str(error)
    else:
        raise AssertionError("expected multiple ranges to be rejected")


def _pat(length, seed):
    return bytes((seed + i * 7) & 0xFF for i in range(length))


def _from_pats(*segments):
    return hexy.HexFile.from_segments(
        [hexy.Segment(start, _pat(length, seed)) for start, length, seed in segments]
    )


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
    pipeline.align(0x40, fill=0x00, length=True)
    pipeline.filter(["0x0F00-0x1FFF"])
    pipeline.merge(merge, mode="preserve", offset=0x100)
    pipeline.cut(["0x1010-0x101F"])
    pipeline.fill(["0x0F00-0x0F3F"], pattern=b"\xa5\x5a")

    result = pipeline.apply(source)

    assert result.checksums == [b"\x4e\x5e\x64\x5e"]
    assert result.hexfile.read(0x0F00, 4) == b"\x5a\xa5\x5a\xa5"
    assert source.read(0x0F00, 1) is None


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


def test_pipeline_removes_split_pieces_and_places_constant():
    # HexView 1.15.2: /SB:0x100 /RB=0x101 removes every piece; /CS16 writes a constant.
    pipeline = hexy.Pipeline()
    pipeline.remove_small_blocks(0x101)
    pipeline.split(0x100)
    pipeline.checksum(16, constant=b"", placement=0x5000)

    result = pipeline.apply(hexy.HexFile.from_binary(bytes(0x300), 0x1000))

    assert result.checksums == [b""]
    assert [s.start for s in result.hexfile.segments()] == [0x5000]


def test_dspic_and_mapping_surfaces_are_available():
    hf = hexy.HexFile.from_binary(b"\x01\x02\x03\x04", 0x1000)
    hf.dspic_expand("0x1000-0x1003", 0x2000)
    assert hf.read(0x2000, 8) == b"\x01\x02\x00\x00\x03\x04\x00\x00"

    mapped = hexy.HexFile.from_binary(b"\xaa", 0x4000)
    mapped.map_star12()
    assert mapped.read(0x0F8000, 1) == b"\xaa"


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

    assert source.sign("rsa-pkcs1v15-sha256", private, metadata=True) == RSA_METADATA
    source.verify_signature("rsa-pkcs1v15-sha256", public, RSA_METADATA, metadata=True)
    with pytest.raises(ValueError):
        source.verify_signature("rsa-pkcs1v15-sha256", public, RSA_METADATA)

    pipeline = hexy.Pipeline()
    pipeline.verify("rsa-pkcs1v15-sha256", public, RSA_METADATA, metadata=True)
    pipeline.sign("rsa-pkcs1v15-sha256", private, metadata=True, placement=0x3000)
    with pytest.raises(ValueError):
        pipeline.apply(source)

    pipeline = hexy.Pipeline()
    pipeline.sign("rsa-pkcs1v15-sha256", private, metadata=True, placement=0x3000)
    result = pipeline.apply(source)
    assert result.data_processing == RSA_METADATA
    assert result.hexfile.read(0x3000, 128) == RSA_METADATA


def test_signing_reports_small_pss_key_as_value_error():
    source = hexy.HexFile.from_binary(b"\x01\x02", 0x1000)
    key = (KEYS / "rsa_512_test.pem").read_bytes()

    with pytest.raises(ValueError):
        source.sign("rsa-pss-sha256", key, placement="append")

    assert source.read(0x1000, 2) == b"\x01\x02"
    assert source.total_bytes == 2


def test_signing_rejects_empty_ed25519_key_material():
    source = hexy.HexFile.from_binary(b"\x01\x02", 0x1000)
    for method in ("ed25519", "ed25519ph", "ed25519ph-sha512"):
        for key in (b"", b" \r\n,", b"0x"):
            with pytest.raises(ValueError):
                source.sign(method, key, placement="append")
    assert source.read(0x1000, 2) == b"\x01\x02"
    assert source.total_bytes == 2


def test_asymmetric_methods_match_hexview():
    source = _from_pats((0x1000, 0x30, 1), (0x2000, 0x10, 2))
    # HexView 1.15.2 /DP38 with #SALT=0102030405, and /DP48.
    private = (KEYS / "rsa_pkcs8.pem").read_bytes()
    pss = source.sign("rsa-pss-sha256", private, salt=bytes(range(1, 6)))
    assert pss[:8] == bytes.fromhex("3691474c28b26247")
    seed = (KEYS / "ed25519_seed.txt").read_text()
    assert source.sign("ed25519ph-sha512", seed)[:8] == bytes.fromhex(
        "4461b57de6c357df"
    )
    with pytest.raises(ValueError):
        source.sign("ed25519", seed)

    p256 = (KEYS / "p256_sec1.pem").read_bytes()
    pipeline = hexy.Pipeline()
    pipeline.sign("ecdsa-p256-sha256", p256, metadata=True)
    signature = pipeline.apply(source).data_processing
    source.verify_signature("ecdsa-p256-sha256", p256, signature, metadata=True)

    encrypted = source.copy()
    encrypted.encrypt("rsa-oaep-sha256", (KEYS / "rsa_his_public.txt").read_text())
    assert encrypted.read(0x2000, 0x10) != source.read(0x2000, 0x10)
    encrypted.decrypt("rsa-oaep-sha256", private)
    assert encrypted.read(0x2000, 0x10) == source.read(0x2000, 0x10)


AES_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")


def test_symmetric_methods_match_hexview():
    gaps = _from_pats(
        (0x1000, 0x100, 1), (0x1180, 0x80, 2), (0x1301, 0x3E, 3), (0x2000, 6, 4)
    )
    # HexView 1.15.2 /DP4 and /DP44 over gaps.hex.
    assert gaps.mac("hmac-sha1", AES_KEY) == bytes.fromhex(
        "3A8E6287A8443A03FC254B861702942BDB06E871"
    )
    assert gaps.mac("cmac-aes128", AES_KEY) == bytes.fromhex(
        "8609A186AB2B6FA9165CBFEC95D179DF"
    )

    # HexView 1.15.2 /DP11 without #IV: the first 16 bytes stay as the IV.
    source = _from_pats((0x1000, 0x40, 1), (0x2000, 0x20, 2))
    encrypted = source.copy()
    encrypted.encrypt("cbc", AES_KEY, padding="pkcs7")
    assert encrypted.read(0x1010, 16) == bytes.fromhex(
        "f436b5ea403cd5018f7ae5880ebae1b2"
    )
    assert encrypted.read(0x2000, 16) == bytes.fromhex(
        "d5c6df82d76aa57c6438b5b074c613e7"
    )
    encrypted.decrypt("cbc", AES_KEY, padding="pkcs7")
    assert encrypted.read(0x1000, 0x40) == source.read(0x1000, 0x40)
    assert encrypted.read(0x2000, 0x20) == source.read(0x2000, 0x20)

    pipeline = hexy.Pipeline()
    pipeline.encrypt("gcm", AES_KEY, iv=bytes(12), aad=b"AB", placement="append")
    result = pipeline.apply(source)
    tagged = result.hexfile
    assert tagged.read(0x2020, 16) == result.data_processing
    tagged.decrypt("gcm", AES_KEY, iv=bytes(12), aad=b"AB", tag="0x2020-0x202F")
    assert tagged.read(0x2000, 0x20) == source.read(0x2000, 0x20)
    with pytest.raises(ValueError):
        tagged.decrypt("gcm", AES_KEY, iv=bytes(12), tag=bytes(16))

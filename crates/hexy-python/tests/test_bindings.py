import hexy


def test_segments_preserve_raw_order_and_normalize_last_wins():
    hf = hexy.HexFile.from_segments(
        [
            hexy.Segment(0x1000, b"\xAA\xBB"),
            hexy.Segment(0x1001, b"\xCC"),
        ]
    )

    raw = hf.segments()
    assert [(segment.start, segment.data) for segment in raw] == [
        (0x1000, b"\xAA\xBB"),
        (0x1001, b"\xCC"),
    ]
    assert hf.read(0x1000, 2) == b"\xAA\xCC"
    assert hf.segments(normalized=True)[0].data == b"\xAA\xCC"


def test_binary_hex_ascii_intel_hex_and_srec_roundtrip_in_memory():
    hf = hexy.HexFile.from_binary(b"\xDE\xAD\xBE\xEF", 0x1000)

    intel = hexy.HexFile.from_intel_hex(hf.to_intel_hex())
    assert intel.read(0x1000, 4) == b"\xDE\xAD\xBE\xEF"

    srec = hexy.HexFile.from_srec(hf.to_srec())
    assert srec.read(0x1000, 4) == b"\xDE\xAD\xBE\xEF"

    ascii_hex = hexy.HexFile.from_hex_ascii(hf.to_hex_ascii(separator=", "), 0x1000)
    assert ascii_hex.read(0x1000, 4) == b"\xDE\xAD\xBE\xEF"

    assert hf.to_binary() == b"\xDE\xAD\xBE\xEF"


def test_memory_operations_cover_filter_cut_fill_merge_align_split_swap():
    hf = hexy.HexFile.from_binary(bytes(range(16)), 0x1000)
    hf.cut("0x1004-0x1007")
    hf.fill("0x1004-0x1007", pattern=b"\xFF", overwrite=False)
    hf.filter(["0x1000-0x100B"])

    overlay = hexy.HexFile.from_binary(b"\xAA\xBB", 0x1002)
    hf.merge(overlay, mode="overwrite")
    hf.align(4, fill=0xEE, length=True)
    hf.split(4)
    hf.swap("word")

    assert [len(segment) for segment in hf.segments()] == [4, 4, 4]
    assert hf.read(0x1000, 4) == b"\x01\x00\xBB\xAA"
    assert hf.read(0x1004, 4) == b"\xFF\xFF\xFF\xFF"


def test_pipeline_applies_in_user_order():
    hf = hexy.HexFile.from_binary(b"\x00\x01\x02\x03", 0x1000)
    pipeline = hexy.Pipeline()
    pipeline.swap("word")
    pipeline.fill("0x1001-0x1002", pattern=b"\xFF", overwrite=True)

    out = pipeline.apply(hf)

    assert hf.read(0x1000, 4) == b"\x00\x01\x02\x03"
    assert out.read(0x1000, 4) == b"\x01\xFF\xFF\x02"


def test_hexview_pipeline_uses_compat_operation_order():
    hf = hexy.HexFile.from_binary(b"\x00\x01\x02\x03", 0x1000)
    pipeline = hexy.HexViewPipeline()
    pipeline.swap("word")
    pipeline.fill("0x1001-0x1002", pattern=b"\xFF", overwrite=True)

    out = pipeline.apply(hf)

    assert out.read(0x1000, 4) == b"\x00\xFF\xFF\x03"


def test_dspic_and_mapping_surfaces_are_available():
    hf = hexy.HexFile.from_binary(b"\x01\x02\x03\x04", 0x1000)
    hf.dspic_expand("0x1000-0x1003", 0x2000)
    assert hf.read(0x2000, 8) == b"\x01\x02\x00\x00\x03\x04\x00\x00"

    mapped = hexy.HexFile.from_binary(b"\xAA", 0x4000)
    mapped.map_star12()
    assert mapped.read(0x0F8000, 1) == b"\xAA"

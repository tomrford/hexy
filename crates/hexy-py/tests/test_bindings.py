import hexy


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
        assert "extended segment mode" in str(error)
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


def test_pipeline_uses_compat_operation_order():
    hf = hexy.HexFile.from_binary(b"\x00\x01\x02\x03", 0x1000)
    pipeline = hexy.Pipeline()
    pipeline.swap("word")
    pipeline.fill(["0x1001-0x1002"], pattern=b"\xff", overwrite=True)

    out = pipeline.apply(hf)

    assert out.read(0x1000, 4) == b"\x00\xff\xff\x03"


def test_pipeline_orders_align_before_swap_even_when_called_late():
    hf = hexy.HexFile.from_binary(b"\x01\x02\x03", 0x1001)
    pipeline = hexy.Pipeline()
    pipeline.swap("word")
    pipeline.align(4, fill=0x00, length=True)

    out = pipeline.apply(hf)

    assert out.read(0x1000, 4) == b"\x01\x00\x03\x02"


def test_pipeline_orders_mapping_variants_before_remap():
    hf = hexy.HexFile.from_binary(b"\xaa", 0x4000)
    pipeline = hexy.Pipeline()
    pipeline.remap(0x104000, 0x104000, 0x200000, 0x1000, 0x1000)
    pipeline.map_star08()

    out = pipeline.apply(hf)

    assert out.read(0x200000, 1) == b"\xaa"


def test_pipeline_orders_dspic_expand_before_shrink():
    hf = hexy.HexFile.from_binary(b"\x01\x02", 0x1000)
    pipeline = hexy.Pipeline()
    pipeline.dspic_shrink("0x2000-0x2003", 0x3000)
    pipeline.dspic_expand("0x1000-0x1001", 0x2000)

    out = pipeline.apply(hf)

    assert out.read(0x3000, 2) == b"\x01\x02"


def test_compat_pipeline_rejects_mixed_merge_modes():
    first = hexy.HexFile.from_binary(b"\xaa", 0x1000)
    second = hexy.HexFile.from_binary(b"\xbb", 0x1001)
    pipeline = hexy.Pipeline()
    pipeline.merge(first, mode="preserve")

    try:
        pipeline.merge(second, mode="overwrite")
    except ValueError as error:
        assert "cannot combine preserve and overwrite merges" in str(error)
    else:
        raise AssertionError("expected mixed merge modes to be rejected")


def test_dspic_and_mapping_surfaces_are_available():
    hf = hexy.HexFile.from_binary(b"\x01\x02\x03\x04", 0x1000)
    hf.dspic_expand("0x1000-0x1003", 0x2000)
    assert hf.read(0x2000, 8) == b"\x01\x02\x00\x00\x03\x04\x00\x00"

    mapped = hexy.HexFile.from_binary(b"\xaa", 0x4000)
    mapped.map_star12()
    assert mapped.read(0x0F8000, 1) == b"\xaa"

use hexy_core::{
    AutoFormat, BinaryWriteOptions, HexFile, IntelHexWriteOptions, ParseError, Segment,
    detect_format, parse_auto, parse_intel_hex, write_binary, write_intel_hex,
};

#[test]
fn intel_hex_input_scans_past_header_text() -> Result<(), ParseError> {
    let input = b"HEADER\r\ncreated by fixture\r\n:020000000102FB\r\n:00000001FF\r\n";

    assert_eq!(detect_format(input), AutoFormat::IntelHex);

    let auto = parse_auto(input)?;
    assert_eq!(auto.read_bytes_contiguous(0, 2), Some(vec![0x01, 0x02]));

    let direct = parse_intel_hex(input)?;
    assert_eq!(direct.read_bytes_contiguous(0, 2), Some(vec![0x01, 0x02]));
    Ok(())
}

#[test]
fn intel_hex_input_rejects_leading_record_missing_colon() {
    let input = b"020000000102FB\r\n:00000001FF\r\n";

    let result = parse_intel_hex(input);

    assert!(matches!(
        result,
        Err(ParseError::InvalidRecord { line: 1, .. })
    ));
}

#[test]
fn srecord_input_does_not_scan_past_header_text() -> Result<(), ParseError> {
    let input = b"HEADER\r\nS10500000102F7\r\nS9030000FC\r\n";

    assert_eq!(detect_format(input), AutoFormat::Binary);
    let parsed = parse_auto(input)?;
    assert_eq!(
        parsed.read_bytes_contiguous(0, input.len()),
        Some(input.to_vec())
    );
    Ok(())
}

#[test]
fn intel_hex_writer_formats_u32_ceiling_as_extended_linear()
-> Result<(), std::string::FromUtf8Error> {
    let hexfile = HexFile::with_segments(vec![Segment::new(0xFFFF_FFFE, vec![0xAA, 0xBB])]);

    let output = write_intel_hex(&hexfile, &IntelHexWriteOptions::default()).unwrap();

    assert_eq!(
        String::from_utf8(output)?,
        ":02000004FFFFFC\r\n:02FFFE00AABB9C\r\n:00000001FF\r\n"
    );
    Ok(())
}

#[test]
fn intel_hex_parser_rejects_records_that_cross_u32_ceiling() {
    let input = b":02000004FFFFFC\r\n:02FFFF00AABB9B\r\n:00000001FF\r\n";

    let result = parse_intel_hex(input);

    assert!(matches!(result, Err(ParseError::AddressOverflow(_))));
}

#[test]
fn binary_writer_serializes_normalized_blocks_without_sparse_padding() {
    let hexfile = HexFile::with_segments(vec![
        Segment::new(0x1000, vec![0x01, 0x02, 0x03]),
        Segment::new(0x1001, vec![0xAA]),
        Segment::new(0x2000, vec![0xBB, 0xCC]),
    ]);

    let output = write_binary(&hexfile, &BinaryWriteOptions::default()).unwrap();

    assert_eq!(output, vec![0x01, 0xAA, 0x03, 0xBB, 0xCC]);
}

use super::{ParseError, push_crlf, push_hex_byte};
use crate::{HexFile, Segment};

const RECORD_DATA: u8 = 0x00;
const RECORD_EOF: u8 = 0x01;
const RECORD_EXTENDED_SEGMENT: u8 = 0x02;
const RECORD_EXTENDED_LINEAR: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntelHexMode {
    #[default]
    Auto,
    ExtendedLinear,
    ExtendedSegment,
}

#[derive(Debug, Clone)]
pub struct IntelHexWriteOptions {
    pub bytes_per_line: u8,
    pub mode: IntelHexMode,
}

impl Default for IntelHexWriteOptions {
    fn default() -> Self {
        Self {
            bytes_per_line: 32,
            mode: IntelHexMode::Auto,
        }
    }
}

fn parse_intel_hex_with_address_scale(
    input: &[u8],
    address_scale: u32,
) -> Result<HexFile, ParseError> {
    let text = std::str::from_utf8(input).map_err(|e| ParseError::InvalidRecord {
        line: 1,
        message: format!("invalid UTF-8: {e}"),
    })?;

    let mut segments: Vec<Segment> = Vec::new();
    let mut current_segment: Option<Segment> = None;
    let mut extended_address: u32 = 0;
    let mut eof_seen = false;

    for (line_num, line) in text.lines().enumerate() {
        let line_num = line_num + 1;
        let line = line.trim();

        if line.is_empty() {
            continue;
        }

        if eof_seen {
            return Err(ParseError::InvalidRecord {
                line: line_num,
                message: "data after EOF record".to_owned(),
            });
        }

        if !line.starts_with(':') {
            return Err(ParseError::InvalidRecord {
                line: line_num,
                message: "line does not start with ':'".to_owned(),
            });
        }

        let hex_str = &line[1..];
        if hex_str.len() < 10 {
            return Err(ParseError::InvalidRecord {
                line: line_num,
                message: "record too short".to_owned(),
            });
        }

        let bytes = super::parse_hex_bytes(hex_str.as_bytes(), line_num)?;
        validate_checksum(&bytes, line_num)?;

        let byte_count = bytes[0] as usize;

        if bytes.len() < 5 + byte_count {
            return Err(ParseError::InvalidRecord {
                line: line_num,
                message: format!(
                    "byte count too large: header says {}, but record only has {} data bytes",
                    byte_count,
                    bytes.len().saturating_sub(5),
                ),
            });
        }

        if bytes.len() != 5 + byte_count {
            return Err(ParseError::InvalidRecord {
                line: line_num,
                message: format!(
                    "byte count mismatch: header says {}, got {}",
                    byte_count,
                    bytes.len() - 5
                ),
            });
        }

        let address = u16::from_be_bytes([bytes[1], bytes[2]]);
        let record_type = bytes[3];
        let data = &bytes[4..4 + byte_count];

        match record_type {
            RECORD_DATA => {
                let full_address = extended_address
                    .checked_add(address as u32)
                    .ok_or_else(|| ParseError::AddressOverflow(format!("line {line_num}")))?
                    .checked_mul(address_scale)
                    .ok_or_else(|| ParseError::AddressOverflow(format!("line {line_num}")))?;

                if byte_count > 0 {
                    full_address
                        .checked_add(byte_count as u32 - 1)
                        .ok_or_else(|| ParseError::AddressOverflow(format!("line {line_num}")))?;
                }

                match &mut current_segment {
                    Some(seg) if seg.end_address().checked_add(1) == Some(full_address) => {
                        seg.data.extend_from_slice(data);
                    }
                    Some(seg) => {
                        let next = Segment::try_new(full_address, data.to_vec()).map_err(|e| {
                            ParseError::AddressOverflow(format!("line {line_num}: {e}"))
                        })?;
                        segments.push(std::mem::replace(seg, next));
                    }
                    None => {
                        current_segment =
                            Some(Segment::try_new(full_address, data.to_vec()).map_err(|e| {
                                ParseError::AddressOverflow(format!("line {line_num}: {e}"))
                            })?);
                    }
                }
            }
            RECORD_EOF => {
                eof_seen = true;
            }
            RECORD_EXTENDED_SEGMENT => {
                if byte_count != 2 {
                    return Err(ParseError::InvalidRecord {
                        line: line_num,
                        message: "extended segment address must have 2 data bytes".to_owned(),
                    });
                }
                if let Some(seg) = current_segment.take() {
                    segments.push(seg);
                }
                let base = u16::from_be_bytes([data[0], data[1]]);
                extended_address = (base as u32) << 4;
            }
            RECORD_EXTENDED_LINEAR => {
                if byte_count != 2 {
                    return Err(ParseError::InvalidRecord {
                        line: line_num,
                        message: "extended linear address must have 2 data bytes".to_owned(),
                    });
                }
                if let Some(seg) = current_segment.take() {
                    segments.push(seg);
                }
                let base = u16::from_be_bytes([data[0], data[1]]);
                extended_address = (base as u32) << 16;
            }
            0x03 | 0x05 => {}
            _ => {
                return Err(ParseError::UnsupportedRecordType {
                    line: line_num,
                    record_type,
                });
            }
        }
    }

    if !eof_seen {
        return Err(ParseError::UnexpectedEof);
    }

    if let Some(seg) = current_segment {
        segments.push(seg);
    }

    Ok(HexFile::with_segments(segments))
}

/// Parse Intel-HEX input. CLI: auto-detect Intel-HEX input.
pub fn parse_intel_hex(input: &[u8]) -> Result<HexFile, ParseError> {
    parse_intel_hex_with_address_scale(input, 1)
}

/// Parse Intel-HEX with 16-bit addressing (address * 2). CLI: /II2.
pub fn parse_intel_hex_16bit(input: &[u8]) -> Result<HexFile, ParseError> {
    parse_intel_hex_with_address_scale(input, 2)
}

/// Write Intel-HEX output. CLI: /XI.
pub fn write_intel_hex(hexfile: &HexFile, options: &IntelHexWriteOptions) -> Vec<u8> {
    let segments = hexfile.normalized().into_segments();
    let mut output = Vec::new();
    let bytes_per_line = if options.bytes_per_line == 0 {
        16
    } else {
        options.bytes_per_line
    } as usize;
    let auto_mode = matches!(options.mode, IntelHexMode::Auto);
    let max_addr = segments.iter().map(|s| s.end_address()).max();
    let auto_force_linear = auto_mode && matches!(max_addr, Some(max) if max > 0xFFFFF);
    let fixed_mode = if auto_mode { None } else { Some(options.mode) };

    let mut current_extended: Option<u16> = None;
    let mut current_mode: Option<IntelHexMode> = fixed_mode;

    let total_bytes: usize = segments.iter().map(|s| s.len()).sum();
    let total_records: usize = if bytes_per_line == 0 {
        0
    } else {
        segments
            .iter()
            .map(|s| s.len().div_ceil(bytes_per_line))
            .sum()
    };
    // Rough reserve: 2 hex chars per byte + per-record overhead.
    output.reserve(total_bytes.saturating_mul(2) + total_records.saturating_mul(12) + 64);

    for segment in segments {
        let mut addr = segment.start_address;
        let mut data_offset = 0;
        let seg_start = segment.start_address;

        while data_offset < segment.len() {
            let line_mode = if let Some(mode) = fixed_mode {
                mode
            } else if auto_force_linear || addr > 0xFFFFF {
                IntelHexMode::ExtendedLinear
            } else {
                IntelHexMode::ExtendedSegment
            };
            let needed_extended = match line_mode {
                IntelHexMode::ExtendedLinear => (addr >> 16) as u16,
                IntelHexMode::ExtendedSegment => ((addr >> 4) & 0xF000) as u16,
                IntelHexMode::Auto => unreachable!(),
            };

            let mut should_emit =
                current_extended != Some(needed_extended) || current_mode != Some(line_mode);
            if auto_mode {
                if line_mode == IntelHexMode::ExtendedSegment {
                    if addr <= 0xFFFF {
                        if current_mode.is_none() && current_extended.is_none() {
                            should_emit = false;
                        }
                    } else {
                        let upper = (addr >> 16) as u16;
                        let needed_segment = upper << 12;
                        if needed_extended != needed_segment {
                            current_extended = Some(needed_segment);
                        }
                    }
                }
                if auto_force_linear
                    && line_mode == IntelHexMode::ExtendedLinear
                    && needed_extended == 0
                    && current_mode.is_none()
                    && current_extended.is_none()
                {
                    should_emit = false;
                }
            }

            if should_emit {
                current_extended = Some(needed_extended);
                current_mode = Some(line_mode);
                let record_type = match line_mode {
                    IntelHexMode::ExtendedLinear => RECORD_EXTENDED_LINEAR,
                    IntelHexMode::ExtendedSegment => RECORD_EXTENDED_SEGMENT,
                    IntelHexMode::Auto => unreachable!(),
                };
                write_record(&mut output, record_type, 0, &needed_extended.to_be_bytes());
            }

            let offset_addr = (addr & 0xFFFF) as u16;

            let remaining_in_bank = 0x10000u32.saturating_sub(offset_addr as u32) as usize;
            let remaining_data = segment.len() - data_offset;
            let offset_from_start = addr.saturating_sub(seg_start);
            let line_offset = (offset_from_start % bytes_per_line as u32) as usize;
            let line_remaining = bytes_per_line - line_offset;
            let chunk_len = line_remaining.min(remaining_in_bank).min(remaining_data);

            let chunk = &segment.data[data_offset..data_offset + chunk_len];
            write_record(&mut output, RECORD_DATA, offset_addr, chunk);

            data_offset += chunk_len;
            addr = addr.wrapping_add(chunk_len as u32);
        }
    }

    write_record(&mut output, RECORD_EOF, 0, &[]);
    output
}

fn write_record(output: &mut Vec<u8>, record_type: u8, address: u16, data: &[u8]) {
    let byte_count = data.len() as u8;
    let addr_bytes = address.to_be_bytes();

    let mut checksum: u8 = 0;
    checksum = checksum.wrapping_add(byte_count);
    checksum = checksum.wrapping_add(addr_bytes[0]);
    checksum = checksum.wrapping_add(addr_bytes[1]);
    checksum = checksum.wrapping_add(record_type);
    for &b in data {
        checksum = checksum.wrapping_add(b);
    }
    checksum = (!checksum).wrapping_add(1);

    output.push(b':');
    push_hex_byte(output, byte_count);
    push_hex_byte(output, addr_bytes[0]);
    push_hex_byte(output, addr_bytes[1]);
    push_hex_byte(output, record_type);
    for &b in data {
        push_hex_byte(output, b);
    }
    push_hex_byte(output, checksum);
    push_crlf(output);
}

fn validate_checksum(bytes: &[u8], line_num: usize) -> Result<(), ParseError> {
    let sum: u8 = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    if sum != 0 {
        let Some((&actual, payload)) = bytes.split_last() else {
            return Err(ParseError::InvalidRecord {
                line: line_num,
                message: "record too short".to_owned(),
            });
        };
        let expected = (!payload.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))).wrapping_add(1);
        return Err(ParseError::ChecksumMismatch {
            line: line_num,
            expected,
            actual,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple() {
        let input = b":10010000214601360121470136007EFE09D2190140\n\
                      :100110002146017E17C20001FF5F16002148011928\n\
                      :00000001FF\n";
        let hf = parse_intel_hex(input).unwrap();
        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x0100);
        assert_eq!(hf.segments()[0].len(), 32);
    }

    #[test]
    fn test_parse_extended_linear() {
        let input = b":020000040800F2\n\
                      :10000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00\n\
                      :00000001FF\n";
        let hf = parse_intel_hex(input).unwrap();
        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x08000000);
    }

    #[test]
    fn test_parse_extended_segment() {
        let input = b":020000021000EC\n\
                      :10000000FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00\n\
                      :00000001FF\n";
        let hf = parse_intel_hex(input).unwrap();
        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x00010000);
    }

    #[test]
    fn test_parse_16bit_addresses_scaled() {
        let input = b":02000100AABB98\n:00000001FF\n";
        let hf = parse_intel_hex_16bit(input).unwrap();
        assert_eq!(hf.segments().len(), 1);
        assert_eq!(hf.segments()[0].start_address, 0x0002);
        assert_eq!(hf.segments()[0].data, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_parse_16bit_scales_before_merging_adjacent_records() {
        let input = b":04D0C00082B77EF8BD\n\
                      :20D0C40080D874F080DC774080C874E080C674D080C474C000007E2080CA74C000F47AC095\n\
                      :00000001FF\n";
        let hf = parse_intel_hex_16bit(input).unwrap();
        assert_eq!(hf.segments().len(), 2);
        assert_eq!(hf.segments()[0].start_address, 0x1A180);
        assert_eq!(hf.segments()[0].data, vec![0x82, 0xB7, 0x7E, 0xF8]);
        assert_eq!(hf.segments()[1].start_address, 0x1A188);
        assert_eq!(
            hf.segments()[1].data,
            vec![
                0x80, 0xD8, 0x74, 0xF0, 0x80, 0xDC, 0x77, 0x40, 0x80, 0xC8, 0x74, 0xE0, 0x80, 0xC6,
                0x74, 0xD0, 0x80, 0xC4, 0x74, 0xC0, 0x00, 0x00, 0x7E, 0x20, 0x80, 0xCA, 0x74, 0xC0,
                0x00, 0xF4, 0x7A, 0xC0,
            ]
        );
    }

    #[test]
    fn test_parse_16bit_overflow() {
        let input = b":0200000480007A\n:01000000AA55\n:00000001FF\n";
        let result = parse_intel_hex_16bit(input);
        assert!(matches!(result, Err(ParseError::AddressOverflow(_))));
    }

    #[test]
    fn test_parse_record_crossing_u32_max_errors() {
        let mut input = Vec::new();
        write_record(
            &mut input,
            RECORD_EXTENDED_LINEAR,
            0,
            &0xFFFFu16.to_be_bytes(),
        );
        write_record(&mut input, RECORD_DATA, 0xFFFF, &[0xAA, 0xBB]);
        write_record(&mut input, RECORD_EOF, 0, &[]);

        let result = parse_intel_hex(&input);
        assert!(matches!(result, Err(ParseError::AddressOverflow(_))));
    }

    #[test]
    fn test_checksum_error() {
        let input = b":10010000214601360121470136007EFE09D2190141\n\
                      :00000001FF\n";
        let result = parse_intel_hex(input);
        assert!(matches!(result, Err(ParseError::ChecksumMismatch { .. })));
    }

    #[test]
    fn test_missing_eof() {
        let input = b":10010000214601360121470136007EFE09D2190140\n";
        let result = parse_intel_hex(input);
        assert!(matches!(result, Err(ParseError::UnexpectedEof)));
    }

    #[test]
    fn test_roundtrip() {
        let input = b":020000040800F2\n\
                      :10000000000102030405060708090A0B0C0D0E0F78\n\
                      :10001000101112131415161718191A1B1C1D1E1F68\n\
                      :00000001FF\n";
        let hf = parse_intel_hex(input).unwrap();
        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default());
        let hf2 = parse_intel_hex(&output).unwrap();
        assert_eq!(hf, hf2);
    }

    #[test]
    fn test_write_simple() {
        let hf = HexFile::with_segments(vec![Segment::new(0x0100, vec![0x00, 0x01, 0x02, 0x03])]);
        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default());
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(":0401000000010203F5"));
        assert!(text.contains(":00000001FF"));
    }

    #[test]
    fn test_write_roundtrip_at_u32_max_boundary() {
        let hf = HexFile::with_segments(vec![Segment::new(
            u32::MAX - 3,
            vec![0xFC, 0xFD, 0xFE, 0xFF],
        )]);

        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default());
        let parsed = parse_intel_hex(&output).unwrap();

        assert_eq!(parsed.normalized(), hf.normalized());
    }

    #[test]
    fn test_write_auto_mixed_modes() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x12000, vec![0xAA]),
            Segment::new(0x120000, vec![0xBB]),
        ]);
        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default());
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains(":02000002")); // extended segment suppressed when > 0xFFFFF
        assert!(text.contains(":02000004")); // extended linear only
    }

    #[test]
    fn test_write_extended_segment_first_line_respects_bytes_per_line() {
        let data: Vec<u8> = (0u8..64u8).collect();
        let hf = HexFile::with_segments(vec![Segment::new(0x10000, data)]);
        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default());
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let ext_idx = lines
            .iter()
            .position(|line| line.starts_with(":02000002"))
            .expect("missing extended segment record");
        let first_data = lines[ext_idx + 1];
        let second_data = lines[ext_idx + 2];
        assert!(first_data.starts_with(":20"));
        assert!(second_data.starts_with(":20"));
    }

    #[test]
    fn test_write_extended_segment_boundary_alignment() {
        let data: Vec<u8> = (0u8..0x30u8).collect();
        let hf = HexFile::with_segments(vec![Segment::new(0xFFF0, data)]);
        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default());
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        let ext_idx = lines
            .iter()
            .position(|line| line.starts_with(":020000021000EC"))
            .expect("missing extended segment record");
        let first_data = lines[ext_idx + 1];
        assert!(first_data.starts_with(":10"));
    }
}

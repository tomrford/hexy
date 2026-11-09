use super::{ParseError, SegmentBuilder, WriteError, push_crlf, push_hex_byte};
use crate::{HexFile, Segment};

const RECORD_DATA: u8 = 0x00;
const RECORD_EOF: u8 = 0x01;
const RECORD_EXTENDED_SEGMENT: u8 = 0x02;
const RECORD_EXTENDED_LINEAR: u8 = 0x04;

pub const DEFAULT_INTEL_HEX_BYTES_PER_LINE: u8 = 32;

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
            bytes_per_line: DEFAULT_INTEL_HEX_BYTES_PER_LINE,
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

    let mut builder = SegmentBuilder::default();
    let mut extended_address: u32 = 0;
    let mut eof_seen = false;
    let mut record_seen = false;

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
            if !record_seen && !looks_like_malformed_intel_hex_record(line) {
                continue;
            }
            return Err(ParseError::InvalidRecord {
                line: line_num,
                message: "line does not start with ':'".to_owned(),
            });
        }
        record_seen = true;

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
                    .checked_add(u32::from(address))
                    .and_then(|addr| addr.checked_mul(address_scale))
                    .ok_or(ParseError::AddressOverflow { line: line_num })?;
                builder.push(full_address, data, line_num)?;
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
                builder.close();
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
                builder.close();
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

    Ok(builder.finish())
}

fn looks_like_malformed_intel_hex_record(line: &str) -> bool {
    let bytes = line.as_bytes();
    bytes.len() >= 10
        && bytes.len().is_multiple_of(2)
        && bytes.iter().all(|byte| byte.is_ascii_hexdigit())
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
///
/// Records follow the blocks ([`HexFile::blocks`]), so adjacent blocks start new
/// records, as HexView writes them. One extended address record type is used for the
/// whole file: the forced mode, or in auto mode segment records up to 1 MiB and linear
/// records above. An extended address
/// record is written only where the upper address differs from the previous one, which
/// starts at zero.
pub fn write_intel_hex(
    hexfile: &HexFile,
    options: &IntelHexWriteOptions,
) -> Result<Vec<u8>, WriteError> {
    let segments = hexfile.blocks();
    let bytes_per_line = match options.bytes_per_line {
        0 => DEFAULT_INTEL_HEX_BYTES_PER_LINE,
        n => n,
    } as usize;
    let max_addr = segments.iter().map(Segment::end_address).max();
    let record_type = match options.mode {
        IntelHexMode::ExtendedLinear => RECORD_EXTENDED_LINEAR,
        IntelHexMode::ExtendedSegment => RECORD_EXTENDED_SEGMENT,
        IntelHexMode::Auto if max_addr.is_some_and(|max| max > 0xFFFFF) => RECORD_EXTENDED_LINEAR,
        IntelHexMode::Auto => RECORD_EXTENDED_SEGMENT,
    };
    if record_type == RECORD_EXTENDED_SEGMENT
        && let Some(address) = max_addr.filter(|&max| max > 0xFFFFF)
    {
        return Err(WriteError::AddressNotEncodable {
            address,
            format: "Intel HEX extended segment address",
        });
    }

    let total_bytes: usize = segments.iter().map(Segment::len).sum();
    let mut output = Vec::with_capacity(total_bytes * 2 + total_bytes / bytes_per_line * 14 + 64);
    let mut current_extended = 0u16;
    for segment in segments {
        let mut data_offset = 0;
        while data_offset < segment.len() {
            let addr = segment.start_address + data_offset as u32;
            let needed_extended = if record_type == RECORD_EXTENDED_LINEAR {
                (addr >> 16) as u16
            } else {
                ((addr >> 4) & 0xF000) as u16
            };
            if needed_extended != current_extended {
                current_extended = needed_extended;
                write_record(&mut output, record_type, 0, &needed_extended.to_be_bytes());
            }

            let offset_addr = (addr & 0xFFFF) as u16;
            let remaining_in_bank = 0x10000 - offset_addr as usize;
            let line_remaining = bytes_per_line - data_offset % bytes_per_line;
            let chunk_len = line_remaining
                .min(remaining_in_bank)
                .min(segment.len() - data_offset);
            let chunk = &segment.data[data_offset..data_offset + chunk_len];
            write_record(&mut output, RECORD_DATA, offset_addr, chunk);
            data_offset += chunk_len;
        }
    }

    write_record(&mut output, RECORD_EOF, 0, &[]);
    Ok(output)
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
        assert!(matches!(result, Err(ParseError::AddressOverflow { .. })));
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
        assert!(matches!(result, Err(ParseError::AddressOverflow { .. })));
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
        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default()).unwrap();
        let hf2 = parse_intel_hex(&output).unwrap();
        assert_eq!(hf, hf2);
    }

    #[test]
    fn test_write_simple() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x0100, vec![0x00, 0x01, 0x02, 0x03]).unwrap(),
        ]);
        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default()).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains(":0401000000010203F5"));
        assert!(text.contains(":00000001FF"));
    }

    #[test]
    fn test_write_roundtrip_at_u32_max_boundary() {
        let hf = HexFile::with_segments(vec![
            Segment::new(u32::MAX - 3, vec![0xFC, 0xFD, 0xFE, 0xFF]).unwrap(),
        ]);

        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default()).unwrap();
        let parsed = parse_intel_hex(&output).unwrap();

        assert_eq!(parsed.normalized(), hf.normalized());
    }

    #[test]
    fn test_write_auto_mixed_modes() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0x12000, vec![0xAA]).unwrap(),
            Segment::new(0x120000, vec![0xBB]).unwrap(),
        ]);
        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default()).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains(":02000002")); // extended segment suppressed when > 0xFFFFF
        assert!(text.contains(":02000004")); // extended linear only
    }

    #[test]
    fn test_write_forced_extended_segment_rejects_high_address() {
        let hf = HexFile::with_segments(vec![Segment::new(0x100000, vec![0xAA]).unwrap()]);
        let result = write_intel_hex(
            &hf,
            &IntelHexWriteOptions {
                bytes_per_line: 16,
                mode: IntelHexMode::ExtendedSegment,
            },
        );

        assert!(matches!(
            result,
            Err(WriteError::AddressNotEncodable { .. })
        ));
    }

    #[test]
    fn test_write_extended_segment_first_line_respects_bytes_per_line() {
        let data: Vec<u8> = (0u8..64u8).collect();
        let hf = HexFile::with_segments(vec![Segment::new(0x10000, data).unwrap()]);
        let output = write_intel_hex(&hf, &IntelHexWriteOptions::default()).unwrap();
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

    /// HexView 1.15.2 `/XI:16:1` and `/XI:16:2`: no extended address record until the
    /// upper address leaves zero.
    #[test]
    fn test_write_forced_modes_start_at_upper_zero() {
        let hf = HexFile::with_segments(vec![
            Segment::new(0xFFF0, (0..0x20u8).map(|i| 1 + i * 7).collect()).unwrap(),
        ]);
        let write = |mode| {
            let options = IntelHexWriteOptions {
                bytes_per_line: 16,
                mode,
            };
            String::from_utf8(write_intel_hex(&hf, &options).unwrap()).unwrap()
        };
        let first = ":10FFF00001080F161D242B323940474E555C636AA9\r\n";
        let second = ":1000000071787F868D949BA2A9B0B7BEC5CCD3DA98\r\n:00000001FF\r\n";
        assert_eq!(
            write(IntelHexMode::ExtendedLinear),
            format!("{first}:020000040001F9\r\n{second}")
        );
        assert_eq!(
            write(IntelHexMode::ExtendedSegment),
            format!("{first}:020000021000EC\r\n{second}")
        );
    }
}

use super::{ParseError, SegmentBuilder, WriteError, push_crlf, push_hex_byte};
use crate::HexFile;

pub const DEFAULT_SREC_BYTES_PER_LINE: u8 = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SRecordType {
    S1,
    S2,
    S3,
}

impl SRecordType {
    fn address_len(self) -> usize {
        match self {
            Self::S1 => 2,
            Self::S2 => 3,
            Self::S3 => 4,
        }
    }

    fn max_address(self) -> u32 {
        match self {
            Self::S1 => 0xFFFF,
            Self::S2 => 0xFF_FFFF,
            Self::S3 => u32::MAX,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SRecordWriteOptions {
    pub bytes_per_line: u8,
    pub record_type: Option<SRecordType>,
}

impl Default for SRecordWriteOptions {
    fn default() -> Self {
        Self {
            bytes_per_line: DEFAULT_SREC_BYTES_PER_LINE,
            record_type: None,
        }
    }
}

/// Parse Motorola S-Record input. CLI: auto-detect S-Record input.
pub fn parse_srec(data: &[u8]) -> Result<HexFile, ParseError> {
    let mut builder = SegmentBuilder::default();

    for (idx, raw_line) in data.split(|&b| b == b'\n').enumerate() {
        let line_no = idx + 1;
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.is_empty() {
            continue;
        }
        if (line[0] != b'S' && line[0] != b's') || line.len() < 2 {
            return Err(ParseError::InvalidRecord {
                line: line_no,
                message: "missing S-record prefix".to_owned(),
            });
        }

        let record_type = line[1];
        let record_bytes = super::parse_hex_bytes(&line[2..], line_no)?;
        let Some((&count, _)) = record_bytes.split_first() else {
            return Err(ParseError::InvalidRecord {
                line: line_no,
                message: "missing record length".to_owned(),
            });
        };
        let count = count as usize;
        if record_bytes.len() != count + 1 {
            return Err(ParseError::InvalidRecord {
                line: line_no,
                message: format!(
                    "byte count mismatch: expected {}, got {}",
                    count + 1,
                    record_bytes.len()
                ),
            });
        }

        let (&actual, payload) = record_bytes.split_last().ok_or(ParseError::UnexpectedEof)?;
        let expected = checksum(payload);
        if actual != expected {
            return Err(ParseError::ChecksumMismatch {
                line: line_no,
                expected,
                actual,
            });
        }

        let addr_len = match record_type {
            b'0' | b'5' | b'7' | b'8' | b'9' => continue,
            b'1' => 2,
            b'2' => 3,
            b'3' => 4,
            other => {
                return Err(ParseError::UnsupportedRecordType {
                    line: line_no,
                    record_type: other,
                });
            }
        };
        if count < addr_len + 1 {
            return Err(ParseError::InvalidRecord {
                line: line_no,
                message: "record length too short".to_owned(),
            });
        }
        let (addr_bytes, data) = payload[1..].split_at(addr_len);
        let addr = addr_bytes
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
        builder.push(addr, data, line_no)?;
    }

    Ok(builder.finish())
}

/// Write Motorola S-Record output, starting new records at each block
/// ([`HexFile::blocks`]) as HexView does. CLI: /XS.
pub fn write_srec(hexfile: &HexFile, options: &SRecordWriteOptions) -> Result<Vec<u8>, WriteError> {
    let blocks = hexfile.blocks();
    let max_addr = blocks
        .iter()
        .map(|block| block.end_address())
        .max()
        .unwrap_or(0);

    let record_type = match options.record_type {
        Some(t) if max_addr > t.max_address() => {
            return Err(WriteError::AddressNotEncodable {
                address: max_addr,
                format: match t {
                    SRecordType::S1 => "S1 record",
                    SRecordType::S2 => "S2 record",
                    SRecordType::S3 => "S3 record",
                },
            });
        }
        Some(t) => t,
        None if max_addr <= SRecordType::S1.max_address() => SRecordType::S1,
        None if max_addr <= SRecordType::S2.max_address() => SRecordType::S2,
        None => SRecordType::S3,
    };
    let (data_digit, term_digit) = match record_type {
        SRecordType::S1 => (b'1', b'9'),
        SRecordType::S2 => (b'2', b'8'),
        SRecordType::S3 => (b'3', b'7'),
    };
    let addr_len = record_type.address_len();
    let bytes_per_line = match options.bytes_per_line {
        0 => DEFAULT_SREC_BYTES_PER_LINE,
        n => n,
    } as usize;

    let mut out = Vec::new();
    for segment in &blocks {
        let mut addr = segment.start_address;
        for chunk in segment.data.chunks(bytes_per_line) {
            push_record(&mut out, data_digit, addr, addr_len, chunk);
            addr = addr.wrapping_add(chunk.len() as u32);
        }
    }
    push_record(&mut out, term_digit, 0, addr_len, &[]);
    Ok(out)
}

/// Ones' complement of the byte sum, the S-record checksum.
fn checksum(bytes: &[u8]) -> u8 {
    !bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b))
}

fn push_record(out: &mut Vec<u8>, digit: u8, addr: u32, addr_len: usize, data: &[u8]) {
    let mut record = Vec::with_capacity(1 + addr_len + data.len());
    record.push((addr_len + data.len() + 1) as u8);
    record.extend_from_slice(&addr.to_be_bytes()[4 - addr_len..]);
    record.extend_from_slice(data);
    out.push(b'S');
    out.push(digit);
    for &byte in &record {
        push_hex_byte(out, byte);
    }
    push_hex_byte(out, checksum(&record));
    push_crlf(out);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    #[test]
    fn test_srec_roundtrip_s1() {
        let hexfile =
            HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02, 0x03]).unwrap()]);
        let options = SRecordWriteOptions {
            bytes_per_line: 2,
            record_type: Some(SRecordType::S1),
        };
        let out = write_srec(&hexfile, &options).unwrap();
        assert_eq!(out, b"S10510000102E7\r\nS104100203E6\r\nS9030000FC\r\n");
        assert_eq!(parse_srec(&out).unwrap(), hexfile);
    }

    #[test]
    fn test_parse_coalesces_contiguous_records() {
        let parsed = parse_srec(b"S10510000102E7\r\nS104100203E6\r\nS1041004AA3D\r\n").unwrap();
        assert_eq!(
            parsed.segments(),
            &[
                Segment::new(0x1000, vec![0x01, 0x02, 0x03]).unwrap(),
                Segment::new(0x1004, vec![0xAA]).unwrap()
            ]
        );
    }

    #[test]
    fn test_srec_bad_checksum() {
        let line = b"S10510000102E8\n";
        assert!(matches!(
            parse_srec(line),
            Err(ParseError::ChecksumMismatch { line: 1, .. })
        ));
    }

    #[test]
    fn test_srec_auto_type_and_forced_type_limit() {
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1_0000, vec![0x01]).unwrap()]);
        let out = write_srec(&hexfile, &SRecordWriteOptions::default()).unwrap();
        assert!(out.starts_with(b"S2"));
        let forced = SRecordWriteOptions {
            record_type: Some(SRecordType::S1),
            ..Default::default()
        };
        assert!(matches!(
            write_srec(&hexfile, &forced),
            Err(WriteError::AddressNotEncodable {
                address: 0x1_0000,
                ..
            })
        ));
    }

    #[test]
    fn test_srec_roundtrip_at_u32_max_boundary() {
        let hexfile = HexFile::with_segments(vec![
            Segment::new(u32::MAX - 3, vec![0xFC, 0xFD, 0xFE, 0xFF]).unwrap(),
        ]);
        let out = write_srec(&hexfile, &SRecordWriteOptions::default()).unwrap();
        assert_eq!(parse_srec(&out).unwrap(), hexfile);
    }

    #[test]
    fn test_parse_record_crossing_u32_max_errors() {
        let mut data = Vec::new();
        push_record(&mut data, b'3', u32::MAX, 4, &[0xAA, 0xBB]);
        push_record(&mut data, b'7', 0, 4, &[]);
        assert!(matches!(
            parse_srec(&data),
            Err(ParseError::AddressOverflow { line: 1 })
        ));
    }

    #[test]
    fn test_parse_lowercase_prefix() {
        let parsed = parse_srec(b"s10500000102f7\ns9030000fc\n").unwrap();
        assert_eq!(
            parsed.segments(),
            &[Segment::new(0x0000, vec![0x01, 0x02]).unwrap()]
        );
    }
}

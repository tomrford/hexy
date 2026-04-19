use crate::io::{ParseError, push_crlf, push_hex_byte};
use crate::{HexFile, Segment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SRecordType {
    S1,
    S2,
    S3,
}

#[derive(Debug, Clone)]
pub struct SRecordWriteOptions {
    pub bytes_per_line: u8,
    pub record_type: Option<SRecordType>,
}

impl Default for SRecordWriteOptions {
    fn default() -> Self {
        Self {
            bytes_per_line: 16,
            record_type: None,
        }
    }
}

/// Parse Motorola S-Record input. CLI: auto-detect S-Record input.
pub fn parse_srec(data: &[u8]) -> Result<HexFile, ParseError> {
    let mut hexfile = HexFile::new();

    for (idx, raw_line) in data.split(|&b| b == b'\n').enumerate() {
        let line_no = idx + 1;
        let mut line = raw_line;
        if let Some(b'\r') = line.last() {
            line = &line[..line.len().saturating_sub(1)];
        }
        if line.is_empty() {
            continue;
        }
        if (line[0] != b'S' && line[0] != b's') || line.len() < 2 {
            return Err(ParseError::InvalidRecord {
                line: line_no,
                message: "missing S-record prefix".to_owned(),
            });
        }

        let record_type = line[1] as char;
        let record_bytes = super::parse_hex_bytes(&line[2..], line_no)?;
        if record_bytes.is_empty() {
            return Err(ParseError::InvalidRecord {
                line: line_no,
                message: "missing record length".to_owned(),
            });
        }

        let count = record_bytes[0] as usize;
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

        if !checksum_valid(&record_bytes) {
            let expected = expected_checksum(&record_bytes[..record_bytes.len() - 1]);
            let actual = *record_bytes.last().unwrap_or(&0);
            return Err(ParseError::ChecksumMismatch {
                line: line_no,
                expected,
                actual,
            });
        }

        match record_type {
            '0' | '5' | '7' | '8' | '9' => continue,
            '1' | '2' | '3' => {
                let addr_len = match record_type {
                    '1' => 2,
                    '2' => 3,
                    '3' => 4,
                    _ => 0,
                };
                let data_len =
                    count
                        .checked_sub(addr_len + 1)
                        .ok_or(ParseError::InvalidRecord {
                            line: line_no,
                            message: "record length too short".to_owned(),
                        })?;
                let addr_end = 1 + addr_len;
                let data_start = addr_end;
                let data_end = data_start + data_len;

                if data_end > record_bytes.len().saturating_sub(1) {
                    return Err(ParseError::InvalidRecord {
                        line: line_no,
                        message: "data length mismatch".to_owned(),
                    });
                }

                let addr = parse_address(&record_bytes[1..addr_end]);
                if data_len > 0 {
                    let data = record_bytes[data_start..data_end].to_vec();
                    let end = addr.checked_add(data.len() as u32 - 1).ok_or_else(|| {
                        ParseError::AddressOverflow(format!(
                            "{:#X} + {} exceeds u32",
                            addr,
                            data.len()
                        ))
                    })?;
                    if end < addr {
                        return Err(ParseError::AddressOverflow(format!(
                            "{:#X} + {} exceeds u32",
                            addr,
                            data.len()
                        )));
                    }
                    hexfile.append_segment(Segment::new(addr, data));
                }
            }
            other => {
                return Err(ParseError::UnsupportedRecordType {
                    line: line_no,
                    record_type: other as u8,
                });
            }
        }
    }

    Ok(hexfile)
}

/// Write Motorola S-Record output. CLI: /XS.
pub fn write_srec(hexfile: &HexFile, options: &SRecordWriteOptions) -> Result<Vec<u8>, ParseError> {
    let normalized = hexfile.normalized();
    let max_addr = normalized.max_address().unwrap_or(0);

    let auto_type = if max_addr <= 0xFFFF {
        SRecordType::S1
    } else if max_addr <= 0xFF_FFFF {
        SRecordType::S2
    } else {
        SRecordType::S3
    };

    let record_type = match options.record_type {
        Some(t) => {
            let max_allowed = max_address_for(t);
            if max_addr > max_allowed {
                return Err(ParseError::AddressOverflow(format!(
                    "max address {:#X} exceeds {:?} limit {:#X}",
                    max_addr, t, max_allowed
                )));
            }
            t
        }
        None => auto_type,
    };

    let bytes_per_line = if options.bytes_per_line == 0 {
        16
    } else {
        options.bytes_per_line
    } as usize;

    let segments = normalized.into_segments();

    let mut out = Vec::new();
    let (addr_len, record_digit) = match record_type {
        SRecordType::S1 => (2usize, '1'),
        SRecordType::S2 => (3usize, '2'),
        SRecordType::S3 => (4usize, '3'),
    };

    for segment in segments {
        let mut addr = segment.start_address;
        for chunk in segment.data.chunks(bytes_per_line) {
            let addr_bytes = addr.to_be_bytes();
            let addr_slice = &addr_bytes[4 - addr_len..];
            let count = (addr_len + chunk.len() + 1) as u8;
            let mut record = Vec::with_capacity(1 + addr_len + chunk.len() + 1);
            record.push(count);
            record.extend_from_slice(addr_slice);
            record.extend_from_slice(chunk);
            let checksum = expected_checksum(&record);

            push_record_line(&mut out, record_digit, &record, checksum);
            addr = addr
                .checked_add(chunk.len() as u32)
                .ok_or_else(|| ParseError::AddressOverflow("address overflow".to_owned()))?;
        }
    }

    let term_digit = match record_type {
        SRecordType::S1 => '9',
        SRecordType::S2 => '8',
        SRecordType::S3 => '7',
    };
    let addr_bytes = [0u8; 4];
    let addr_slice = &addr_bytes[4 - addr_len..];
    let count = (addr_len + 1) as u8;
    let mut term = Vec::with_capacity(1 + addr_len);
    term.push(count);
    term.extend_from_slice(addr_slice);
    let checksum = expected_checksum(&term);
    push_record_line(&mut out, term_digit, &term, checksum);

    Ok(out)
}

fn parse_address(bytes: &[u8]) -> u32 {
    bytes.iter().fold(0u32, |acc, &b| (acc << 8) | b as u32)
}

fn checksum_valid(bytes: &[u8]) -> bool {
    let sum = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    sum == 0xFF
}

fn expected_checksum(bytes: &[u8]) -> u8 {
    let sum = bytes.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    0xFFu8.wrapping_sub(sum)
}

fn max_address_for(record_type: SRecordType) -> u32 {
    match record_type {
        SRecordType::S1 => 0xFFFF,
        SRecordType::S2 => 0xFF_FFFF,
        SRecordType::S3 => 0xFFFF_FFFF,
    }
}

fn push_record_line(out: &mut Vec<u8>, record_digit: char, data: &[u8], checksum: u8) {
    out.push(b'S');
    out.push(record_digit as u8);
    for &byte in data {
        push_hex_byte(out, byte);
    }
    push_hex_byte(out, checksum);
    push_crlf(out);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_srec_roundtrip_s1() {
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1000, vec![0x01, 0x02, 0x03])]);
        let options = SRecordWriteOptions {
            bytes_per_line: 16,
            record_type: Some(SRecordType::S1),
        };
        let out = write_srec(&hexfile, &options).unwrap();
        let parsed = parse_srec(&out).unwrap();
        let norm = parsed.normalized();
        assert_eq!(norm.segments().len(), 1);
        assert_eq!(norm.segments()[0].start_address, 0x1000);
        assert_eq!(norm.segments()[0].data, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_srec_bad_checksum() {
        let line = b"S11310000102030405060708090A0B0C0D0E0F00\n";
        let result = parse_srec(line);
        assert!(result.is_err());
    }

    #[test]
    fn test_srec_auto_type_s2() {
        let hexfile = HexFile::with_segments(vec![Segment::new(0x1_0000, vec![0x01])]);
        let out = write_srec(&hexfile, &SRecordWriteOptions::default()).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("S2"));
    }

    #[test]
    fn test_parse_lowercase_prefix() {
        let data = b"s10500000102f7\ns9030000fc\n";
        let parsed = parse_srec(data).unwrap();
        let norm = parsed.normalized();
        assert_eq!(norm.segments()[0].start_address, 0x0000);
        assert_eq!(norm.segments()[0].data, vec![0x01, 0x02]);
    }
}

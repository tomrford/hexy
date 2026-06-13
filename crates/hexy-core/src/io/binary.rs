use crate::io::ParseError;
use crate::{HexFile, Segment};

#[derive(Debug, Clone, Default)]
pub struct BinaryWriteOptions {
    /// If set, fills gaps between min/max addresses with this byte.
    /// If None, segments are concatenated in ascending address order.
    pub fill_gaps: Option<u8>,
}

/// Parse a raw binary blob into a single segment at the given base address.
/// CLI: /IN.
pub fn parse_binary(data: &[u8], base_address: u32) -> Result<HexFile, ParseError> {
    if data.is_empty() {
        return Ok(HexFile::new());
    }

    let len = data.len() as u32;
    let end = base_address
        .checked_add(len.saturating_sub(1))
        .ok_or_else(|| {
            ParseError::AddressOverflow(format!("{:#X} + {} exceeds u32", base_address, len))
        })?;

    if end < base_address {
        return Err(ParseError::AddressOverflow(format!(
            "{:#X} + {} exceeds u32",
            base_address, len
        )));
    }

    Ok(HexFile::with_segments(vec![Segment::new(
        base_address,
        data.to_vec(),
    )]))
}

/// Write the HexFile to a binary blob.
/// CLI: /XN.
pub fn write_binary(hexfile: &HexFile, options: &BinaryWriteOptions) -> Vec<u8> {
    if hexfile.segments().is_empty() {
        return Vec::new();
    }

    if let Some(fill) = options.fill_gaps {
        let mut filled = hexfile.normalized();
        filled.fill_gaps(fill);
        if let Some(segment) = filled.segments().first() {
            return segment.data.clone();
        }
        return Vec::new();
    }

    let normalized = hexfile.normalized();
    let segments = normalized.segments();
    let total_len: usize = segments.iter().map(|s| s.len()).sum();
    let mut out = Vec::with_capacity(total_len);
    for segment in segments {
        out.extend_from_slice(&segment.data);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_binary_base_address() {
        let data = vec![0xAA, 0xBB, 0xCC];
        let hexfile = parse_binary(&data, 0x1000).unwrap();
        assert_eq!(hexfile.segments().len(), 1);
        assert_eq!(hexfile.segments()[0].start_address, 0x1000);
        assert_eq!(hexfile.segments()[0].data, data);
    }

    #[test]
    fn test_parse_binary_overflow() {
        let data = vec![0xAA, 0xBB];
        let result = parse_binary(&data, u32::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_binary_address_order() {
        let hexfile = HexFile::with_segments(vec![
            Segment::new(0x2000, vec![0x01, 0x02]),
            Segment::new(0x1000, vec![0xAA]),
        ]);
        let out = write_binary(&hexfile, &BinaryWriteOptions::default());
        assert_eq!(out, vec![0xAA, 0x01, 0x02]);
    }

    #[test]
    fn test_write_binary_concatenates_normalized_segments_without_gaps() {
        let hexfile = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02, 0x03]),
            Segment::new(0x1001, vec![0xAA]),
            Segment::new(0x2000, vec![0x04]),
        ]);
        let out = write_binary(&hexfile, &BinaryWriteOptions::default());
        assert_eq!(out, vec![0x01, 0xAA, 0x03, 0x04]);
    }

    #[test]
    fn test_write_binary_fill_gaps() {
        let hexfile = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA]),
            Segment::new(0x1002, vec![0xBB]),
        ]);
        let out = write_binary(
            &hexfile,
            &BinaryWriteOptions {
                fill_gaps: Some(0x00),
            },
        );
        assert_eq!(out, vec![0xAA, 0x00, 0xBB]);
    }
}

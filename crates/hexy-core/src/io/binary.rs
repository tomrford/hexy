use crate::io::{ParseError, WriteError};
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
    Ok(HexFile::with_segments(vec![Segment::new(
        base_address,
        data.to_vec(),
    )?]))
}

/// Write the HexFile to a binary blob.
/// CLI: /XN.
pub fn write_binary(
    hexfile: &HexFile,
    options: &BinaryWriteOptions,
) -> Result<Vec<u8>, WriteError> {
    if let Some(fill) = options.fill_gaps {
        let contiguous = hexfile.as_contiguous(fill, u64::MAX)?;
        return Ok(contiguous.map(|segment| segment.data).unwrap_or_default());
    }
    Ok(hexfile
        .normalized()
        .into_segments()
        .into_iter()
        .flat_map(|segment| segment.data)
        .collect())
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
            Segment::new(0x2000, vec![0x01, 0x02]).unwrap(),
            Segment::new(0x1000, vec![0xAA]).unwrap(),
        ]);
        let out = write_binary(&hexfile, &BinaryWriteOptions::default()).unwrap();
        assert_eq!(out, vec![0xAA, 0x01, 0x02]);
    }

    #[test]
    fn test_write_binary_concatenates_normalized_segments_without_gaps() {
        let hexfile = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0x01, 0x02, 0x03]).unwrap(),
            Segment::new(0x1001, vec![0xAA]).unwrap(),
            Segment::new(0x2000, vec![0x04]).unwrap(),
        ]);
        let out = write_binary(&hexfile, &BinaryWriteOptions::default()).unwrap();
        assert_eq!(out, vec![0x01, 0xAA, 0x03, 0x04]);
    }

    #[test]
    fn test_write_binary_fill_gaps() {
        let hexfile = HexFile::with_segments(vec![
            Segment::new(0x1000, vec![0xAA]).unwrap(),
            Segment::new(0x1002, vec![0xBB]).unwrap(),
        ]);
        let out = write_binary(
            &hexfile,
            &BinaryWriteOptions {
                fill_gaps: Some(0x00),
            },
        )
        .unwrap();
        assert_eq!(out, vec![0xAA, 0x00, 0xBB]);
    }
}

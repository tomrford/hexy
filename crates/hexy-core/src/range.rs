use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AddressRangeError {
    #[error("invalid range format: {0}")]
    InvalidFormat(String),

    #[error("invalid number: {0}")]
    InvalidNumber(String),

    #[error("range start ({start:#X}) exceeds end ({end:#X})")]
    StartExceedsEnd { start: u32, end: u32 },

    #[error("zero length range at {start:#X}")]
    ZeroLength { start: u32 },
}

/// A memory address range, specified either as start+length or start-end (inclusive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    start: u32,
    end: u32,           // inclusive, clipped to the u32 address space
    requested_end: u64, // inclusive, preserves overflowing length-form requests
}

impl AddressRange {
    /// Create range from start address and length.
    pub fn from_start_length(start: u32, length: u64) -> Result<Self, AddressRangeError> {
        if length == 0 {
            return Err(AddressRangeError::ZeroLength { start });
        }
        let requested_end = (start as u64)
            .checked_add(length - 1)
            .ok_or_else(|| AddressRangeError::InvalidFormat("address overflow".to_owned()))?;
        let end = requested_end.min(u32::MAX as u64) as u32;
        Ok(Self {
            start,
            end,
            requested_end,
        })
    }

    /// Create range from start and end addresses (inclusive).
    pub fn from_start_end(start: u32, end: u32) -> Result<Self, AddressRangeError> {
        if start > end {
            return Err(AddressRangeError::StartExceedsEnd { start, end });
        }
        Ok(Self {
            start,
            end,
            requested_end: end as u64,
        })
    }

    pub fn start(&self) -> u32 {
        self.start
    }

    pub fn end(&self) -> u32 {
        self.end
    }

    pub fn requested_end(&self) -> u64 {
        self.requested_end
    }

    pub fn length(&self) -> u64 {
        self.requested_end - self.start as u64 + 1
    }

    pub fn addressable_length(&self) -> u64 {
        self.end as u64 - self.start as u64 + 1
    }

    pub fn extends_past_address_space(&self) -> bool {
        self.requested_end > u32::MAX as u64
    }

    pub fn contains(&self, addr: u32) -> bool {
        addr >= self.start && addr <= self.end
    }

    pub fn overlaps(&self, other: &AddressRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Return the intersection of two ranges, if they overlap.
    pub fn intersection(&self, other: &AddressRange) -> Option<AddressRange> {
        if !self.overlaps(other) {
            return None;
        }
        Some(AddressRange {
            start: self.start.max(other.start),
            end: self.end.min(other.end),
            requested_end: self.end.min(other.end) as u64,
        })
    }
}

/// Parse a number from decimal, hex (0x), or binary (0b or trailing b).
fn parse_number(s: &str) -> Result<u64, AddressRangeError> {
    let s = s.trim();
    if s.is_empty() {
        return Err(AddressRangeError::InvalidNumber("empty string".to_owned()));
    }

    let s = s.trim_end_matches(['u', 'U', 'l', 'L']).trim();
    if s.is_empty() {
        return Err(AddressRangeError::InvalidNumber("empty string".to_owned()));
    }
    let (radix, digits) = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        (16, hex)
    } else if let Some(bin) = s.strip_prefix("0b").or_else(|| s.strip_prefix("0B")) {
        (2, bin)
    } else if let Some(bin) = s.strip_suffix('b').or_else(|| s.strip_suffix('B')) {
        (2, bin)
    } else if let Some(hex) = s.strip_suffix('h').or_else(|| s.strip_suffix('H')) {
        (16, hex)
    } else {
        (10, s)
    };

    let cleaned: String = digits.chars().filter(|c| *c != '.' && *c != '_').collect();
    if cleaned.is_empty() {
        return Err(AddressRangeError::InvalidNumber("empty".to_owned()));
    }
    u64::from_str_radix(&cleaned, radix)
        .map_err(|e| AddressRangeError::InvalidNumber(e.to_string()))
}

fn parse_address(s: &str) -> Result<u32, AddressRangeError> {
    let value = parse_number(s)?;
    u32::try_from(value).map_err(|e| AddressRangeError::InvalidNumber(e.to_string()))
}

impl FromStr for AddressRange {
    type Err = AddressRangeError;

    /// Parse range from string.
    /// Formats:
    /// - "start,length" (e.g., "0x1000,0x200")
    /// - "start-end" (e.g., "0x1000-0x11FF")
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some((start_str, len_str)) = s.split_once(',') {
            let start = parse_address(start_str)?;
            let length = parse_number(len_str)?;
            AddressRange::from_start_length(start, length)
        } else if let Some((start_str, end_str)) = s.split_once('-') {
            let start = parse_address(start_str)?;
            let end = parse_address(end_str)?;
            AddressRange::from_start_end(start, end)
        } else {
            Err(AddressRangeError::InvalidFormat(format!(
                "expected 'start,length' or 'start-end', got '{s}'"
            )))
        }
    }
}

/// Merge overlapping or adjacent ranges into a sorted, non-overlapping set.
///
/// Adjacent ranges are coalesced by their addressable endpoints. If any input
/// range came from an overflowing length-form request, the merged range keeps
/// the largest requested end so allocation-producing callers can still reject it.
pub fn merge_ranges(ranges: &[AddressRange]) -> Vec<AddressRange> {
    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|r| r.start());

    let mut merged: Vec<AddressRange> = Vec::new();
    for range in sorted {
        if let Some(last) = merged.last_mut() {
            let adjacent = last
                .end()
                .checked_add(1)
                .map(|v| range.start() <= v)
                .unwrap_or(false);
            if range.start() <= last.end() || adjacent {
                let new_end = last.end().max(range.end());
                let requested_end = last.requested_end().max(range.requested_end());
                *last = AddressRange {
                    start: last.start(),
                    end: new_end,
                    requested_end,
                };
                continue;
            }
        }
        merged.push(range);
    }
    merged
}

/// Parse multiple ranges separated by ':'.
pub fn parse_ranges(s: &str) -> Result<Vec<AddressRange>, AddressRangeError> {
    s.split(':').map(|part| part.parse()).collect()
}

/// Parse multiple ranges, trimming optional surrounding quotes.
pub fn parse_compat_ranges(s: &str) -> Result<Vec<AddressRange>, AddressRangeError> {
    let trimmed = s.trim_matches(|c| c == '"' || c == '\'');
    parse_ranges(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_start_length() {
        let r = AddressRange::from_start_length(0x1000, 0x200).unwrap();
        assert_eq!(r.start(), 0x1000);
        assert_eq!(r.end(), 0x11FF);
        assert_eq!(r.length(), 0x200);
    }

    #[test]
    fn test_from_start_end() {
        let r = AddressRange::from_start_end(0x1000, 0x11FF).unwrap();
        assert_eq!(r.start(), 0x1000);
        assert_eq!(r.end(), 0x11FF);
        assert_eq!(r.length(), 0x200);
    }

    #[test]
    fn test_parse_range_with_dots() {
        let r: AddressRange = "0x10.000-0x10.0FFF".parse().unwrap();
        assert_eq!(r.start(), 0x10000);
        assert_eq!(r.end(), 0x100FFF);
    }

    #[test]
    fn test_parse_range_with_hex_suffix() {
        let r: AddressRange = "1000h-10FFh".parse().unwrap();
        assert_eq!(r.start(), 0x1000);
        assert_eq!(r.end(), 0x10FF);
    }

    #[test]
    fn test_parse_range_with_c_suffixes() {
        let r: AddressRange = "0x1000u-0x10FFUL".parse().unwrap();
        assert_eq!(r.start(), 0x1000);
        assert_eq!(r.end(), 0x10FF);
    }

    #[test]
    fn test_contains() {
        let r = AddressRange::from_start_end(0x1000, 0x1FFF).unwrap();
        assert!(r.contains(0x1000));
        assert!(r.contains(0x1500));
        assert!(r.contains(0x1FFF));
        assert!(!r.contains(0x0FFF));
        assert!(!r.contains(0x2000));
    }

    #[test]
    fn test_overlaps() {
        let r1 = AddressRange::from_start_end(0x1000, 0x1FFF).unwrap();
        let r2 = AddressRange::from_start_end(0x1800, 0x2800).unwrap();
        let r3 = AddressRange::from_start_end(0x2000, 0x3000).unwrap();
        let r4 = AddressRange::from_start_end(0x0500, 0x0FFF).unwrap();

        assert!(r1.overlaps(&r2)); // overlap at 0x1800-0x1FFF
        assert!(!r1.overlaps(&r3)); // adjacent but not overlapping
        assert!(!r1.overlaps(&r4)); // no overlap
    }

    #[test]
    fn test_intersection() {
        let r1 = AddressRange::from_start_end(0x1000, 0x1FFF).unwrap();
        let r2 = AddressRange::from_start_end(0x1800, 0x2800).unwrap();

        let i = r1.intersection(&r2).unwrap();
        assert_eq!(i.start(), 0x1800);
        assert_eq!(i.end(), 0x1FFF);

        let r3 = AddressRange::from_start_end(0x2000, 0x3000).unwrap();
        assert!(r1.intersection(&r3).is_none());
    }

    #[test]
    fn test_parse_start_length_hex() {
        let r: AddressRange = "0x1000,0x200".parse().unwrap();
        assert_eq!(r.start(), 0x1000);
        assert_eq!(r.end(), 0x11FF);
    }

    #[test]
    fn test_parse_start_end_hex() {
        let r: AddressRange = "0x1000-0x11FF".parse().unwrap();
        assert_eq!(r.start(), 0x1000);
        assert_eq!(r.end(), 0x11FF);
    }

    #[test]
    fn test_parse_decimal() {
        let r: AddressRange = "4096,512".parse().unwrap();
        assert_eq!(r.start(), 4096);
        assert_eq!(r.length(), 512);
    }

    #[test]
    fn test_parse_binary() {
        let r: AddressRange = "0b1000,0b100".parse().unwrap();
        assert_eq!(r.start(), 8);
        assert_eq!(r.length(), 4);

        let r2: AddressRange = "1000b,100b".parse().unwrap();
        assert_eq!(r2.start(), 8);
        assert_eq!(r2.length(), 4);
    }

    #[test]
    fn test_parse_ranges_multiple() {
        let ranges = parse_ranges("0x1000,0x100:0x2000-0x2FFF").unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start(), 0x1000);
        assert_eq!(ranges[0].end(), 0x10FF);
        assert_eq!(ranges[1].start(), 0x2000);
        assert_eq!(ranges[1].end(), 0x2FFF);
    }

    #[test]
    fn test_parse_compat_ranges_quotes() {
        let ranges = parse_compat_ranges("'0x1000,0x100:0x2000-0x2FFF'").unwrap();
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start(), 0x1000);
        assert_eq!(ranges[1].start(), 0x2000);
    }

    #[test]
    fn test_zero_length_error() {
        assert!(matches!(
            AddressRange::from_start_length(0x1000, 0),
            Err(AddressRangeError::ZeroLength { .. })
        ));
    }

    #[test]
    fn test_start_exceeds_end_error() {
        assert!(matches!(
            AddressRange::from_start_end(0x2000, 0x1000),
            Err(AddressRangeError::StartExceedsEnd { .. })
        ));
    }

    // --- Edge case tests ---

    #[test]
    fn test_full_4gib_range_allowed() {
        let r = AddressRange::from_start_end(0, u32::MAX).unwrap();
        assert_eq!(r.start(), 0);
        assert_eq!(r.end(), u32::MAX);
        assert_eq!(r.length(), 0x1_0000_0000);
        assert_eq!(r.addressable_length(), 0x1_0000_0000);
        assert!(!r.extends_past_address_space());
    }

    #[test]
    fn test_near_max_range_allowed() {
        // 1 to MAX is allowed (length = MAX)
        let r = AddressRange::from_start_end(1, u32::MAX).unwrap();
        assert_eq!(r.length(), u64::from(u32::MAX));
    }

    #[test]
    fn test_merge_ranges_can_coalesce_full_span() {
        let ranges = [
            AddressRange::from_start_end(0, 0x7FFF_FFFF).unwrap(),
            AddressRange::from_start_end(0x8000_0000, u32::MAX).unwrap(),
        ];

        let merged = merge_ranges(&ranges);
        assert_eq!(
            merged,
            vec![AddressRange::from_start_end(0, u32::MAX).unwrap()]
        );
    }

    #[test]
    fn test_single_byte_range() {
        let r = AddressRange::from_start_end(0x1000, 0x1000).unwrap();
        assert_eq!(r.length(), 1);
        assert!(r.contains(0x1000));
        assert!(!r.contains(0x1001));
    }

    #[test]
    fn test_parse_u32_max() {
        let r: AddressRange = "0xFFFFFFFF,1".parse().unwrap();
        assert_eq!(r.start(), u32::MAX);
        assert_eq!(r.end(), u32::MAX);
        assert_eq!(r.length(), 1);
    }

    #[test]
    fn test_parse_overflow_number() {
        let result: Result<AddressRange, _> = "0x100000000,1".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_binary() {
        let result: Result<AddressRange, _> = "0b102,1".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_string() {
        let result: Result<AddressRange, _> = "".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_malformed_comma() {
        let result: Result<AddressRange, _> = "0x1000,".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_malformed_dash() {
        let result: Result<AddressRange, _> = "0x1000-".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_ranges_single() {
        let ranges = parse_ranges("0x1000,0x100").unwrap();
        assert_eq!(ranges.len(), 1);
    }

    #[test]
    fn test_start_length_can_extend_past_address_space() {
        let r = AddressRange::from_start_length(u32::MAX, 2).unwrap();
        assert_eq!(r.start(), u32::MAX);
        assert_eq!(r.end(), u32::MAX);
        assert_eq!(r.length(), 2);
        assert_eq!(r.addressable_length(), 1);
        assert!(r.extends_past_address_space());
    }

    #[test]
    fn test_parse_length_overflow_keeps_addressable_endpoint() {
        let r: AddressRange = "0xFFFFFFFC,0x8".parse().unwrap();
        assert_eq!(r.start(), 0xFFFF_FFFC);
        assert_eq!(r.end(), u32::MAX);
        assert_eq!(r.length(), 8);
        assert_eq!(r.addressable_length(), 4);
        assert!(r.extends_past_address_space());
    }

    #[test]
    fn test_parse_full_span_start_length() {
        let r: AddressRange = "0x0,0x100000000".parse().unwrap();
        assert_eq!(r.start(), 0);
        assert_eq!(r.end(), u32::MAX);
        assert_eq!(r.length(), 0x1_0000_0000);
        assert!(!r.extends_past_address_space());
    }

    #[test]
    fn test_parse_endpoint_above_address_space_errors() {
        let result: Result<AddressRange, _> = "0x0-0x100000000".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_overlaps_single_byte_boundary() {
        let r1 = AddressRange::from_start_end(0x1000, 0x1000).unwrap();
        let r2 = AddressRange::from_start_end(0x1000, 0x1000).unwrap();
        assert!(r1.overlaps(&r2));

        let r3 = AddressRange::from_start_end(0x1001, 0x1001).unwrap();
        assert!(!r1.overlaps(&r3));
    }
}

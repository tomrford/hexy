use std::str::FromStr;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AddressRangeError {
    #[error("invalid range '{0}': expected start-end or start,length")]
    InvalidFormat(String),

    #[error("range start ({start:#X}) exceeds end ({end:#X})")]
    StartExceedsEnd { start: u32, end: u32 },

    #[error("zero length range at {start:#X}")]
    ZeroLength { start: u32 },

    #[error("range {start:#X},{length:#X} reaches past the address space")]
    PastAddressSpace { start: u32, length: u64 },
}

/// An inclusive memory address range inside the u32 address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressRange {
    start: u32,
    end: u32,
}

impl AddressRange {
    /// Create range from start address and length.
    pub fn from_start_length(start: u32, length: u64) -> Result<Self, AddressRangeError> {
        if length == 0 {
            return Err(AddressRangeError::ZeroLength { start });
        }
        let end = u64::from(start)
            .checked_add(length - 1)
            .and_then(|end| u32::try_from(end).ok())
            .ok_or(AddressRangeError::PastAddressSpace { start, length })?;
        Ok(Self { start, end })
    }

    /// Create range from start and end addresses (inclusive).
    pub fn from_start_end(start: u32, end: u32) -> Result<Self, AddressRangeError> {
        if start > end {
            return Err(AddressRangeError::StartExceedsEnd { start, end });
        }
        Ok(Self { start, end })
    }

    /// Construct from endpoints already known to satisfy `start <= end`.
    pub(crate) fn new_valid(start: u32, end: u32) -> Self {
        debug_assert!(start <= end);
        Self { start, end }
    }

    pub fn start(&self) -> u32 {
        self.start
    }

    pub fn end(&self) -> u32 {
        self.end
    }

    pub fn length(&self) -> u64 {
        u64::from(self.end) - u64::from(self.start) + 1
    }

    pub fn contains(&self, addr: u32) -> bool {
        addr >= self.start && addr <= self.end
    }

    pub fn overlaps(&self, other: &AddressRange) -> bool {
        self.start <= other.end && other.start <= self.end
    }

    /// Return the intersection of two ranges, if they overlap.
    pub fn intersection(&self, other: &AddressRange) -> Option<AddressRange> {
        self.overlaps(other).then(|| AddressRange {
            start: self.start.max(other.start),
            end: self.end.min(other.end),
        })
    }
}

impl FromStr for AddressRange {
    type Err = AddressRangeError;

    /// `start-end` or `start,length` as HexView reads a range. Each number is `0x` hex or
    /// decimal after optional blanks, the start also after one `+`, and text after the
    /// second number is ignored; the start must be followed directly by `,` or `-`. A
    /// missing second number reads as 0.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let invalid = || AddressRangeError::InvalidFormat(s.to_owned());
        let (start, rest) = range_number(s.strip_prefix('+').unwrap_or(s)).ok_or_else(invalid)?;
        let mut rest = rest.chars();
        let separator = rest.next();
        let second = range_number(rest.as_str()).map_or(0, |(value, _)| value);
        match separator {
            Some(',') => Self::from_start_length(start, u64::from(second)),
            Some('-') => Self::from_start_end(start, second),
            _ => Err(invalid()),
        }
    }
}

/// A HexView range number and the text after it; `None` without digits or above 32
/// bits.
fn range_number(s: &str) -> Option<(u32, &str)> {
    let s = s.trim_start();
    let (radix, digits) = match s.strip_prefix("0x") {
        Some(hex) if hex.starts_with(|c: char| c.is_ascii_hexdigit()) => (16, hex),
        _ => (10, s),
    };
    let end = digits
        .find(|c: char| !c.is_digit(radix))
        .unwrap_or(digits.len());
    let value = u32::from_str_radix(&digits[..end], radix).ok()?;
    Some((value, &digits[end..]))
}

/// Merge overlapping or adjacent ranges into a sorted, non-overlapping set.
pub(crate) fn merge_ranges(ranges: &[AddressRange]) -> Vec<AddressRange> {
    let mut sorted = ranges.to_vec();
    sorted.sort_by_key(|r| r.start);

    let mut merged: Vec<AddressRange> = Vec::new();
    for range in sorted {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end.saturating_add(1)
        {
            last.end = last.end.max(range.end);
            continue;
        }
        merged.push(range);
    }
    merged
}

/// The parts of `range` not covered by `excludes` (sorted and non-overlapping, as
/// returned by [`merge_ranges`]).
pub(crate) fn subtract_ranges(range: AddressRange, excludes: &[AddressRange]) -> Vec<AddressRange> {
    let mut out = Vec::new();
    let mut cursor = range.start;
    for ex in excludes {
        if ex.end < cursor {
            continue;
        }
        if ex.start > range.end {
            break;
        }
        if cursor < ex.start {
            out.push(AddressRange {
                start: cursor,
                end: ex.start - 1,
            });
        }
        match ex.end.checked_add(1) {
            Some(next) if next <= range.end => cursor = next,
            _ => return out,
        }
    }
    out.push(AddressRange {
        start: cursor,
        end: range.end,
    });
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HexView 1.15.2 range text: `0x` hex or decimal, ignored trailing text, no `h` or
    /// `0b` forms, and a start that must be followed directly by `,` or `-`. HexView
    /// skips an empty range or one past the address space and stops a list at any other
    /// error.
    #[test]
    fn test_parse_matches_hexview() {
        let range = |text: &str| text.parse::<AddressRange>();
        let valid = |start, end| AddressRange::from_start_end(start, end).unwrap();
        assert_eq!(range("0x1000,4x").unwrap(), valid(0x1000, 0x1003));
        assert_eq!(
            range("0x1000-0x1003-0x1005").unwrap(),
            valid(0x1000, 0x1003)
        );
        assert_eq!(range("+ 8,4").unwrap(), valid(8, 11));
        assert_eq!(range("010,4").unwrap(), valid(10, 13));
        assert_eq!(range("0x0-0xFFFFFFFF").unwrap(), valid(0, u32::MAX));
        for skipped in ["0x1000,", "8,+4", "0xFFFFFFFC,5"] {
            assert!(
                matches!(
                    range(skipped),
                    Err(AddressRangeError::ZeroLength { .. }
                        | AddressRangeError::PastAddressSpace { .. })
                ),
                "{skipped}"
            );
        }
        for invalid in [
            "0x1000-",
            "0x1000",
            ",4",
            "1000h,4",
            "0X8,4",
            "0x1000 , 4",
            "0x10_00,4",
            " +8,4",
            "q",
            "8\u{e9}4",
            "0x100000000,1",
        ] {
            assert!(
                matches!(
                    range(invalid),
                    Err(AddressRangeError::InvalidFormat(_)
                        | AddressRangeError::StartExceedsEnd { .. })
                ),
                "{invalid}"
            );
        }
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
}

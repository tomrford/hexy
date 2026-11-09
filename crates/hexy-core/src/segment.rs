use thiserror::Error;

use crate::AddressRange;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SegmentError {
    #[error("segment at {start:#X} has no data")]
    Empty { start: u32 },
    #[error("segment at {start:#X} with length {length} exceeds u32 address space")]
    AddressOverflow { start: u32, length: usize },
}

/// A non-empty run of bytes that lies wholly inside the u32 address space.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub(crate) start_address: u32,
    pub(crate) data: Vec<u8>,
}

#[allow(clippy::len_without_is_empty)] // segments are never empty
impl Segment {
    pub fn new(start_address: u32, data: Vec<u8>) -> Result<Self, SegmentError> {
        if data.is_empty() {
            return Err(SegmentError::Empty {
                start: start_address,
            });
        }
        if end_address_for(start_address, data.len()).is_none() {
            return Err(SegmentError::AddressOverflow {
                start: start_address,
                length: data.len(),
            });
        }
        Ok(Self {
            start_address,
            data,
        })
    }

    /// Build a segment from bytes already known to be non-empty and in range.
    pub(crate) fn from_valid(start_address: u32, data: Vec<u8>) -> Self {
        debug_assert!(end_address_for(start_address, data.len()).is_some());
        Self {
            start_address,
            data,
        }
    }

    pub fn start_address(&self) -> u32 {
        self.start_address
    }

    /// Inclusive end address.
    pub fn end_address(&self) -> u32 {
        self.start_address + (self.data.len() - 1) as u32
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn into_parts(self) -> (u32, Vec<u8>) {
        (self.start_address, self.data)
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn range(&self) -> AddressRange {
        AddressRange::new_valid(self.start_address, self.end_address())
    }

    /// The part of this segment inside `range`, if any.
    pub(crate) fn clipped(&self, range: AddressRange) -> Option<Segment> {
        let part = self.range().intersection(&range)?;
        let offset = (part.start() - self.start_address) as usize;
        let len = part.length() as usize;
        Some(Segment::from_valid(
            part.start(),
            self.data[offset..offset + len].to_vec(),
        ))
    }

    pub(crate) fn is_contiguous_with(&self, other: &Segment) -> bool {
        self.end_address().checked_add(1) == Some(other.start_address)
    }
}

/// Inclusive end address of `len` bytes at `start`, if they are non-empty and fit in u32.
pub(crate) fn end_address_for(start: u32, len: usize) -> Option<u32> {
    let len = u32::try_from(len).ok()?;
    start.checked_add(len.checked_sub(1)?)
}

#[cfg(test)]
mod tests {
    use super::{Segment, SegmentError};

    #[test]
    fn test_new_rejects_overflow_and_empty() {
        assert_eq!(
            Segment::new(u32::MAX, vec![0xAA, 0xBB]),
            Err(SegmentError::AddressOverflow {
                start: u32::MAX,
                length: 2
            })
        );
        assert_eq!(
            Segment::new(0x1000, Vec::new()),
            Err(SegmentError::Empty { start: 0x1000 })
        );
        assert_eq!(
            Segment::new(u32::MAX, vec![0xAA]).map(|s| s.end_address()),
            Ok(u32::MAX)
        );
    }
}

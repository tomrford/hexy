use thiserror::Error;

#[derive(Debug, Error)]
pub enum SegmentError {
    #[error("segment at {start:#X} with length {length} exceeds u32 address space")]
    AddressOverflow { start: u32, length: usize },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub start_address: u32,
    pub data: Vec<u8>,
}

impl Segment {
    /// Construct a segment.
    ///
    /// Panics if the segment data would extend past `u32::MAX`. Use
    /// [`Segment::try_new`] when invalid input should be reported as an error.
    #[allow(clippy::panic)]
    pub fn new(start_address: u32, data: Vec<u8>) -> Self {
        if Self::checked_end_address_for(start_address, data.len()).is_none() {
            panic!("segment exceeds u32 address space; use Segment::try_new to handle overflow");
        }
        Self {
            start_address,
            data,
        }
    }

    pub fn try_new(start_address: u32, data: Vec<u8>) -> Result<Self, SegmentError> {
        if Self::checked_end_address_for(start_address, data.len()).is_none() {
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

    pub fn checked_end_address(&self) -> Option<u32> {
        Self::checked_end_address_for(self.start_address, self.data.len())
    }

    pub fn end_address(&self) -> u32 {
        self.checked_end_address().unwrap_or(u32::MAX)
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_contiguous_with(&self, other: &Segment) -> bool {
        self.end_address().checked_add(1) == Some(other.start_address)
    }

    pub fn merge(&mut self, other: Segment) {
        debug_assert!(self.is_contiguous_with(&other));
        self.data.extend(other.data);
    }

    fn checked_end_address_for(start_address: u32, len: usize) -> Option<u32> {
        if len == 0 {
            return Some(start_address);
        }
        let len = u32::try_from(len).ok()?;
        start_address.checked_add(len - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::Segment;

    #[test]
    fn test_try_new_rejects_overflow() {
        let result = Segment::try_new(u32::MAX, vec![0xAA, 0xBB]);
        assert!(result.is_err());
    }

    #[test]
    #[should_panic(expected = "segment exceeds u32 address space")]
    fn test_new_rejects_overflow() {
        let _ = Segment::new(u32::MAX, vec![0xAA, 0xBB]);
    }

    #[test]
    fn test_is_contiguous_with_overflow_false() {
        let seg = Segment::new(u32::MAX, vec![0xAA]);
        let next = Segment::new(0, vec![0xCC]);
        assert!(!seg.is_contiguous_with(&next));
    }
}

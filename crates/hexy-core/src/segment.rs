use thiserror::Error;

#[derive(Debug, Error)]
pub enum SegmentError {
    #[error("segment at {start:#X} with length {length} exceeds u32 address space")]
    AddressOverflow { start: u32, length: usize },
    #[error("segments are not contiguous (left end {left_end:#X}, right start {right_start:#X})")]
    NotContiguous { left_end: u32, right_start: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub(crate) start_address: u32,
    pub(crate) data: Vec<u8>,
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

    pub fn start_address(&self) -> u32 {
        self.start_address
    }

    pub fn end_address(&self) -> u32 {
        self.checked_end_address().unwrap_or(u32::MAX)
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

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn is_contiguous_with(&self, other: &Segment) -> bool {
        self.end_address().checked_add(1) == Some(other.start_address)
    }

    pub fn merge(&mut self, other: Segment) -> Result<(), SegmentError> {
        if !self.is_contiguous_with(&other) {
            return Err(SegmentError::NotContiguous {
                left_end: self.end_address(),
                right_start: other.start_address,
            });
        }
        let new_len =
            self.data
                .len()
                .checked_add(other.data.len())
                .ok_or(SegmentError::AddressOverflow {
                    start: self.start_address,
                    length: usize::MAX,
                })?;
        if Self::checked_end_address_for(self.start_address, new_len).is_none() {
            return Err(SegmentError::AddressOverflow {
                start: self.start_address,
                length: new_len,
            });
        }
        self.data.extend(other.data);
        Ok(())
    }

    pub(crate) fn set_start_address(&mut self, start_address: u32) -> Result<(), SegmentError> {
        if Self::checked_end_address_for(start_address, self.data.len()).is_none() {
            return Err(SegmentError::AddressOverflow {
                start: start_address,
                length: self.data.len(),
            });
        }
        self.start_address = start_address;
        Ok(())
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

    #[test]
    fn test_merge_rejects_non_contiguous_segment() {
        let mut seg = Segment::new(u32::MAX, vec![0xAA]);
        let result = seg.merge(Segment::new(0, vec![0xCC]));

        assert!(matches!(
            result,
            Err(super::SegmentError::NotContiguous { .. })
        ));
        assert_eq!(seg.start_address(), u32::MAX);
        assert_eq!(seg.data(), &[0xAA]);
    }
}

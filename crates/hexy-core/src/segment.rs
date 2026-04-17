#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    pub start_address: u32,
    pub data: Vec<u8>,
}

impl Segment {
    pub fn new(start_address: u32, data: Vec<u8>) -> Self {
        debug_assert!(
            data.len() <= u32::MAX as usize,
            "segment data exceeds u32::MAX bytes"
        );
        Self {
            start_address,
            data,
        }
    }

    pub fn end_address(&self) -> u32 {
        if self.data.is_empty() {
            self.start_address
        } else {
            self.start_address
                .checked_add(self.data.len() as u32)
                .and_then(|v| v.checked_sub(1))
                .unwrap_or(u32::MAX)
        }
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
}

#[cfg(test)]
mod tests {
    use super::Segment;

    #[test]
    fn test_end_address_saturates_on_overflow() {
        let seg = Segment::new(u32::MAX, vec![0xAA, 0xBB]);
        assert_eq!(seg.end_address(), u32::MAX);
    }

    #[test]
    fn test_is_contiguous_with_overflow_false() {
        let seg = Segment::new(u32::MAX, vec![0xAA, 0xBB]);
        let next = Segment::new(0, vec![0xCC]);
        assert!(!seg.is_contiguous_with(&next));
    }
}

//! LZSS as HexView 1.15.2 codes it (`/DP26`, `/DP27`, `/DP57` to `/DP60`).
//!
//! The stream is MSB-first bits: `1` and a byte is a literal; `0`, a window position and
//! a length code is a match; `0` and position 0 ends the stream. The window starts empty
//! (zero bytes) and is written from position 1. A match copies `code + break_even + 1`
//! bytes from its absolute window position, where `break_even` is
//! `(1 + window_bits + length_bits) / 9`.
//!
//! The compressor keeps the window's strings in a binary search tree and takes the
//! longest match greedily, which fixes its choice among equally long matches; this
//! reproduces HexView's output byte for byte.

use super::ProcessingError;

/// The window and length field sizes of an LZSS stream, in bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lzss {
    window_bits: u8,
    length_bits: u8,
}

impl Default for Lzss {
    /// HexView's default: a 10-bit window and 4-bit lengths, as in Ford SWDL005.
    fn default() -> Self {
        Self {
            window_bits: 10,
            length_bits: 4,
        }
    }
}

impl Lzss {
    /// Field sizes with `0 < length_bits < window_bits < 16`, as HexView requires.
    ///
    /// HexView holds the match length in a byte, so with 8 or more length bits it
    /// compresses to literals only, and decompression wraps longer lengths.
    pub fn new(window_bits: u8, length_bits: u8) -> Result<Self, ProcessingError> {
        if length_bits == 0 || length_bits >= window_bits || window_bits >= 16 {
            return Err(ProcessingError::InvalidLzss(window_bits, length_bits));
        }
        Ok(Self {
            window_bits,
            length_bits,
        })
    }

    pub fn window_bits(self) -> u8 {
        self.window_bits
    }

    pub fn length_bits(self) -> u8 {
        self.length_bits
    }

    fn window(self) -> usize {
        1 << self.window_bits
    }

    /// The longest match that does not pay off.
    fn break_even(self) -> usize {
        (1 + usize::from(self.window_bits) + usize::from(self.length_bits)) / 9
    }

    pub(super) fn compress(self, data: &[u8]) -> Vec<u8> {
        Compressor::new(self, data).run()
    }

    pub(super) fn decompress(self, data: &[u8]) -> Vec<u8> {
        let mask = self.window() - 1;
        let mut window = vec![0u8; self.window()];
        let mut position = 1;
        let mut bits = BitReader { data, position: 0 };
        let mut output = Vec::new();
        loop {
            let (source, length) = if bits.read(1) == 1 {
                (None, 1)
            } else {
                let source = bits.read(self.window_bits) as usize;
                if source == 0 {
                    break;
                }
                let code = bits.read(self.length_bits) as usize;
                (Some(source), (code + self.break_even() + 1) & 0xFF)
            };
            for i in 0..length {
                let byte = match source {
                    Some(source) => window[(source + i) & mask],
                    None => bits.read(8) as u8,
                };
                output.push(byte);
                window[position] = byte;
                position = (position + 1) & mask;
            }
        }
        output
    }
}

/// MSB-first bits; HexView reads past the end of the data as zero bits, which end the
/// stream.
struct BitReader<'a> {
    data: &'a [u8],
    position: usize,
}

impl BitReader<'_> {
    fn read(&mut self, count: u8) -> u32 {
        let mut value = 0;
        for _ in 0..count {
            let bit = self
                .data
                .get(self.position / 8)
                .map_or(0, |byte| (byte >> (7 - self.position % 8)) & 1);
            value = (value << 1) | u32::from(bit);
            self.position += 1;
        }
        value
    }
}

#[derive(Default)]
struct BitWriter {
    output: Vec<u8>,
    bits: usize,
}

impl BitWriter {
    fn write(&mut self, value: u32, count: u8) {
        for i in (0..count).rev() {
            if self.bits.is_multiple_of(8) {
                self.output.push(0);
            }
            if (value >> i) & 1 == 1 {
                self.output[self.bits / 8] |= 0x80 >> (self.bits % 8);
            }
            self.bits += 1;
        }
    }
}

/// No node: window position 0 is never in the tree, as it marks the end of a stream.
const NONE: usize = 0;

/// The greedy compressor. Window positions are tree nodes ordered by the string that
/// starts there; the root is the extra node at index `window`.
struct Compressor<'a> {
    lzss: Lzss,
    input: std::slice::Iter<'a, u8>,
    window: Vec<u8>,
    mask: usize,
    /// HexView holds the lookahead length in a byte.
    lookahead: usize,
    parent: Vec<usize>,
    smaller: Vec<usize>,
    larger: Vec<usize>,
    output: BitWriter,
}

impl<'a> Compressor<'a> {
    fn new(lzss: Lzss, data: &'a [u8]) -> Self {
        let size = lzss.window();
        Self {
            lzss,
            input: data.iter(),
            window: vec![0; size],
            mask: size - 1,
            lookahead: ((1usize << lzss.length_bits) + lzss.break_even()) & 0xFF,
            parent: vec![NONE; size + 1],
            smaller: vec![NONE; size + 1],
            larger: vec![NONE; size + 1],
            output: BitWriter::default(),
        }
    }

    fn root(&self) -> usize {
        self.window.len()
    }

    fn run(mut self) -> Vec<u8> {
        let mut position = 1;
        let mut ahead = 0;
        while ahead < self.lookahead {
            let Some(&byte) = self.input.next() else {
                break;
            };
            self.window[(position + ahead) & self.mask] = byte;
            ahead += 1;
        }
        let root = self.root();
        self.larger[root] = position;
        self.parent[position] = root;
        let (mut length, mut source) = (0, 0);
        while ahead > 0 {
            length = length.min(ahead);
            let consumed = if length <= self.lzss.break_even() {
                self.output.write(1, 1);
                self.output.write(u32::from(self.window[position]), 8);
                1
            } else {
                let code = length - self.lzss.break_even() - 1;
                self.output.write(0, 1);
                self.output.write(source as u32, self.lzss.window_bits);
                self.output.write(code as u32, self.lzss.length_bits);
                length
            };
            for _ in 0..consumed {
                let incoming = (position + self.lookahead) & self.mask;
                self.remove(incoming);
                match self.input.next() {
                    Some(&byte) => self.window[incoming] = byte,
                    None => ahead -= 1,
                }
                position = (position + 1) & self.mask;
                if ahead > 0 {
                    (length, source) = self.insert(position);
                }
            }
        }
        self.output.write(0, 1);
        self.output.write(0, self.lzss.window_bits);
        self.output.output
    }

    /// Add the string at `node` and return the longest match among the strings it passes,
    /// as (length, position), the last one found winning a tie. Position 0 is not added
    /// and matches nothing.
    fn insert(&mut self, node: usize) -> (usize, usize) {
        if node == NONE {
            return (0, 0);
        }
        let mut test = self.larger[self.root()];
        let (mut length, mut source) = (0, 0);
        loop {
            let mut matched = 0;
            let mut order = std::cmp::Ordering::Equal;
            while matched < self.lookahead {
                order = self.window[(node + matched) & self.mask]
                    .cmp(&self.window[(test + matched) & self.mask]);
                if order.is_ne() {
                    break;
                }
                matched += 1;
            }
            if matched >= length {
                (length, source) = (matched, test);
                if length >= self.lookahead {
                    self.replace(test, node);
                    return (length, source);
                }
            }
            let child = if order.is_ge() {
                &mut self.larger[test]
            } else {
                &mut self.smaller[test]
            };
            if *child == NONE {
                *child = node;
                self.parent[node] = test;
                self.larger[node] = NONE;
                self.smaller[node] = NONE;
                return (length, source);
            }
            test = *child;
        }
    }

    fn remove(&mut self, node: usize) {
        if node == NONE || self.parent[node] == NONE {
            return;
        }
        if self.larger[node] == NONE {
            self.splice(node, self.smaller[node]);
        } else if self.smaller[node] == NONE {
            self.splice(node, self.larger[node]);
        } else {
            let mut next = self.smaller[node];
            while self.larger[next] != NONE {
                next = self.larger[next];
            }
            self.remove(next);
            self.replace(node, next);
        }
    }

    /// Put `child` (possibly no node) in the place of `node`, which has no other child.
    fn splice(&mut self, node: usize, child: usize) {
        let parent = self.parent[node];
        if child != NONE {
            self.parent[child] = parent;
        }
        if self.larger[parent] == node {
            self.larger[parent] = child;
        } else {
            self.smaller[parent] = child;
        }
        self.parent[node] = NONE;
    }

    /// Put `new` in the place of `old` in the tree.
    fn replace(&mut self, old: usize, new: usize) {
        let parent = self.parent[old];
        if self.smaller[parent] == old {
            self.smaller[parent] = new;
        } else {
            self.larger[parent] = new;
        }
        self.parent[new] = parent;
        self.smaller[new] = self.smaller[old];
        self.larger[new] = self.larger[old];
        for child in [self.smaller[new], self.larger[new]] {
            if child != NONE {
                self.parent[child] = new;
            }
        }
        self.parent[old] = NONE;
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};

    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        crate::decode_hex_text(text.as_bytes()).unwrap()
    }

    /// 2500 bytes of `A`, `B` and `C` from a linear congruential generator, enough to wrap
    /// a 10-bit window twice.
    fn wrap_data() -> Vec<u8> {
        let mut x: u32 = 1;
        (0..2500)
            .map(|_| {
                x = (x.wrapping_mul(1_103_515_245).wrapping_add(12345)) & 0x7FFF_FFFF;
                b"ABC"[(x >> 16) as usize % 3]
            })
            .collect()
    }

    /// HexView 1.15.2 `/DP26`: literals, overlapping matches, the oldest of two equal
    /// matches, and the end marker without a length.
    #[test]
    fn test_compress_matches_hexview() {
        let lzss = Lzss::default();
        assert_eq!(lzss.compress(b"ABCDEFGH"), hex("a0d0a8744a2d1a8f480000"));
        assert_eq!(lzss.compress(&[b'A'; 32]), hex("a0801f02580000"));
        assert_eq!(lzss.compress(b"ABCxABCyABC"), hex("a0d0a87780023790022000"));
        // With 8 length bits HexView's byte-sized lookahead allows no match.
        let literals = Lzss::new(9, 8).unwrap();
        assert_eq!(literals.compress(b"AAAA"), hex("a0d068341000"));
    }

    /// HexView 1.15.2 `/DP26` and `/DP57` across window wraps, and their decompression.
    #[test]
    fn test_window_wrap_matches_hexview() {
        let data = wrap_data();
        for (window, length, digest) in [
            (
                10,
                4,
                "a32b0ea536cc9b6a7143f278229e976e823c7fa10318de955c77512ab5b31aa1",
            ),
            (
                12,
                5,
                "da8c2e4ffd118ed3470b75e2b8109ea1d846274bd20376b0e59d365ecbabe57e",
            ),
            (
                3,
                1,
                "3fd4572c31dde9e8660013656207bd8389787e1c14e85ff22c32a176669991f1",
            ),
        ] {
            let lzss = Lzss::new(window, length).unwrap();
            let compressed = lzss.compress(&data);
            assert_eq!(
                hex(digest),
                Sha256::digest(&compressed).to_vec(),
                "{window},{length}"
            );
            assert_eq!(lzss.decompress(&compressed), data, "{window},{length}");
        }
    }

    /// HexView 1.15.2 `/DP27` and `/DP58`: bits past the end are zero, the window starts
    /// as zero bytes, and lengths wrap at a byte.
    #[test]
    fn test_decompress_matches_hexview() {
        let lzss = Lzss::default();
        assert_eq!(lzss.decompress(&hex("ff")), hex("fe"));
        assert_eq!(lzss.decompress(&hex("a09f430000")), hex("410000000000"));
        // `A`, then matches with codes 0, 255 and 253: 3, 2 and 0 bytes.
        let wide = Lzss::new(9, 8).unwrap();
        assert_eq!(
            wide.decompress(&hex("a08020000ff803fa0000")),
            [b'A'; 6].to_vec()
        );
    }

    #[test]
    fn test_bits_limits() {
        assert!(Lzss::new(15, 14).is_ok());
        assert!(Lzss::new(2, 1).is_ok());
        for (window, length) in [(4, 4), (16, 4), (12, 0), (4, 5)] {
            assert!(Lzss::new(window, length).is_err(), "{window},{length}");
        }
    }
}

//! ARLE as HexView 1.15.2 codes it (`/DP36`, `/DP37`).
//!
//! Each token is a header byte `KKCCCCCC` and its data: kind 0 is `C` plain bytes; kinds
//! 1, 2 and 3 are one byte, word or long word repeated `C` times.
//!
//! The compressor's choices reproduce HexView's output: at each position it takes the
//! run that covers the most bytes (a byte run of at least 3, a word run of at least 2,
//! or a long word run of at least 2; the shorter unit on a tie). A word run of 2 starts
//! only where 6 or more bytes remain. A byte run ends early where a word run starts that
//! reaches past it and is longer than the word run at its end, and a word run likewise
//! where a long word run starts. Zero bytes that end the data are coded by a fixed rule
//! (see [`zero_tail`]).

use super::ProcessingError;

/// The most units or plain bytes one token holds.
const MAX_COUNT: usize = 63;

pub(super) fn compress(data: &[u8]) -> Vec<u8> {
    let mut runs = Runs::new(data);
    let zero_tail_start = data.len() - data.iter().rev().take_while(|&&b| b == 0).count();
    let mut output = Vec::new();
    let mut plain: Vec<u8> = Vec::new();
    let flush = |output: &mut Vec<u8>, plain: &mut Vec<u8>| {
        if !plain.is_empty() {
            output.push(plain.len() as u8);
            output.append(plain);
        }
    };
    let mut i = 0;
    while i < data.len() {
        let run = if i >= zero_tail_start {
            zero_tail(data.len() - i)
        } else {
            runs.best(i)
        };
        match run {
            Some((kind, count)) => {
                flush(&mut output, &mut plain);
                let unit = unit(kind);
                output.push(kind << 6 | count as u8);
                output.extend_from_slice(&data[i..i + unit]);
                i += unit * count;
            }
            None => {
                plain.push(data[i]);
                i += 1;
                if plain.len() == MAX_COUNT {
                    flush(&mut output, &mut plain);
                }
            }
        }
    }
    flush(&mut output, &mut plain);
    output
}

/// Every token must be complete and the output not empty, as HexView requires.
pub(super) fn decompress(data: &[u8]) -> Result<Vec<u8>, ProcessingError> {
    let mut output = Vec::new();
    let mut rest = data;
    while let Some((&header, tail)) = rest.split_first() {
        let count = usize::from(header & 0x3F);
        let kind = header >> 6;
        let take = if kind == 0 { count } else { unit(kind) };
        let (bytes, tail) = tail
            .split_at_checked(take)
            .ok_or(ProcessingError::InvalidArle)?;
        if kind == 0 {
            output.extend_from_slice(bytes);
        } else {
            (0..count).for_each(|_| output.extend_from_slice(bytes));
        }
        rest = tail;
    }
    if output.is_empty() {
        return Err(ProcessingError::InvalidArle);
    }
    Ok(output)
}

/// The unit size of a run kind: 1 byte, word or long word.
fn unit(kind: u8) -> usize {
    1 << (kind - 1)
}

/// HexView's run for `length` zero bytes that end the data: a byte run up to 63 bytes,
/// except a word run where the length is 2 more than a multiple of 4; above that, a long
/// word run, except a word run where the length is 2 or 3 more than a multiple of 4 and
/// below 128.
fn zero_tail(length: usize) -> Option<(u8, usize)> {
    Some(match length {
        0..3 => return None,
        3..=MAX_COUNT if length % 4 == 2 => (2, length / 2),
        3..=MAX_COUNT => (1, length),
        64..128 if length % 4 >= 2 => (2, length / 2),
        _ => (3, (length / 4).min(MAX_COUNT)),
    })
}

/// Repeat counts of each unit at each position, and the word runs ending byte runs.
struct Runs<'a> {
    data: &'a [u8],
    /// Whole units equal to the one at each position, from there on, up to 63; for
    /// bytes, words and long words.
    counts: [Vec<u8>; 3],
    /// Word runs as seen from inside a byte run, by position.
    words: Vec<Option<u8>>,
}

impl<'a> Runs<'a> {
    fn new(data: &'a [u8]) -> Self {
        let counts = [1, 2, 4].map(|unit| {
            let mut counts = vec![0u8; data.len()];
            for k in (0..data.len().saturating_sub(unit - 1)).rev() {
                let next = k + unit;
                counts[k] = if data.get(next..next + unit) == Some(&data[k..next]) {
                    (counts[next] + 1).min(MAX_COUNT as u8)
                } else {
                    1
                };
            }
            counts
        });
        Self {
            data,
            counts,
            words: vec![None; data.len()],
        }
    }

    fn count(&self, kind: u8, i: usize) -> usize {
        self.counts[usize::from(kind - 1)]
            .get(i)
            .map_or(0, |&count| usize::from(count))
    }

    /// The run to code at `i`, as (kind, count).
    fn best(&mut self, i: usize) -> Option<(u8, usize)> {
        [
            (1, self.byte_run(i)),
            (2, self.word_run(i, true)),
            (3, self.long_run(i)),
        ]
        .into_iter()
        .filter(|&(_, count)| count > 0)
        .fold(None, |best, (kind, count)| match best {
            Some((k, c)) if unit(k) * c >= unit(kind) * count => best,
            _ => Some((kind, count)),
        })
    }

    fn long_run(&self, i: usize) -> usize {
        let count = self.count(3, i);
        if count >= 2 { count } else { 0 }
    }

    /// A word run at `i`; one that starts the next token needs 6 bytes for 2 words.
    fn word_run(&self, i: usize, starts: bool) -> usize {
        let valid =
            |count: usize| count >= 3 || (count == 2 && !(starts && self.data.len() - i < 6));
        let mut count = self.count(2, i);
        if !valid(count) {
            return 0;
        }
        let end = i + 2 * count;
        let at_end = 4 * self.long_run(end);
        if let Some(k) = (i + 2..end).step_by(2).find(|&k| {
            let long = 4 * self.long_run(k);
            long > 0 && k + long > end && long > at_end
        }) {
            count = (k - i) / 2;
        }
        if valid(count) { count } else { 0 }
    }

    fn inner_word_run(&mut self, i: usize) -> usize {
        if i >= self.data.len() {
            return 0;
        }
        if let Some(count) = self.words[i] {
            return usize::from(count);
        }
        let count = self.word_run(i, false);
        self.words[i] = Some(count as u8);
        count
    }

    fn byte_run(&mut self, i: usize) -> usize {
        let mut count = self.count(1, i);
        if count < 3 {
            return 0;
        }
        let end = i + count;
        let at_end = 2 * self.inner_word_run(end);
        if let Some(k) = (i + 1..end).find(|&k| {
            let word = 2 * self.inner_word_run(k);
            word > 0 && k + word > end && word > at_end
        }) {
            count = k - i;
        }
        if count >= 3 { count } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        crate::decode_hex_text(text.as_bytes()).unwrap()
    }

    /// HexView 1.15.2 `/DP36` on inputs that show its run choices.
    #[test]
    fn test_compress_matches_hexview() {
        for (data, expected) in [
            // A word run of 2 needs 6 bytes left.
            (&b"ABAB"[..], "0441424142"),
            (b"ABABxy", "8241420278 79"),
            // The byte run ends where the word run ABAB starts, so AA as words wins.
            (b"AAAABAB", "82414103424142"),
            // The word run AB ends where the long word run ABAA starts.
            (b"ABABAAABAAA", "024142c2414241410141"),
            // ABAB at the end of AAA is no longer than BABA after it, so AAA stays.
            (b"AAABABA", "434104 42414241"),
            (&[b'A'; 65], "a041410141"),
            (&[b'A'; 300], "ff41414141 70 41"),
            // Zero bytes that end the data.
            (&[1, 0, 0, 0, 0, 0, 0], "0101830000"),
            (&[0; 64], "d000000000"),
        ] {
            assert_eq!(
                compress(data),
                hex(expected),
                "{}",
                String::from_utf8_lossy(data)
            );
            assert_eq!(decompress(&compress(data)).unwrap(), data);
        }
    }

    /// HexView 1.15.2 `/DP37` takes a count of 0 and fails on an incomplete token or
    /// empty output.
    #[test]
    fn test_decompress_matches_hexview() {
        assert_eq!(decompress(&hex("004142")).unwrap(), hex("42"));
        for data in ["4341ff", "0341424344", "4000", ""] {
            assert!(decompress(&hex(data)).is_err(), "{data}");
        }
    }
}

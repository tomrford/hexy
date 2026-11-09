mod checksum;
mod error;
mod filter;
mod map;
mod transform;

pub use checksum::{ChecksumAlgorithm, ChecksumOptions, ForcedRange};
pub use error::OpsError;
pub use filter::{DEFAULT_DENSE_SPAN_LIMIT, FillOptions, MergeMode, MergeOptions};
pub use map::{BankedMapOptions, MapCollision, RemapOptions};
pub use transform::{AlignOptions, SwapMode};

use crate::AddressRange;

/// Length of `range` as an allocation size; a range covering the whole 4 GiB address
/// space cannot be held in one segment.
pub(crate) fn materialized_len(range: AddressRange) -> Result<usize, OpsError> {
    u32::try_from(range.length())
        .map(|len| len as usize)
        .map_err(|_| OpsError::AddressOverflow {
            address: range.start(),
        })
}

/// `len` bytes of `pattern` repeated, starting `phase` bytes into the pattern.
pub(crate) fn pattern_bytes(
    pattern: &[u8],
    phase: usize,
    len: usize,
) -> impl Iterator<Item = u8> + '_ {
    let skip = phase.checked_rem(pattern.len()).unwrap_or(0);
    pattern.iter().cycle().skip(skip).take(len).copied()
}

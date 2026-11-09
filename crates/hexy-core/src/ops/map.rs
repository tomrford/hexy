//! Banked-to-linear address mapping (`/REMAP`, `/S12MAP`, `/S12XMAP`, `/S08MAP`).
//!
//! Blocks are cut where mapping windows start and end; pieces outside every window stay
//! in place and stay joined. When a mapped piece lands on other data, the losing block
//! is dropped whole, as HexView 1.15.2 does.

use std::collections::BTreeMap;

use super::OpsError;
use crate::segment::end_address_for;
use crate::{AddressRange, HexFile, Segment};

const PAGE: u32 = 0x4000;

/// Options for address remapping of banked memory layouts.
#[derive(Debug, Clone)]
pub struct RemapOptions {
    pub start: u32,
    pub end: u32,
    pub linear: u32,
    pub size: u32,
    pub inc: u32,
}

/// Which block survives when a mapped piece lands on data that stays in place.
/// Between two mapped pieces the one from the lower source address survives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum MapCollision {
    /// The mapped piece replaces the data (HexView `/REMAP`, `/S12XMAP`, `/S08MAP`).
    #[default]
    MappedWins,
    /// The mapped piece is dropped (HexView `/S12MAP`).
    UnmappedWins,
}

/// Options for banked address mapping.
#[derive(Debug, Clone)]
pub(crate) struct BankedMapOptions {
    bank_min: u8,
    bank_max: u8,
    linear_base: u32,
    nonbank_low_base: u32,
    nonbank_high_base: u32,
    collision: MapCollision,
}

/// A piece of a block and its mapped start, `None` when it stays in place.
type Piece = (Segment, Option<u32>);

impl HexFile {
    /// Remap banked address ranges into a linear space.
    pub fn remap(&mut self, options: &RemapOptions) -> Result<(), OpsError> {
        if options.size == 0 || options.inc == 0 {
            return Err(OpsError::InvalidRemapParams(format!(
                "size and increment must be non-zero (size={}, inc={})",
                options.size, options.inc
            )));
        }
        if options.start > options.end {
            return Err(OpsError::InvalidRemapParams(format!(
                "start must be <= end (start={:#X}, end={:#X})",
                options.start, options.end
            )));
        }
        self.map_pieces(
            |segment| remap_pieces(segment, options),
            MapCollision::MappedWins,
        )
    }

    /// Map banked address ranges into a linear space.
    pub(crate) fn map_banked(&mut self, options: &BankedMapOptions) -> Result<(), OpsError> {
        if options.bank_min > options.bank_max {
            return Err(OpsError::InvalidRemapParams(format!(
                "bank_min must be <= bank_max (bank_min={}, bank_max={})",
                options.bank_min, options.bank_max
            )));
        }
        self.map_pieces(
            |segment| page_pieces(segment, |page| banked_target(page, options)),
            options.collision,
        )
    }

    pub fn map_star12(&mut self) -> Result<(), OpsError> {
        self.map_banked(&BankedMapOptions {
            bank_min: 0x30,
            bank_max: 0x3F,
            linear_base: 0x0C0000,
            nonbank_low_base: 0x0F8000,
            nonbank_high_base: 0x0FC000,
            collision: MapCollision::UnmappedWins,
        })
    }

    pub fn map_star12x(&mut self) -> Result<(), OpsError> {
        self.map_banked(&BankedMapOptions {
            bank_min: 0xE0,
            bank_max: 0xFF,
            linear_base: 0x780000,
            nonbank_low_base: 0x7F4000,
            nonbank_high_base: 0x7FC000,
            collision: MapCollision::MappedWins,
        })
    }

    /// Map Star08 pages to `0x100000 + page * 0x4000`: 0x0000, 0x4000 and 0xC000 are
    /// pages 0, 1 and 3, and the 0x8000 window of bank `PP` is page `PP` for banks 0, 2
    /// and 4 to 0x1F. Like HexView, 0x0000-0x3FFF stays in place when its data would
    /// land on data of the bank 0 window (0x8000-0xBFFF), which also maps to page 0.
    pub fn map_star08(&mut self) -> Result<(), OpsError> {
        let normalized = self.normalized();
        let page_offsets = |window: u32| -> Vec<AddressRange> {
            let window = AddressRange::new_valid(window, window + PAGE - 1);
            normalized
                .segments()
                .iter()
                .filter_map(|segment| segment.range().intersection(&window))
                .map(|part| AddressRange::new_valid(part.start() & 0x3FFF, part.end() & 0x3FFF))
                .collect()
        };
        let bank0 = page_offsets(0x8000);
        let map_page0 = !page_offsets(0x0000)
            .iter()
            .any(|fixed| bank0.iter().any(|window| window.overlaps(fixed)));
        self.map_pieces(
            |segment| page_pieces(segment, |page| Ok(star08_target(page, map_page0))),
            MapCollision::MappedWins,
        )
    }

    /// Cut each normalized block with `split`, then place the mapped pieces in source
    /// order, resolving collisions per `collision`. Validates every target before
    /// changing anything.
    fn map_pieces(
        &mut self,
        split: impl Fn(&Segment) -> Result<Vec<Piece>, OpsError>,
        collision: MapCollision,
    ) -> Result<(), OpsError> {
        let mut staying = BTreeMap::new();
        let mut mapped = Vec::new();
        for segment in self.normalized().segments() {
            let mut stay: Option<Segment> = None;
            for (piece, target) in split(segment)? {
                match target.filter(|&target| target != piece.start_address) {
                    Some(target) => {
                        if end_address_for(target, piece.len()).is_none() {
                            return Err(OpsError::AddressOverflow {
                                address: piece.start_address,
                            });
                        }
                        if let Some(stay) = stay.take() {
                            staying.insert(stay.start_address, stay);
                        }
                        mapped.push(Segment::from_valid(target, piece.data));
                    }
                    None => match &mut stay {
                        Some(stay) => stay.data.extend(piece.data),
                        None => stay = Some(piece),
                    },
                }
            }
            if let Some(stay) = stay {
                staying.insert(stay.start_address, stay);
            }
        }
        let mut placed: BTreeMap<u32, Segment> = BTreeMap::new();
        for piece in mapped {
            if !overlapping(&placed, &piece).is_empty() {
                continue;
            }
            let hits = overlapping(&staying, &piece);
            if collision == MapCollision::UnmappedWins && !hits.is_empty() {
                continue;
            }
            for start in hits {
                staying.remove(&start);
            }
            placed.insert(piece.start_address, piece);
        }
        staying.append(&mut placed);
        *self = HexFile::with_segments(staying.into_values().collect()).normalized();
        Ok(())
    }
}

/// Start addresses of the blocks in `blocks` (sorted, non-overlapping) that overlap
/// `segment`.
fn overlapping(blocks: &BTreeMap<u32, Segment>, segment: &Segment) -> Vec<u32> {
    let before = blocks
        .range(..segment.start_address)
        .next_back()
        .filter(|(_, block)| block.end_address() >= segment.start_address);
    before
        .into_iter()
        .chain(blocks.range(segment.start_address..=segment.end_address()))
        .map(|(&start, _)| start)
        .collect()
}

/// `segment` cut at 16 KiB page boundaries, each page mapped by `target`.
fn page_pieces(
    segment: &Segment,
    target: impl Fn(&Segment) -> Result<Option<u32>, OpsError>,
) -> Result<Vec<Piece>, OpsError> {
    let mut pieces = Vec::new();
    let mut addr = segment.start_address;
    let mut rest = segment.data.as_slice();
    while !rest.is_empty() {
        let len = ((PAGE - addr % PAGE) as usize).min(rest.len());
        let (page, tail) = rest.split_at(len);
        let page = Segment::from_valid(addr, page.to_vec());
        let target = target(&page)?;
        pieces.push((page, target));
        addr = addr.wrapping_add(len as u32);
        rest = tail;
    }
    Ok(pieces)
}

fn remap_pieces(segment: &Segment, options: &RemapOptions) -> Result<Vec<Piece>, OpsError> {
    let seg_start = segment.start_address;
    let seg_end = segment.end_address();
    let mut pieces = Vec::new();
    let mut start = seg_start;

    loop {
        let (end, mapped_start) = if start < options.start {
            (seg_end.min(options.start - 1), Some(start))
        } else if start > options.end {
            (seg_end, Some(start))
        } else {
            let offset = start - options.start;
            let bank_index = offset / options.inc;
            let bank_offset = offset % options.inc;
            let (window, mapped_start) = if bank_offset < options.size {
                let mapped = bank_index
                    .checked_mul(options.size)
                    .and_then(|base| base.checked_add(options.linear))
                    .and_then(|base| base.checked_add(bank_offset));
                (options.size, mapped)
            } else {
                (options.inc, Some(start))
            };
            let end = start
                .saturating_add(window - bank_offset - 1)
                .min(seg_end)
                .min(options.end);
            (end, mapped_start)
        };

        let data = &segment.data[(start - seg_start) as usize..=(end - seg_start) as usize];
        let mapped_start = mapped_start.ok_or(OpsError::AddressOverflow { address: start })?;
        pieces.push((
            Segment::from_valid(start, data.to_vec()),
            Some(mapped_start),
        ));

        if end == seg_end {
            return Ok(pieces);
        }
        start = end + 1;
    }
}

/// Mapped start of a piece within one 16 KiB page.
fn banked_target(page: &Segment, options: &BankedMapOptions) -> Result<Option<u32>, OpsError> {
    let start = page.start_address;
    let banks = u32::from(options.bank_min)..=u32::from(options.bank_max);
    let target = match (start >> 16, start & 0xC000) {
        (0, 0x4000) => options.nonbank_low_base.checked_add(start - 0x4000),
        (0, 0xC000) => options.nonbank_high_base.checked_add(start - 0xC000),
        (bank, 0x8000) if banks.contains(&bank) => options
            .linear_base
            .checked_add((bank - banks.start()) * PAGE + (start & 0x3FFF)),
        _ => return Ok(None),
    };
    target
        .map(Some)
        .ok_or(OpsError::AddressOverflow { address: start })
}

fn star08_target(page: &Segment, map_page0: bool) -> Option<u32> {
    let start = page.start_address;
    let page_number = match (start >> 16, start & 0xC000) {
        (0, 0x0000) if map_page0 => 0,
        (0, 0x8000) => 0,
        (0, 0x4000) => 1,
        (0, 0xC000) => 3,
        (bank @ (2 | 4..=0x1F), 0x8000) => bank,
        _ => return None,
    };
    Some(0x100000 + page_number * PAGE + (start & 0x3FFF))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hf(segments: &[(u32, &[u8])]) -> HexFile {
        HexFile::with_segments(
            segments
                .iter()
                .map(|&(start, data)| Segment::new(start, data.to_vec()).unwrap())
                .collect(),
        )
    }

    fn layout(file: &HexFile) -> Vec<(u32, Vec<u8>)> {
        file.segments()
            .iter()
            .map(|s| (s.start_address, s.data.clone()))
            .collect()
    }

    const BANKS: RemapOptions = RemapOptions {
        start: 0x018000,
        end: 0x02BFFF,
        linear: 0x008000,
        size: 0x4000,
        inc: 0x010000,
    };

    #[test]
    fn test_remap_moves_window_pieces_and_keeps_the_rest() {
        let mut file = hf(&[(0x017FFE, &[1, 2, 3, 4]), (0x01BFFE, &[5, 6, 7, 8])]);
        file.remap(&BANKS).unwrap();
        assert_eq!(
            layout(&file),
            [
                (0x8000, vec![3, 4]),
                (0xBFFE, vec![5, 6]),
                (0x017FFE, vec![1, 2]),
                (0x01C000, vec![7, 8]),
            ]
        );
    }

    #[test]
    fn test_remap_rejects_invalid_params_and_overflow_unchanged() {
        let mut file = hf(&[(0x1000, &[0xAA]), (0x2000, &[0xBB, 0xCC, 0xDD])]);
        let invalid = RemapOptions { size: 0, ..BANKS };
        assert!(matches!(
            file.remap(&invalid),
            Err(OpsError::InvalidRemapParams(_))
        ));
        let overflow = RemapOptions {
            start: 0x1000,
            end: 0x2FFF,
            linear: u32::MAX - 0x1000,
            size: 0x1000,
            inc: 0x1000,
        };
        assert!(matches!(
            file.remap(&overflow),
            Err(OpsError::AddressOverflow { .. })
        ));
        assert_eq!(
            layout(&file),
            [(0x1000, vec![0xAA]), (0x2000, vec![0xBB, 0xCC, 0xDD])]
        );
    }

    /// HexView 1.15.2: a mapped piece replaces the whole block it lands on.
    #[test]
    fn test_remap_mapped_piece_drops_block_it_lands_on() {
        let mut file = hf(&[(0x7FFE, &[1, 1, 1, 1]), (0x018000, &[2, 2, 2, 2])]);
        file.remap(&BANKS).unwrap();
        assert_eq!(layout(&file), [(0x8000, vec![2, 2, 2, 2])]);
    }

    /// HexView 1.15.2 `/S12MAP`: data that stays wins, and non-banked pages map first.
    #[test]
    fn test_map_star12_collisions_keep_existing_data() {
        let mut file = hf(&[(0xC000, &[1; 4]), (0x3F8000, &[2; 4])]);
        file.map_star12().unwrap();
        assert_eq!(layout(&file), [(0x0FC000, vec![1; 4])]);

        let mut file = hf(&[(0x4000, &[1; 4]), (0x0F8000, &[2; 4])]);
        file.map_star12().unwrap();
        assert_eq!(layout(&file), [(0x0F8000, vec![2; 4])]);
    }

    /// HexView 1.15.2 `/S12XMAP`: mapped data wins, and non-banked pages map first.
    #[test]
    fn test_map_star12x_collisions_keep_first_mapped_data() {
        let mut file = hf(&[(0x4000, &[1; 4]), (0x7F4000, &[2; 4]), (0xFD8000, &[3; 4])]);
        file.map_star12x().unwrap();
        assert_eq!(layout(&file), [(0x7F4000, vec![1; 4])]);
    }

    /// HexView 1.15.2 `/S08MAP` pages; banks 1 and 3 only have fixed windows.
    #[test]
    fn test_map_star08_pages() {
        let mut file = hf(&[
            (0x2000, &[2]),
            (0x4000, &[3]),
            (0x8000, &[4]),
            (0xC000, &[5]),
            (0x018000, &[6]),
            (0x028000, &[7]),
            (0x038000, &[8]),
            (0x1F8000, &[9]),
            (0x208000, &[10]),
        ]);
        file.map_star08().unwrap();
        assert_eq!(
            layout(&file),
            [
                (0x018000, vec![6]),
                (0x038000, vec![8]),
                (0x100000, vec![4]),
                (0x102000, vec![2]),
                (0x104000, vec![3]),
                (0x108000, vec![7]),
                (0x10C000, vec![5]),
                (0x17C000, vec![9]),
                (0x208000, vec![10]),
            ]
        );
    }

    /// HexView 1.15.2 leaves all of 0x0000-0x3FFF in place when any of it would land on
    /// bank 0 window data.
    #[test]
    fn test_map_star08_keeps_page0_that_collides_with_bank0() {
        let mut file = hf(&[(0x0000, &[1]), (0x2000, &[2]), (0x8000, &[4])]);
        file.map_star08().unwrap();
        assert_eq!(
            layout(&file),
            [(0x0000, vec![1]), (0x2000, vec![2]), (0x100000, vec![4])]
        );
    }

    #[test]
    fn test_map_star08_splits_blocks_at_pages() {
        // HexView 1.15.2 maps 0x7FFC..0x8003 as two pages and 0xFFFC..0x10003 as one.
        let mut file = hf(&[(0x7FFC, &[1, 2, 3, 4, 5, 6, 7, 8])]);
        file.map_star08().unwrap();
        assert_eq!(
            layout(&file),
            [(0x100000, vec![5, 6, 7, 8]), (0x107FFC, vec![1, 2, 3, 4])]
        );
        let mut file = hf(&[(0xFFFC, &[1, 2, 3, 4, 5, 6, 7, 8])]);
        file.map_star08().unwrap();
        assert_eq!(
            layout(&file),
            [(0x010000, vec![5, 6, 7, 8]), (0x10FFFC, vec![1, 2, 3, 4])]
        );
    }

    #[test]
    fn test_map_banked_overflow_leaves_file_unchanged() {
        let mut file = hf(&[(0x4000, &[0xAA]), (0xC000, &[0xBB, 0xCC, 0xDD])]);
        let options = BankedMapOptions {
            bank_min: 0x30,
            bank_max: 0x30,
            linear_base: 0,
            nonbank_low_base: 0x100000,
            nonbank_high_base: u32::MAX - 1,
            collision: MapCollision::MappedWins,
        };
        assert!(matches!(
            file.map_banked(&options),
            Err(OpsError::AddressOverflow { .. })
        ));
        assert_eq!(
            layout(&file),
            [(0x4000, vec![0xAA]), (0xC000, vec![0xBB, 0xCC, 0xDD])]
        );
    }
}

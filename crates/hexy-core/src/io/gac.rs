use super::WriteError;
use crate::HexFile;

/// Write a GAC software interlock file: the block count as one byte, each block's
/// big-endian start address and length, then the data of every block. CLI: /XGACSWIL.
pub fn write_gac_swil(hexfile: &HexFile) -> Result<Vec<u8>, WriteError> {
    let blocks = hexfile.blocks();
    let count = u8::try_from(blocks.len()).map_err(|_| {
        WriteError::InvalidOutput(format!(
            "{} blocks do not fit a GAC block count",
            blocks.len()
        ))
    })?;
    let mut out = vec![count];
    for block in &blocks {
        out.extend(block.start_address().to_be_bytes());
        out.extend((block.len() as u32).to_be_bytes());
    }
    for block in &blocks {
        out.extend_from_slice(block.data());
    }
    Ok(out)
}

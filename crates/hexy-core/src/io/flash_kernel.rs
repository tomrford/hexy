use super::{IntelHexWriteOptions, WriteError, write_intel_hex};
use crate::{HexFile, Segment};

/// The `[FLASH_KERNEL_CONFIG]` values of a CCP/XCP flash kernel file. HexView copies
/// them as text, so they keep the form they are given in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlashKernelHeader {
    pub name: String,
    pub comment: String,
    pub file_address: String,
    pub size: String,
    pub ram_address: String,
    pub ram_start: String,
}

impl FlashKernelHeader {
    /// HexView's defaults for kernel `block` written to the file `name`: the block's
    /// start for the addresses, its length for the size.
    pub fn new(name: &str, block: &Segment) -> Self {
        let start = format!("0x{:X}", block.start_address());
        Self {
            name: name.to_owned(),
            comment: format!("Flash kernel {name}").trim_end().to_owned(),
            file_address: start.clone(),
            size: format!("0x{:X}", block.len()),
            ram_address: start.clone(),
            ram_start: start,
        }
    }
}

/// Write a CCP/XCP flash kernel (`.fkl`): the header followed by the kernel as Intel
/// HEX. The kernel must be a single block. CLI: /XK.
pub fn write_flash_kernel(
    hexfile: &HexFile,
    header: &FlashKernelHeader,
) -> Result<Vec<u8>, WriteError> {
    let blocks = hexfile.blocks().len();
    if blocks != 1 {
        return Err(WriteError::InvalidOutput(format!(
            "a flash kernel is a single block, not {blocks}"
        )));
    }
    let mut out = format!(
        "\r\n[FLASH_KERNEL_CONFIG]\r\n\r\nFLASH_KERNEL_NAME=\"{}\"\r\nFLASH_KERNEL_COMMENT=\"{}\"\r\nFLASH_KERNEL_FILE_ADDR={}\r\nFLASH_KERNEL_SIZE={}\r\nFLASH_KERNEL_RAM_ADDR={}\r\nFLASH_KERNEL_RAM_START={}\r\n\r\n\r\n[FLASH_KERNEL_DATA]\r\n\r\n\r\n",
        header.name,
        header.comment,
        header.file_address,
        header.size,
        header.ram_address,
        header.ram_start
    )
    .into_bytes();
    out.extend(write_intel_hex(hexfile, &IntelHexWriteOptions::default())?);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// HexView 1.15.2 `/XK -o out.fkl` without an INI file.
    #[test]
    fn test_flash_kernel_matches_hexview() {
        let block = Segment::new(0x1000, (0..0x13u8).map(|i| 1 + 7 * i).collect()).unwrap();
        let header = FlashKernelHeader::new("out.fkl", &block);
        let out = write_flash_kernel(&HexFile::with_segments(vec![block]), &header).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&out),
            "\r\n[FLASH_KERNEL_CONFIG]\r\n\r\nFLASH_KERNEL_NAME=\"out.fkl\"\r\nFLASH_KERNEL_COMMENT=\"Flash kernel out.fkl\"\r\nFLASH_KERNEL_FILE_ADDR=0x1000\r\nFLASH_KERNEL_SIZE=0x13\r\nFLASH_KERNEL_RAM_ADDR=0x1000\r\nFLASH_KERNEL_RAM_START=0x1000\r\n\r\n\r\n[FLASH_KERNEL_DATA]\r\n\r\n\r\n:1310000001080F161D242B323940474E555C636A71787F1D\r\n:00000001FF\r\n"
        );
    }
}

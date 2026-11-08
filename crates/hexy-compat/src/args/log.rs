//! HexView log-file commands (`/L`), matched case-sensitively at the start of a line.
//! `FileNew` and `FileOpen` leave an empty image, as they do in HexView's command-line
//! run; other lines are ignored. `FileOpen` without a file name also fails.

use hexy_core::HexFile;

use super::error::CliError;

pub(super) fn execute_log(hexfile: &mut HexFile, content: &str) -> Result<(), CliError> {
    let mut result = Ok(());
    for line in content.lines() {
        if line.starts_with("FileNew") {
            *hexfile = HexFile::new();
        } else if let Some(file) = line.strip_prefix("FileOpen") {
            *hexfile = HexFile::new();
            if file.trim().is_empty() {
                result = Err(CliError::Other("/L: FileOpen without a file name".into()));
            }
        }
    }
    result
}

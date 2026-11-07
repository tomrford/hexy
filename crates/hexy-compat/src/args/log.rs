//! HexView log-file commands (`/L`). `FileClose` and `FileNew` clear the image;
//! `FileOpen <path>` is rejected because command-line export works on one image.

use hexy_core::HexFile;

use super::error::CliError;

pub(super) fn execute_log(hexfile: &mut HexFile, content: &str) -> Result<(), CliError> {
    for (index, line) in content.lines().enumerate() {
        let line_no = index + 1;
        let line = line.trim();
        let Some(command) = line.split_whitespace().next() else {
            continue;
        };
        let argument = line[command.len()..].trim();
        match command.to_ascii_uppercase().as_str() {
            "FILECLOSE" | "FILENEW" => *hexfile = HexFile::new(),
            "FILEOPEN" if argument.is_empty() => {
                return Err(CliError::Other(format!(
                    "/L: FileOpen missing filename on line {line_no}"
                )));
            }
            "FILEOPEN" => {
                return Err(CliError::Unsupported(format!(
                    "/L: FileOpen is not supported for command-line export (line {line_no}): {}",
                    argument.trim_matches(|c| c == '"' || c == '\'')
                )));
            }
            _ => {
                return Err(CliError::Other(format!(
                    "/L: unsupported log command '{command}' on line {line_no}"
                )));
            }
        }
    }
    Ok(())
}

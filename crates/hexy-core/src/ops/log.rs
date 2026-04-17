use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::HexFile;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogCommandKind {
    FileOpen(PathBuf),
    FileClose,
    FileNew,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogCommand {
    pub line: usize,
    pub kind: LogCommandKind,
}

#[derive(Debug, Error)]
pub enum LogError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("log command FileOpen missing filename on line {line}")]
    MissingFilename { line: usize },

    #[error("unsupported log command '{command}' on line {line}")]
    UnsupportedCommand { command: String, line: usize },

    #[error("log command failed on line {line}: {source}")]
    Load {
        line: usize,
        #[source]
        source: Box<dyn std::error::Error>,
    },
}

fn strip_quotes(s: &str) -> &str {
    s.trim_matches(|c| c == '"' || c == '\'')
}

/// Parse log commands. CLI: /L.
pub fn parse_log_commands(content: &str) -> Result<Vec<LogCommand>, LogError> {
    let mut commands = Vec::new();

    for (index, raw_line) in content.lines().enumerate() {
        let line_no = index + 1;
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }

        let mut parts = line.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let rest = line.get(cmd.len()..).unwrap_or("").trim();
        let cmd_upper = cmd.to_ascii_uppercase();

        let kind = match cmd_upper.as_str() {
            "FILEOPEN" => {
                if rest.is_empty() {
                    return Err(LogError::MissingFilename { line: line_no });
                }
                let file = strip_quotes(rest);
                LogCommandKind::FileOpen(PathBuf::from(file))
            }
            "FILECLOSE" => LogCommandKind::FileClose,
            "FILENEW" => LogCommandKind::FileNew,
            _ => {
                return Err(LogError::UnsupportedCommand {
                    command: cmd.to_string(),
                    line: line_no,
                });
            }
        };

        commands.push(LogCommand {
            line: line_no,
            kind,
        });
    }

    Ok(commands)
}

/// Execute parsed log commands. CLI: /L.
pub fn execute_log_commands<F, E>(
    hexfile: &mut HexFile,
    commands: &[LogCommand],
    mut load: F,
) -> Result<(), LogError>
where
    F: FnMut(&Path) -> Result<HexFile, E>,
    E: Into<Box<dyn std::error::Error>>,
{
    for command in commands {
        match &command.kind {
            LogCommandKind::FileOpen(path) => {
                let loaded = load(path).map_err(|err| LogError::Load {
                    line: command.line,
                    source: err.into(),
                })?;
                *hexfile = loaded;
            }
            LogCommandKind::FileClose | LogCommandKind::FileNew => {
                *hexfile = HexFile::new();
            }
        }
    }

    Ok(())
}

/// Execute commands from a log file. CLI: /L.
pub fn execute_log_file<F, E>(hexfile: &mut HexFile, path: &Path, load: F) -> Result<(), LogError>
where
    F: FnMut(&Path) -> Result<HexFile, E>,
    E: Into<Box<dyn std::error::Error>>,
{
    let content = std::fs::read_to_string(path)?;
    let commands = parse_log_commands(&content)?;
    execute_log_commands(hexfile, &commands, load)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Segment;

    #[test]
    fn test_parse_log_commands_basic() {
        let content = "FileOpen test.hex\nFileClose\nFileNew\n";
        let commands = parse_log_commands(content).unwrap();
        assert_eq!(commands.len(), 3);
        assert_eq!(commands[0].line, 1);
        assert_eq!(
            commands[0].kind,
            LogCommandKind::FileOpen(PathBuf::from("test.hex"))
        );
    }

    #[test]
    fn test_parse_log_commands_missing_filename() {
        let content = "FileOpen\n";
        let err = parse_log_commands(content).unwrap_err();
        assert!(matches!(err, LogError::MissingFilename { line: 1 }));
    }

    #[test]
    fn test_execute_log_commands_fileopen() {
        let commands = vec![LogCommand {
            line: 1,
            kind: LogCommandKind::FileOpen(PathBuf::from("input.bin")),
        }];
        let mut file = HexFile::new();
        fn load_ok(_: &Path) -> Result<HexFile, std::io::Error> {
            Ok(HexFile::with_segments(vec![Segment::new(
                0x1000,
                vec![0xAA],
            )]))
        }
        execute_log_commands(&mut file, &commands, load_ok).unwrap();
        assert_eq!(file.segments().len(), 1);
        assert_eq!(file.segments()[0].start_address, 0x1000);
    }

    #[test]
    fn test_execute_log_commands_load_error() {
        let commands = vec![LogCommand {
            line: 3,
            kind: LogCommandKind::FileOpen(PathBuf::from("missing.bin")),
        }];
        let mut file = HexFile::new();
        let err = execute_log_commands(&mut file, &commands, |_| {
            Err(std::io::Error::new(std::io::ErrorKind::NotFound, "missing"))
        })
        .unwrap_err();
        assert!(matches!(err, LogError::Load { line: 3, .. }));
    }
}

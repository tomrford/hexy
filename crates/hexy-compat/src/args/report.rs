//! Warnings and errors: written to the `/E` file one per CRLF-terminated line, as
//! HexView writes them, and to stderr unless `/S` is given.

use std::io::Write;
use std::path::PathBuf;

pub(super) struct Report {
    error_log: Option<PathBuf>,
    silent: bool,
}

impl Report {
    /// Creates or truncates the `/E` file.
    pub(super) fn new(error_log: Option<PathBuf>, silent: bool) -> Self {
        if let Some(path) = &error_log {
            let _ = std::fs::write(path, "");
        }
        Self { error_log, silent }
    }

    pub(super) fn warn(&self, message: &str) {
        self.log(message);
        if !self.silent {
            eprintln!("Warning: {message}");
        }
    }

    pub(super) fn error(&self, message: &str) {
        self.log(message);
        if !self.silent {
            eprintln!("Error: {message}");
        }
    }

    /// A line in the `/E` file only.
    pub(super) fn log(&self, message: &str) {
        let Some(path) = &self.error_log else {
            return;
        };
        if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(path) {
            let _ = write!(file, "{message}\r\n");
        }
    }
}

#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use std::path::Path;

pub fn read_nonempty_lines(path: &Path) -> Vec<String> {
    let text = std::fs::read_to_string(path).unwrap();
    text.lines()
        .map(|l| l.trim().to_owned())
        .filter(|l| !l.is_empty())
        .collect()
}

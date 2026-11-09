use std::collections::HashMap;
use std::path::Path;

use super::io::ReadProvider;

/// Keys (lowercased) and values of an INI file; with `section`, only that section's,
/// matched case-insensitively.
pub(super) fn load_ini(
    path: &Path,
    provider: &impl ReadProvider,
    section: Option<&str>,
) -> Result<HashMap<String, String>, std::io::Error> {
    let content = provider.read_string(path)?;
    let mut map = HashMap::new();
    let mut in_section = section.is_none();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            in_section = section.is_none_or(|section| name.trim().eq_ignore_ascii_case(section));
            continue;
        }
        let Some((key, value)) = line.split_once('=').filter(|_| in_section) else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        // Windows INI reading strips one pair of matching quotes.
        let value = value.trim();
        let value = ['"', '\'']
            .into_iter()
            .find_map(|quote| value.strip_prefix(quote)?.strip_suffix(quote))
            .unwrap_or(value)
            .to_owned();
        map.insert(key, value);
    }

    Ok(map)
}

/// Add `keys` to `section` of an INI file, as Windows' `WritePrivateProfileString`
/// does: after the section's last line, or in a new section at the end of the file.
pub(super) fn add_ini_keys(
    path: &Path,
    section: &str,
    keys: &[(&str, &str)],
) -> Result<(), std::io::Error> {
    let content = match std::fs::read_to_string(path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => return Err(err),
    };
    let mut lines: Vec<String> = content.lines().map(str::to_owned).collect();
    let header = lines.iter().position(|line| {
        line.trim()
            .strip_prefix('[')
            .and_then(|line| line.strip_suffix(']'))
            .is_some_and(|name| name.trim().eq_ignore_ascii_case(section))
    });
    let insert_at = match header {
        Some(header) => {
            let end = lines[header + 1..]
                .iter()
                .position(|line| line.trim_start().starts_with('['))
                .map_or(lines.len(), |offset| header + 1 + offset);
            (header + 1..end)
                .rev()
                .find(|&index| !lines[index].trim().is_empty())
                .map_or(header + 1, |index| index + 1)
        }
        None => {
            lines.push(format!("[{section}]"));
            lines.len()
        }
    };
    let entries = keys.iter().map(|(key, value)| format!("{key}={value}"));
    lines.splice(insert_at..insert_at, entries);
    let mut text = lines.join("\r\n");
    text.push_str("\r\n");
    std::fs::write(path, text)
}

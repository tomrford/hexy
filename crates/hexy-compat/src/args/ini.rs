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

use std::collections::HashMap;
use std::path::Path;

use super::io::ReadProvider;

pub(super) fn load_ini(
    path: &Path,
    provider: &impl ReadProvider,
) -> Result<HashMap<String, String>, std::io::Error> {
    let content = provider.read_string(path)?;
    let mut map = HashMap::new();

    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim().to_ascii_lowercase();
        let value = value.trim().trim_matches('"').to_string();
        map.insert(key, value);
    }

    Ok(map)
}

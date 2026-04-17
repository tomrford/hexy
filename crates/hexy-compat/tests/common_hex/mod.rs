use std::path::Path;

use hexy_core::parse_intel_hex;

use crate::common::{assert_success, run_hexy};

pub fn run_hex_output(args: Vec<String>, out_path: &Path) -> hexy_core::HexFile {
    let output = run_hexy(&args);
    assert_success(&output);
    let data = std::fs::read(out_path).unwrap();
    parse_intel_hex(&data).unwrap()
}

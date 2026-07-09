fn main() {
    // Emit the platform link arguments required by extension modules, including
    // `-undefined dynamic_lookup` on macOS, so plain `cargo build` links.
    pyo3_build_config::add_extension_module_link_args();
}

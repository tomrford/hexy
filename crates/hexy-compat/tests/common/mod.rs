use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static COUNTER: AtomicUsize = AtomicUsize::new(0);

pub fn temp_dir(prefix: &str) -> PathBuf {
    let id = COUNTER.fetch_add(1, Ordering::SeqCst);
    let mut dir = std::env::temp_dir();
    dir.push(format!("hexy_{prefix}_{}_{}", std::process::id(), id));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

pub fn write_file(path: &Path, data: &[u8]) {
    std::fs::write(path, data).unwrap();
}

pub fn run_hexy(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hexy"))
        .args(args)
        .output()
        .unwrap()
}

pub fn assert_success(output: &Output) {
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!("hexy failed: {stderr}");
    }
}

#![allow(clippy::print_stderr)] // the CLI reports errors on stderr

use std::process::ExitCode;

pub use hexy_core::*;

mod args;

fn main() -> ExitCode {
    args::run()
}

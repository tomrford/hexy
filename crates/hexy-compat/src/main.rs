use std::process::ExitCode;

pub use hexy_core::ops::{LogError, execute_log_commands, parse_log_commands};
pub use hexy_core::*;

mod args;

fn main() -> ExitCode {
    args::run()
}

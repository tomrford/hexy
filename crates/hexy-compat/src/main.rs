#![cfg_attr(
    not(test),
    deny(
        clippy::expect_used,
        clippy::panic,
        clippy::str_to_string,
        clippy::todo,
        clippy::unimplemented,
        clippy::unwrap_used
    )
)]

use std::process::ExitCode;

pub use hexy_core::ops::{LogError, execute_log_commands, parse_log_commands};
pub use hexy_core::*;

mod args;

fn main() -> ExitCode {
    args::run()
}

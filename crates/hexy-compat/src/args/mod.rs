//! Cleanroom slash-compatible CLI argument parsing and execution.
//!
//! Parser boundary: this module parses HexView-style argv into `Args`; execution
//! builds a `hexy_core::Pipeline` from `Args` and runs its stages in order. The core
//! pipeline owns the stage order (steps 2-16 below, except /L); compat loads inputs,
//! runs /L after the /AR stage, reads /DP and /SV parameters when their stages run,
//! writes checksum and data processing files after their stages, and exports.
//! `hexy-core` does not depend on slash syntax.
//!
//! Processing order matches the cleanroom compatibility target (implemented subset):
//! 1. Read the input file, or without one the last import (/IN, /IA, /II2)
//! 2. Address mapping (/S08MAP, /S12MAP, /S12XMAP, /REMAP)
//! 3. dsPIC ops (/CDSPX, /CDSPS, /CDSPG)
//! 4. Fill ranges (/FR)
//! 5. Cut ranges (/CR)
//! 6. Merge files (/MT, /MO)
//! 7. Address range filter (/AR)
//! 8. Execute log commands (/L)
//! 9. Create single-region (/FA)
//! 10. Align (/AD, /AL)
//! 11. Split blocks (/SB)
//! 12. Swap bytes (/SWAPWORD, /SWAPLONG)
//! 13. Remove small blocks (/RB)
//! 14. Checksum (/CS, /CSM)
//! 15. Data processing (/DP)
//! 16. Signature verification (/SV)
//! 17. Export (/Xx)
//!
//! Warnings and errors go to the /E file and, without /S, to stderr.

mod error;
mod execute;
mod export;
mod ini;
mod io;
mod log;
mod parse;
mod parse_util;
mod processing;
mod report;
mod types;

use std::process::ExitCode;

use report::Report;
use types::Args;

pub fn run() -> ExitCode {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    let report = Report::new(args.error_log.clone(), args.silent);
    let result = args.execute(&report);
    if let Err(e) = &result {
        report.error(&e.to_string());
    }
    if args.write_version {
        report.log(&format!("hexy V{}", env!("CARGO_PKG_VERSION")));
    }
    // HexView lists unknown options last.
    if !args.unrecognized.is_empty() {
        report.warn(&format!(
            "Unrecognized commandline options: {}",
            args.unrecognized.join(" ")
        ));
    }
    if result.is_ok() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

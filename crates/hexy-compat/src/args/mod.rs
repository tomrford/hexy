//! Cleanroom slash-compatible CLI argument parsing and execution.
//!
//! Parser boundary: this module parses HexView-style argv into `Args`; execution
//! builds a `hexy_core::Pipeline` from `Args` and runs its stages in order. The core
//! pipeline owns the stage order (steps 5-19 below, except /L); compat loads inputs,
//! runs /L after the /AR stage, reads /DP and /SV parameters when their stages run,
//! writes checksum and data processing files after their stages, and exports.
//! `hexy-core` does not depend on slash syntax.
//!
//! Processing order matches the cleanroom compatibility target (implemented subset):
//! 1. Read input file
//! 2. Open error log (/E)
//! 3. Set silent mode (/S)
//! 4. Import 16-bit Hex (/II2)
//! 5. Address mapping (/S08MAP, /S12MAP, /REMAP)
//! 6. dsPIC ops (/CDSPX, /CDSPS, /CDSPG)
//! 7. Fill ranges (/FR)
//! 8. Cut ranges (/CR)
//! 9. Merge files (/MT, /MO)
//! 10. Address range filter (/AR)
//! 11. Execute log commands (/L)
//! 12. Create single-region (/FA)
//! 13. Align (/AD, /AL)
//! 14. Split blocks (/SB)
//! 15. Swap bytes (/SWAPWORD, /SWAPLONG)
//! 16. Remove small blocks (/RB)
//! 17. Checksum (/CS, /CSM)
//! 18. Data processing (/DP32/33/38/39/46/47/48/49)
//! 19. Signature verification (/SV4..11)
//! 20. Export (/Xx)
//!
//! Note: /PB remains unsupported (proprietary DLL-backed).

mod error;
mod execute;
mod ini;
mod io;
mod log;
mod parse;
mod parse_util;
mod processing;
mod types;

use std::io::Write;
use std::process::ExitCode;

use types::Args;

pub fn run() -> ExitCode {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Some(ref path) = args.error_log {
        let _ = std::fs::write(path, "");
    }

    if let Err(e) = args.execute() {
        if let Some(ref path) = args.error_log {
            let _ = std::fs::write(path, format!("{e}"));
        }
        if !args.silent {
            eprintln!("Error: {e}");
        }
        return ExitCode::FAILURE;
    }

    if args.write_version
        && let Some(ref path) = args.error_log
    {
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path);
        if let Ok(ref mut file) = file {
            let _ = write!(file, "hexy V{}", env!("CARGO_PKG_VERSION"));
        }
    }

    ExitCode::SUCCESS
}

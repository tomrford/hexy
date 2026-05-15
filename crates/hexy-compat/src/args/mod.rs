//! Cleanroom slash-compatible CLI argument parsing and execution.
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
//! 16. Checksum (/CS, /CSM)
//! 17. Data processing signature subset (/DP32/33/38/39/46/47/48/49)
//! 18. Signature verification subset (/SV4..11)
//! 19. Export (/Xx)
//!
//! Note: /PB remains unsupported (proprietary DLL-backed).

mod error;
mod execute;
mod ini;
mod io;
mod parse;
mod parse_util;
mod signature;
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

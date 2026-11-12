//! Standalone `umbra-native` CLI — the subprocess fallback for the Python
//! bridge (`defense/native_bridge.py`).
//!
//! Usage:
//!
//! ```text
//! umbra-native poison  <seed> <intensity> < input.bin > output.bin
//! umbra-native exhaust <seed> <intensity> < input.bin > output.bin
//! umbra-native --version
//! ```
//!
//! `<intensity>` accepts `0..3` or `stealth|balanced|maximum|bankrupt`.
//! Exit code 2 covers usage errors and unsupported container magic; exit code
//! 1 covers I/O failures.  Diagnostics go to stderr so stdout stays a clean
//! artifact stream.
//!
//! Concept inspired by: Anchor — zero-dependency native kernel, C-ABI surface

mod engine;

use std::io::{self, Read, Write};
use std::process::ExitCode;

const EXIT_IO: u8 = 1;
const EXIT_USAGE: u8 = 2;

fn parse_intensity(raw: &str) -> Option<u32> {
    match raw.to_ascii_lowercase().as_str() {
        "0" | "stealth" => Some(0),
        "1" | "balanced" => Some(1),
        "2" | "maximum" => Some(2),
        "3" | "bankrupt" => Some(3),
        _ => None,
    }
}

fn usage(message: &str) -> ExitCode {
    eprintln!("umbra-native: {message}");
    eprintln!("usage: umbra-native poison|exhaust <seed> <intensity> < input > output");
    eprintln!("       umbra-native --version");
    ExitCode::from(EXIT_USAGE)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();

    if args.len() == 2 && (args[1] == "--version" || args[1] == "-V") {
        println!("{}", engine::VERSION);
        return ExitCode::SUCCESS;
    }
    if args.len() != 4 {
        return usage("expected exactly three arguments");
    }

    let verb = args[1].as_str();
    if verb != "poison" && verb != "exhaust" {
        return usage(&format!("unknown verb {verb:?}"));
    }

    let seed: u64 = match args[2].parse() {
        Ok(value) => value,
        Err(_) => return usage(&format!("invalid seed {:?}", args[2])),
    };
    let intensity = match parse_intensity(&args[3]) {
        Some(value) => value,
        None => return usage(&format!("invalid intensity {:?}", args[3])),
    };

    let mut input = Vec::new();
    if let Err(exc) = io::stdin().read_to_end(&mut input) {
        eprintln!("umbra-native: failed to read stdin: {exc}");
        return ExitCode::from(EXIT_IO);
    }
    if input.is_empty() {
        return usage("stdin was empty");
    }

    let output = if verb == "poison" {
        engine::poison(&input, seed, intensity)
    } else {
        engine::exhaust(&input, seed, intensity)
    };
    let output = match output {
        Some(bytes) => bytes,
        None => {
            eprintln!(
                "umbra-native: unsupported container magic (expected PE, ELF or Mach-O)"
            );
            return ExitCode::from(EXIT_USAGE);
        }
    };

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if let Err(exc) = handle.write_all(&output) {
        eprintln!("umbra-native: failed to write stdout: {exc}");
        return ExitCode::from(EXIT_IO);
    }
    if let Err(exc) = handle.flush() {
        eprintln!("umbra-native: failed to flush stdout: {exc}");
        return ExitCode::from(EXIT_IO);
    }
    ExitCode::SUCCESS
}

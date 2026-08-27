// Unit-test harnesses may compile on another host, but the actual CLI remains Linux-only.
#[cfg(all(not(target_os = "linux"), not(test)))]
compile_error!("RavenScanner supports Linux only. Build and run it on a Linux target.");

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "ravenscanner",
    version,
    about = "Defensive static triage of a file's raw bytes (Linux only)"
)]
struct Cli {
    /// File to inspect. RavenScanner never executes or modifies it.
    file: PathBuf,

    /// Minimum length of printable ASCII strings to extract.
    #[arg(short = 'm', long, default_value_t = 4, value_parser = clap::value_parser!(u16).range(1..=4096))]
    min_string_length: u16,
}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("ravenscanner: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    let metadata = fs::metadata(&cli.file)
        .map_err(|error| format!("cannot access '{}': {error}", cli.file.display()))?;
    if !metadata.is_file() {
        return Err(format!("'{}' is not a regular file", cli.file.display()));
    }

    let bytes = fs::read(&cli.file)
        .map_err(|error| format!("cannot read '{}': {error}", cli.file.display()))?;
    let result = ravenscanner::scan_bytes(&bytes, usize::from(cli.min_string_length));
    ravenscanner::report::print_report(&cli.file, &result);
    Ok(())
}

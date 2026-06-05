use std::process::ExitCode;

use clap::Parser;

fn main() -> ExitCode {
	mail::cli::Cli::parse().run()
}

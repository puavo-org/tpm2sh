// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use std::sync::atomic::{AtomicBool, Ordering};

pub mod cli;
pub mod command;
pub mod crypto;
pub mod device;
pub mod error;
pub mod key;
pub mod mocktpm;
pub mod parser;
pub mod pcr;
pub mod print;
pub mod session;
pub mod transport;
pub mod uri;
pub mod util;

pub use command::CommandError;
pub use device::TpmDeviceError;

/// A global flag to signal graceful teardown of the application.
///
/// Set by the Ctrl-C handler to allow the main loop to finish its current
/// operation and perform necessary cleanup (e.g., flushing TPM contexts)
/// before exiting.
pub static TEARDOWN: AtomicBool = AtomicBool::new(false);

/// A trait for executing the top-level Commands enum.
pub trait Command {
    /// Returns `true` if the command does not require TPM device access.
    fn is_local(&self) -> bool;

    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `crate::error::CliError` if the command fails.
    fn run(
        &self,
        device: Option<std::sync::Arc<std::sync::Mutex<crate::device::TpmDevice>>>,
        context: &mut crate::command::context::Context,
    ) -> Result<(), crate::error::CliError>;
}

/// The result of parsing command-line arguments.
#[allow(clippy::large_enum_variant)]
pub enum ParseResult {
    /// A command was successfully parsed.
    Command(crate::cli::Cli),
    /// A help message should be printed. The payload is the static string content.
    Help(&'static str),
    /// A usage message should be printed. The payload is the static string content.
    Usage(&'static str),
    /// An error occurred, and a usage message should be printed.
    ErrorAndUsage { error: String, usage: &'static str },
}

/// Parses command-line arguments and executes the corresponding command.
///
/// # Errors
///
/// Returns a `crate::error::CliError` if opening the device, or executing the command fails.
pub fn execute_cli() -> Result<(), crate::error::CliError> {
    let parse_result = cli::parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {err}");
        eprintln!("\n{}", include_str!("usage.txt"));
        std::process::exit(2);
    });

    match parse_result {
        ParseResult::Help(content) => {
            print!("{content}");
            std::process::exit(0);
        }
        ParseResult::Usage(content) => {
            eprint!("{content}");
            std::process::exit(2);
        }
        ParseResult::ErrorAndUsage { error, usage } => {
            eprintln!("Error: {error}");
            eprintln!("\n{usage}");
            std::process::exit(2);
        }
        ParseResult::Command(cli) => {
            if let Some(command) = &cli.command {
                let device_arc = if command.is_local() {
                    None
                } else {
                    let file = std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&cli.device)
                        .map_err(|e| crate::error::CliError::File(cli.device.to_string(), e))?;
                    let device = crate::device::TpmDevice::new(file, cli.log_format);
                    Some(std::sync::Arc::new(std::sync::Mutex::new(device)))
                };

                let mut stdout = std::io::stdout();
                let mut context = crate::command::context::Context::new(&cli, &mut stdout);
                let result = command.run(device_arc.clone(), &mut context);

                context.flush(device_arc)?;

                if TEARDOWN.load(Ordering::Relaxed) {
                    std::process::exit(130);
                }

                result
            } else {
                print!("{}", include_str!("help.txt"));
                Ok(())
            }
        }
    }
}

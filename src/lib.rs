// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

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

use crate::{cli::Cli, device::TpmDevice, error::CliError};
use log::warn;
use std::{
    fmt,
    io::{self, Write},
    process,
    sync::{Arc, Mutex},
};
use tpm2_protocol::{message::TpmFlushContextCommand, TpmTransient};

pub struct Context<'a> {
    pub cli: &'a Cli,
    pub handles: Vec<(TpmTransient, bool)>,
    pub writer: &'a mut dyn Write,
}

impl fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Context")
            .field("cli", &self.cli)
            .field("handles", &self.handles)
            .field("writer", &"<dyn Write>")
            .finish()
    }
}

impl<'a> Context<'a> {
    #[must_use]
    pub fn new(cli: &'a Cli, writer: &'a mut dyn Write) -> Context<'a> {
        Self {
            cli,
            handles: Vec::new(),
            writer,
        }
    }
}

/// A trait for executing the top-level Commands enum.
pub trait Command {
    /// Returns `true` if the command does not require TPM device access.
    fn is_local(&self) -> bool;

    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(
        &self,
        device: Option<Arc<Mutex<TpmDevice>>>,
        context: &mut Context,
    ) -> Result<(), CliError>;
}

/// The result of parsing command-line arguments.
#[allow(clippy::large_enum_variant)]
pub enum ParseResult {
    /// A command was successfully parsed.
    Command(Cli),
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
/// Returns a `CliError` if opening the device, or executing the command fails.
pub fn execute_cli() -> Result<(), CliError> {
    let parse_result = cli::parse_args().unwrap_or_else(|err| {
        eprintln!("Error: {err}");
        eprintln!("\n{}", include_str!("usage.txt"));
        process::exit(2);
    });

    match parse_result {
        ParseResult::Help(content) => {
            print!("{content}");
            process::exit(0);
        }
        ParseResult::Usage(content) => {
            eprint!("{content}");
            process::exit(2);
        }
        ParseResult::ErrorAndUsage { error, usage } => {
            eprintln!("Error: {error}");
            eprintln!("\n{usage}");
            process::exit(2);
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
                        .map_err(|e| CliError::File(cli.device.to_string(), e))?;
                    let device = TpmDevice::new(file, cli.log_format);
                    Some(Arc::new(Mutex::new(device)))
                };

                let mut stdout = io::stdout();
                let mut context = Context::new(&cli, &mut stdout);
                let result = command.run(device_arc.clone(), &mut context);

                if let Some(device_arc) = device_arc {
                    let handles_to_flush: Vec<_> = context
                        .handles
                        .into_iter()
                        .filter(|&(_, should_flush)| should_flush)
                        .map(|(handle, _)| handle)
                        .collect();

                    if !handles_to_flush.is_empty() {
                        let mut guard = device_arc.lock().map_err(|_| {
                            CliError::Execution("TPM device lock poisoned".to_string())
                        })?;
                        for handle in handles_to_flush {
                            let cmd = TpmFlushContextCommand {
                                flush_handle: handle.into(),
                            };
                            if let Err(err) = guard.execute(&cmd, &[]) {
                                warn!(target: "cli::device", "tpm://{handle:#010x}: {err}");
                            }
                        }
                    }
                }
                result
            } else {
                print!("{}", include_str!("help.txt"));
                Ok(())
            }
        }
    }
}

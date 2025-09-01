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
pub mod pcr;
pub mod print;
pub mod session;
pub mod transport;
pub mod uri;
pub mod util;

use crate::{cli::Cli, device::TpmDevice, error::CliError};
use clap::{CommandFactory, Parser};
use std::{
    fs::OpenOptions,
    io::{self, Write},
    sync::{Arc, Mutex},
};

/// A trait for executing subcommands.
pub trait Command {
    /// Returns `true` if the command does not require TPM device access.
    fn is_local(&self) -> bool {
        false
    }

    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
        writer: &mut W,
    ) -> Result<(), CliError>;
}

/// Parses command-line arguments and executes the corresponding command.
///
/// # Errors
///
/// Returns a `CliError` if opening the device, or executing the command fails.
pub fn execute_cli() -> Result<(), CliError> {
    let cli = Cli::parse();

    if let Some(command) = &cli.command {
        let device_arc = if command.is_local() {
            None
        } else {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&cli.device)
                .map_err(|e| CliError::File(cli.device.to_string(), e))?;
            Some(Arc::new(Mutex::new(TpmDevice::new(file))))
        };
        command.run(&cli, device_arc, &mut io::stdout())
    } else {
        Cli::command()
            .help_template(cli::USAGE_TEMPLATE)
            .print_help()?;
        Ok(())
    }
}

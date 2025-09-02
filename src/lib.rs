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
use clap::{CommandFactory, Parser};
use log::warn;
use std::{
    fs::OpenOptions,
    io::{self, Write},
    sync::{Arc, Mutex},
};
use tpm2_protocol::{message::TpmFlushContextCommand, TpmTransient};

#[derive(Debug)]
pub struct Resources {
    pub handles: Vec<(TpmTransient, bool)>,
}

impl Resources {
    #[must_use]
    pub fn new(handles: Vec<(TpmTransient, bool)>) -> Self {
        Self { handles }
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
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
        writer: &mut W,
    ) -> Result<Resources, CliError>;
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
            let device = TpmDevice::new(file, cli.log_format);
            Some(Arc::new(Mutex::new(device)))
        };

        let resources = command.run(&cli, device_arc.clone(), &mut io::stdout())?;

        if let Some(device_arc) = device_arc {
            let handles_to_flush: Vec<_> = resources
                .handles
                .into_iter()
                .filter(|&(_, should_flush)| should_flush)
                .map(|(handle, _)| handle)
                .collect();

            if !handles_to_flush.is_empty() {
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
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
        Ok(())
    } else {
        Cli::command()
            .help_template(cli::USAGE_TEMPLATE)
            .print_help()?;
        Ok(())
    }
}

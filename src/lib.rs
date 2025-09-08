// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use crate::cli::Cli;
use anyhow::{Context, Result};
use std::sync::atomic::{AtomicBool, Ordering};

pub mod cli;
pub mod command;
pub mod context;
pub mod crypto;
pub mod device;
pub mod error;
pub mod key;
pub mod mocktpm;
pub mod policy;
pub mod print;
pub mod transport;
pub mod util;

pub use command::CommandError;
pub use device::TpmDeviceError;

/// A global flag to signal graceful teardown of the application.
///
/// Set by the Ctrl-C handler to allow the main loop to finish its current
/// operation and perform necessary cleanup (e.g., flushing TPM contexts)
/// before exiting.
pub static TEARDOWN: AtomicBool = AtomicBool::new(false);

/// Parses command-line arguments and executes the corresponding command.
///
/// # Errors
///
/// Returns a `crate::error::CliError` if opening the device, or executing the command fails.
pub fn execute_cli() -> Result<()> {
    let cli: Cli = argh::from_env();

    let command = &cli.command;
    let device_arc = if command.is_local() {
        None
    } else {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&cli.device)
            .with_context(|| format!("Failed to open '{}'", &cli.device))?;
        let device = crate::device::TpmDevice::new(file, cli.log_format);
        Some(std::sync::Arc::new(std::sync::Mutex::new(device)))
    };

    let mut stdout = std::io::stdout();
    let mut context = crate::context::Context::new(&mut stdout);
    let result = command.run(device_arc.as_ref(), &mut context);

    context.flush(device_arc)?;

    if TEARDOWN.load(Ordering::Relaxed) {
        std::process::exit(130);
    }

    result
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

pub mod arg_parser;
pub mod cli;
pub mod command;
pub mod command_io;
pub mod crypto;
pub mod device;
pub mod error;
pub mod key;
pub mod pcr;
pub mod pretty_printer;
pub mod schema;
pub mod session;
pub mod uri;
pub mod util;

pub use self::arg_parser::parse_cli;
pub use self::command_io::{CommandIo, ScopedHandle};
pub use self::crypto::*;
pub use self::device::*;
pub use self::error::TpmError;
pub use self::key::*;
pub use self::pcr::*;
pub use self::pretty_printer::PrettyTrace;
pub use self::schema::*;
pub use self::session::*;
pub use self::uri::*;
pub use self::util::*;
use once_cell::sync::{Lazy, OnceCell};
use std::{
    fs::OpenOptions,
    io::{IsTerminal, Read, Write},
    sync::{Arc, Mutex},
};
use threadpool::ThreadPool;

pub static POOL: Lazy<ThreadPool> = Lazy::new(|| ThreadPool::new(4));
pub static LOG_FORMAT: OnceCell<cli::LogFormat> = OnceCell::new();

/// Safely accesses the global `LOG_FORMAT` static, falling back to the default.
pub(crate) fn get_log_format() -> cli::LogFormat {
    *LOG_FORMAT.get().unwrap_or(&cli::LogFormat::default())
}

/// Describes the role a command plays in the JSON pipeline.
pub enum CommandType {
    /// Does not interact with the JSON pipeline. Prints human-readable text.
    Standalone,
    /// Creates new objects for a pipeline, but does not consume any.
    Source,
    /// Consumes and produces objects, acting as a pipeline transformer.
    Pipe,
    /// Consumes objects and terminates the pipeline with non-JSON output.
    Sink,
}

/// A trait for parsing and executing subcommands.
pub trait Command {
    /// Returns the command's role in the pipeline.
    fn command_type(&self) -> CommandType;

    /// Prints the help message for a subcommand.
    fn help()
    where
        Self: Sized;

    /// Parses the arguments for a subcommand.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on parsing failure.
    fn parse(parser: &mut lexopt::Parser) -> Result<cli::Commands, TpmError>
    where
        Self: Sized;

    /// Returns `true` if the command does not require TPM device access.
    fn is_local(&self) -> bool {
        false
    }

    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), TpmError>;
}

/// Parses command-line arguments and executes the corresponding command.
///
/// # Errors
///
/// Returns a `TpmError` if opening the device, or executing the command fails.
pub fn execute_cli() -> Result<(), TpmError> {
    let Some(cli) = parse_cli()? else {
        return Ok(());
    };

    if let Some(command) = cli.command {
        let _ = LOG_FORMAT.set(cli.log_format);

        let device_arc = if command.is_local() {
            None
        } else {
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(&cli.device)
                .map_err(|e| TpmError::File(cli.device.to_string(), e))?;
            Some(Arc::new(Mutex::new(TpmDevice::new(file))))
        };

        let stdin = std::io::stdin();
        let is_tty = stdin.is_terminal();
        let mut io = CommandIo::new(stdin, std::io::stdout(), is_tty);
        let cmd_type = command.command_type();
        command.run(&mut io, device_arc)?;

        match cmd_type {
            CommandType::Standalone => Ok(()),
            _ => io.finalize(),
        }
    } else {
        Ok(())
    }
}

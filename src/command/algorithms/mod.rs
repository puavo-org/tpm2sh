// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, DeviceCommand, Subcommand},
    CliError, Context, TpmDevice,
};
use lexopt::Parser;

#[derive(Debug, Default)]
pub struct Algorithms;

impl Subcommand for Algorithms {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        while let Some(arg) = parser.next()? {
            handle_help(arg)?;
        }
        Ok(Algorithms)
    }
}

impl DeviceCommand for Algorithms {
    /// Runs `algorithms`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let mut algorithms = device.get_all_algorithms()?;
        algorithms.sort_by(|a, b| a.1.cmp(&b.1));
        for (_, name) in algorithms {
            writeln!(context.writer, "{name}")?;
        }
        Ok(())
    }
}

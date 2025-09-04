// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
};
use lexopt::Parser;
use tpm2_protocol::data::TpmRh;

#[derive(Debug, Default)]
pub struct Objects;

impl Subcommand for Objects {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        while let Some(arg) = parser.next()? {
            handle_help(arg)?;
        }
        Ok(Objects)
    }
}

impl DeviceCommand for Objects {
    /// Runs `objects`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let transient_handles = device.get_all_handles(TpmRh::TransientFirst)?;
        for handle in transient_handles {
            writeln!(context.writer, "tpm://{handle:#010x}")?;
        }
        let persistent_handles = device.get_all_handles(TpmRh::PersistentFirst)?;
        for handle in persistent_handles {
            writeln!(context.writer, "tpm://{handle:#010x}")?;
        }
        Ok(())
    }
}

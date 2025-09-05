// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{parse_no_args, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
};
use lexopt::Parser;
use tpm2_protocol::data::{TPM_RH_PERSISTENT_FIRST, TPM_RH_TRANSIENT_FIRST};

#[derive(Debug, Default)]
pub struct Objects;

impl Subcommand for Objects {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        parse_no_args(parser)
    }
}

impl DeviceCommand for Objects {
    /// Runs `objects`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let transient_handles = device.get_all_handles(TPM_RH_TRANSIENT_FIRST)?;
        for handle in transient_handles {
            writeln!(context.writer, "tpm://{handle:#010x}")?;
        }
        let persistent_handles = device.get_all_handles(TPM_RH_PERSISTENT_FIRST)?;
        for handle in persistent_handles {
            writeln!(context.writer, "tpm://{handle:#010x}")?;
        }
        Ok(())
    }
}

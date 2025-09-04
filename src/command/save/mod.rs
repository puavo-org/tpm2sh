// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    uri::Uri,
};
use lexopt::{Arg, Parser, ValueExt};

use tpm2_protocol::TpmPersistent;

#[derive(Debug, Default)]
pub struct Save {
    pub to_uri: Uri,
    pub in_uri: Uri,
}

impl Subcommand for Save {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut to_uri = None;
        let mut in_uri = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("to-uri") => to_uri = Some(parser.value()?.parse()?),
                Arg::Long("in") => in_uri = Some(parser.value()?.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Save {
            to_uri: required(to_uri, "--to-uri")?,
            in_uri: required(in_uri, "--in")?,
        })
    }
}

impl DeviceCommand for Save {
    /// Runs `save`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let object_handle = context.load(device, &self.in_uri)?;
        let persistent_handle = TpmPersistent(self.to_uri.to_tpm_handle()?);
        context.evict(device, object_handle, persistent_handle)?;
        writeln!(context.writer, "tpm://{persistent_handle:#010x}")?;
        Ok(())
    }
}

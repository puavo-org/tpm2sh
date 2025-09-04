// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    session::session_from_args,
    uri::Uri,
};
use lexopt::{Arg, Parser, ValueExt};
use tpm2_protocol::message::TpmUnsealCommand;

#[derive(Debug, Default)]
pub struct Unseal {
    pub handle: Uri,
}

impl Subcommand for Unseal {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut handle = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("handle") => handle = Some(parser.value()?.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Unseal {
            handle: required(handle, "--handle")?,
        })
    }
}

impl DeviceCommand for Unseal {
    /// Runs `unseal`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let object_handle = context.load(device, &self.handle)?;
        let unseal_cmd = TpmUnsealCommand {
            item_handle: object_handle.0.into(),
        };
        let unseal_handles = [object_handle.into()];
        let unseal_sessions = session_from_args(&unseal_cmd, &unseal_handles, context.cli)?;
        let (_rc, unseal_resp, _) = device.execute(&unseal_cmd, &unseal_sessions)?;
        let unseal_resp = unseal_resp
            .Unseal()
            .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
        context.writer.write_all(&unseal_resp.out_data)?;
        Ok(())
    }
}

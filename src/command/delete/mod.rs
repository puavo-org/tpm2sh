// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    uri::Uri,
};
use lexopt::{Arg, Parser, ValueExt};
use tpm2_protocol::{data::TpmRh, TpmPersistent, TpmTransient};

#[derive(Debug, Default)]
pub struct Delete {
    pub handle: Uri,
}

impl Subcommand for Delete {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut handle = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if handle.is_none() => handle = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Delete {
            handle: required(handle, "<URI>")?,
        })
    }
}

impl DeviceCommand for Delete {
    /// Runs `delete`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let handle = self.handle.to_tpm_handle()?;

        if handle >= TpmRh::PersistentFirst as u32 {
            context.delete_persistent(device, TpmPersistent(handle))?;
        } else if handle >= TpmRh::TransientFirst as u32 {
            context.delete_transient(device, TpmTransient(handle))?;
        } else {
            return Err(CliError::InvalidHandleType { handle });
        }

        writeln!(context.writer, "tpm://{handle:#010x}")?;
        Ok(())
    }
}

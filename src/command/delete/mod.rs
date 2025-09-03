// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    uri::Uri,
    CliError, Context, TpmDevice,
};
use lexopt::{Arg, Parser, ValueExt};
use tpm2_protocol::{data::TpmRh, message::TpmFlushContextCommand, TpmPersistent, TpmTransient};

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
            handle: required(handle, "<HANDLE>")?,
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
            let persistent_handle = TpmPersistent(handle);
            device.evict_control(context.cli, handle, persistent_handle)?;
            writeln!(
                context.writer,
                "Deleted handle tpm://{persistent_handle:#010x}"
            )?;
        } else if handle >= TpmRh::TransientFirst as u32 {
            let flush_handle = TpmTransient(handle);
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: flush_handle.into(),
            };
            let (resp, _) = device.execute(&flush_cmd, &[])?;
            resp.FlushContext()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            writeln!(context.writer, "Deleted handle tpm://{flush_handle:#010x}")?;
        } else {
            return Err(CliError::InvalidHandle(format!(
                "'{handle:#010x}' is not a transient or persistent handle"
            )));
        }
        Ok(())
    }
}

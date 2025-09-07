// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, parse_session_option, required, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    uri::Uri,
};
use lexopt::{Arg, Parser, ValueExt};

#[derive(Debug, Default)]
pub struct Delete {
    pub handle: Uri,
    pub session: Option<Uri>,
}

impl Subcommand for Delete {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");
    const OPTION_SESSION: bool = true;

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut handle = None;
        let mut session = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("session") => parse_session_option(parser, &mut session)?,
                Arg::Value(val) if handle.is_none() => handle = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Delete {
            handle: required(handle, "<URI>")?,
            session,
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
        let handle = context.delete(device, &self.handle, self.session.as_ref())?;
        writeln!(context.writer, "tpm://{handle:#010x}")?;
        Ok(())
    }
}

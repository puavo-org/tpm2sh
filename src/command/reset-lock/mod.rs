// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, parse_session_option, DeviceCommand, Subcommand},
    command::context::Context,
    device::{TpmDevice, TpmDeviceError},
    error::CliError,
    session::session_from_uri,
    uri::Uri,
};
use lexopt::{Arg, Parser};
use tpm2_protocol::{data::TpmCc, data::TpmRh, message::TpmDictionaryAttackLockResetCommand};

#[derive(Debug, Default)]
pub struct ResetLock {
    pub session: Option<Uri>,
}

impl Subcommand for ResetLock {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");
    const OPTION_SESSION: bool = true;

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut session = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("session") => parse_session_option(parser, &mut session)?,
                _ => return handle_help(arg),
            }
        }
        Ok(ResetLock { session })
    }
}

impl DeviceCommand for ResetLock {
    /// Runs `reset-lock`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, _context: &mut Context) -> Result<(), CliError> {
        let command = TpmDictionaryAttackLockResetCommand {
            lock_handle: (TpmRh::Lockout as u32).into(),
        };
        let handles = [TpmRh::Lockout as u32];
        let sessions = session_from_uri(&command, &handles, self.session.as_ref())?;
        let (_rc, resp, _) = device.execute(&command, &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::DictionaryAttackLockReset,
            })?;
        Ok(())
    }
}

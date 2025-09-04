// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    session::session_from_args,
};
use lexopt::Parser;
use tpm2_protocol::{data::TpmRh, message::TpmDictionaryAttackLockResetCommand};

#[derive(Debug, Default)]
pub struct ResetLock;

impl Subcommand for ResetLock {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        while let Some(arg) = parser.next()? {
            handle_help(arg)?;
        }
        Ok(ResetLock)
    }
}

impl DeviceCommand for ResetLock {
    /// Runs `reset-lock`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let command = TpmDictionaryAttackLockResetCommand {
            lock_handle: (TpmRh::Lockout as u32).into(),
        };
        let handles = [TpmRh::Lockout as u32];
        let sessions = session_from_args(&command, &handles, context.cli)?;
        let (resp, _) = device.execute(&command, &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
        Ok(())
    }
}

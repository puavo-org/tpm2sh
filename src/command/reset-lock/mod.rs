// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{parse_no_args, DeviceCommand, Subcommand},
    command::context::Context,
    device::{TpmDevice, TpmDeviceError},
    error::CliError,
    session::session_from_args,
};
use lexopt::Parser;
use tpm2_protocol::{data::TpmCc, data::TpmRh, message::TpmDictionaryAttackLockResetCommand};

#[derive(Debug, Default)]
pub struct ResetLock;

impl Subcommand for ResetLock {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        parse_no_args(parser)
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
        let (_rc, resp, _) = device.execute(&command, &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::DictionaryAttackLockReset,
            })?;
        Ok(())
    }
}

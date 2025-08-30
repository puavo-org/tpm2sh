// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineOption},
    cli::{Commands, ResetLock},
    get_auth_sessions, CliError, Command, CommandIo, CommandType, TpmDevice,
};
use lexopt::prelude::*;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::{data::TpmRh, message::TpmDictionaryAttackLockResetCommand};

const ABOUT: &str = "Resets the dictionary attack lockout timer";
const USAGE: &str = "tpm2sh reset-lock [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[(
    None,
    "--password",
    "<PASSWORD>",
    "Authorization value for the Lockout hierarchy",
)];

impl Command for ResetLock {
    fn command_type(&self) -> CommandType {
        CommandType::Sink
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("reset-lock", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = ResetLock::default();
        arguments!(parser, arg, Self::help, {
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        Ok(Commands::ResetLock(args))
    }

    /// Runs `reset-lock`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        _io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let command = TpmDictionaryAttackLockResetCommand {
            lock_handle: (TpmRh::Lockout as u32).into(),
        };
        let handles = [TpmRh::Lockout as u32];
        let sessions =
            get_auth_sessions(&command, &handles, None, self.password.password.as_deref())?;
        let (resp, _) = chip.execute(&command, &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        println!("Dictionary attack lockout has been reset.");
        Ok(())
    }
}

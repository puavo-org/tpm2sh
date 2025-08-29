// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, ResetLock},
    get_auth_sessions, parse_args, Command, CommandIo, CommandType, TpmDevice, TpmError,
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

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = ResetLock::default();
        parse_args!(parser, arg, Self::help, {
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::ResetLock(args))
    }

    /// Runs `reset-lock`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        _io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), TpmError> {
        let device_arc =
            device.ok_or_else(|| TpmError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| TpmError::Execution("TPM device lock poisoned".to_string()))?;

        let command = TpmDictionaryAttackLockResetCommand {
            lock_handle: (TpmRh::Lockout as u32).into(),
        };
        let handles = [TpmRh::Lockout as u32];
        let sessions =
            get_auth_sessions(&command, &handles, None, self.password.password.as_deref())?;
        let (resp, _) = chip.execute(&command, &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        println!("Dictionary attack lockout has been reset.");
        Ok(())
    }
}

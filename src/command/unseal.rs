// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, Unseal},
    get_auth_sessions, parse_args, CliError, Command, CommandIo, CommandType, TpmDevice,
};
use lexopt::prelude::*;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::message::TpmUnsealCommand;

const ABOUT: &str = "Unseals a secret from a loaded TPM object";
const USAGE: &str = "tpm2sh unseal [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[(
    None,
    "--password",
    "<PASSWORD>",
    "Authorization value for the sealed object",
)];

impl Command for Unseal {
    fn command_type(&self) -> CommandType {
        CommandType::Sink
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("unseal", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = Unseal::default();
        parse_args!(parser, arg, Self::help, {
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Unseal(args))
    }

    /// Runs `unseal`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;

        let sealed_tpm_obj = io.pop_tpm()?;
        let object_handle_guard = io.resolve_tpm_context(device_arc.clone(), &sealed_tpm_obj)?;
        let object_handle = object_handle_guard.handle();

        let unseal_cmd = TpmUnsealCommand {
            item_handle: object_handle.0.into(),
        };
        let unseal_handles = [object_handle.into()];
        let unseal_sessions = get_auth_sessions(
            &unseal_cmd,
            &unseal_handles,
            None,
            self.password.password.as_deref(),
        )?;

        let (unseal_resp, _) = {
            let mut chip = device_arc
                .lock()
                .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
            chip.execute(&unseal_cmd, &unseal_sessions)?
        };
        let unseal_resp = unseal_resp
            .Unseal()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        io.writer().write_all(&unseal_resp.out_data)?;
        Ok(())
    }
}

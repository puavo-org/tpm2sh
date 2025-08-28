// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, Unseal},
    get_auth_sessions, get_tpm_device, parse_args, Command, CommandIo, CommandType, TpmError,
};
use lexopt::prelude::*;
use std::io::{Read, Write};
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

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Unseal::default();
        parse_args!(parser, arg, Self::help, {
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Unseal(args))
    }

    /// Runs `unseal`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run<R: Read, W: Write>(&self, io: &mut CommandIo<R, W>) -> Result<(), TpmError> {
        let mut chip = get_tpm_device()?;

        let sealed_tpm_obj = io.pop_tpm()?;
        let object_handle_guard = io.resolve_tpm_context(&mut chip, &sealed_tpm_obj)?;
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

        let (unseal_resp, _) = chip.execute(&unseal_cmd, &unseal_sessions)?;
        let unseal_resp = unseal_resp
            .Unseal()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        io.writer().write_all(&unseal_resp.out_data)?;
        Ok(())
    }
}

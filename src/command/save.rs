// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Commands, Save},
    get_auth_sessions, get_tpm_device, parse_args, parse_tpm_handle_from_uri, Command, CommandIo,
    CommandType, PipelineObject, Tpm, TpmError,
};
use lexopt::prelude::*;
use std::io::{Read, Write};
use tpm2_protocol::{data::TpmRh, message::TpmEvictControlCommand, TpmPersistent};

const ABOUT: &str = "Saves a transient object to non-volatile memory";
const USAGE: &str = "tpm2sh save --to <HANDLE_URI> [OPTIONS]";
const ARGS: &[CommandLineArgument] = &[];
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--to",
        "<HANDLE_URI>",
        "URI for the persistent object to be created (e.g., 'tpm://0x81000001')",
    ),
    (
        None,
        "--password",
        "<PASSWORD>",
        "Authorization value for the Owner hierarchy",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Save {
    fn command_type(&self) -> CommandType {
        CommandType::Pipe
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("save", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Save::default();
        parse_args!(parser, arg, Self::help, {
            Long("to") => {
                args.to_uri = Some(parser.value()?.string()?);
            }
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });

        if args.to_uri.is_none() {
            return Err(TpmError::Usage(
                "Missing required argument: --to <HANDLE_URI>".to_string(),
            ));
        }

        Ok(Commands::Save(args))
    }

    /// Runs `save`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run<R: Read, W: Write>(&self, io: &mut CommandIo<R, W>) -> Result<(), TpmError> {
        let mut chip = get_tpm_device()?;

        let object_to_save = io.pop_tpm()?;
        let object_handle_guard = io.resolve_tpm_context(&mut chip, &object_to_save)?;
        let object_handle = object_handle_guard.handle();

        let persistent_handle =
            TpmPersistent(parse_tpm_handle_from_uri(self.to_uri.as_ref().unwrap())?);
        let auth_handle = TpmRh::Owner;
        let handles = [auth_handle as u32, object_handle.into()];

        let evict_cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: object_handle.0.into(),
            persistent_handle,
        };
        let sessions = get_auth_sessions(
            &evict_cmd,
            &handles,
            None,
            self.password.password.as_deref(),
        )?;
        let (resp, _) = chip.execute(&evict_cmd, &sessions)?;
        resp.EvictControl()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        let persistent_tpm_object = Tpm {
            context: format!("tpm://{persistent_handle:#010x}"),
            parent: object_to_save.parent,
        };

        io.push_object(PipelineObject::Tpm(persistent_tpm_object));
        Ok(())
    }
}

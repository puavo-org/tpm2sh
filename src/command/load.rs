// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Load},
    get_auth_sessions, get_tpm_device, parse_args,
    util::pop_object_data,
    Command, CommandIo, CommandType, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use std::io;
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::TpmLoadCommand,
    TpmParse,
};

const ABOUT: &str = "Loads a TPM key";
const USAGE: &str = "tpm2sh load [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--parent-password",
        "<PASSWORD>",
        "Authorization for the parent object",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Load {
    fn command_type(&self) -> CommandType {
        CommandType::Pipe
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("load", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Load::default();
        parse_args!(parser, arg, Self::help, {
            Long("parent-password") => {
                args.parent_password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Load(args))
    }

    /// Runs `load`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self) -> Result<(), TpmError> {
        let mut chip = get_tpm_device()?;
        let mut io = CommandIo::new(io::stdout())?;
        let session = io.take_session()?;

        let parent_handle_guard = io.consume_handle()?;
        let parent_handle = parent_handle_guard.handle();

        let object_data = pop_object_data(&mut io)?;

        let pub_bytes = base64_engine
            .decode(object_data.public)
            .map_err(|e| TpmError::Parse(e.to_string()))?;
        let priv_bytes = base64_engine
            .decode(object_data.private)
            .map_err(|e| TpmError::Parse(e.to_string()))?;

        let (in_public, _) = Tpm2bPublic::parse(&pub_bytes)?;
        let (in_private, _) = Tpm2bPrivate::parse(&priv_bytes)?;

        let load_cmd = TpmLoadCommand {
            parent_handle: parent_handle.0.into(),
            in_private,
            in_public,
        };

        let handles = [parent_handle.into()];
        let sessions = get_auth_sessions(
            &load_cmd,
            &handles,
            session.as_ref(),
            self.parent_password.password.as_deref(),
        )?;

        let (resp, _) = chip.execute(&load_cmd, &sessions)?;
        let load_resp = resp
            .Load()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        let new_object = cli::Object::Handle(load_resp.object_handle.into());
        io.push_object(new_object);

        io.finalize()
    }
}

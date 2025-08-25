// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, Unseal},
    command_io::ScopedHandle,
    get_auth_sessions, get_tpm_device, parse_args, pop_object_data, Command, CommandIo,
    CommandType, ObjectData, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use std::io::{self, Write};
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::{TpmLoadCommand, TpmUnsealCommand},
    TpmParse, TpmTransient,
};

const ABOUT: &str = "Unseals a keyedhash object";
const USAGE: &str = "tpm2sh unseal [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (None, "--password", "<PASSWORD>", "Authorization value"),
    (Some("-h"), "--help", "", "Print help information"),
];

/// Parses a parent handle from a hex string in the loaded object data.
///
/// # Errors
///
/// Returns a `TpmError::Parse` if the hex string is invalid.
fn parse_parent_handle_from_json(object_data: &ObjectData) -> Result<TpmTransient, TpmError> {
    u32::from_str_radix(object_data.parent.trim_start_matches("0x"), 16)
        .map_err(TpmError::from)
        .map(TpmTransient)
}

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
    fn run(&self) -> Result<(), TpmError> {
        let mut chip = get_tpm_device()?;
        let mut io = CommandIo::new(io::stdout())?;
        let session = io.take_session()?;
        let object_data = pop_object_data(&mut io)?;

        let parent_handle = parse_parent_handle_from_json(&object_data)?;

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
        let parent_handles = [parent_handle.into()];
        let parent_sessions = get_auth_sessions(
            &load_cmd,
            &parent_handles,
            session.as_ref(),
            self.password.password.as_deref(),
        )?;
        let (load_resp, _) = chip.execute(&load_cmd, &parent_sessions)?;
        let load_resp = load_resp
            .Load()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
        let object_handle = load_resp.object_handle;

        let _object_handle_guard = ScopedHandle::new(object_handle);

        let unseal_cmd = TpmUnsealCommand {
            item_handle: object_handle.0.into(),
        };
        let unseal_handles = [object_handle.into()];
        let unseal_sessions = get_auth_sessions(
            &unseal_cmd,
            &unseal_handles,
            session.as_ref(),
            self.password.password.as_deref(),
        )?;

        let (unseal_resp, _) = chip.execute(&unseal_cmd, &unseal_sessions)?;
        let unseal_resp = unseal_resp
            .Unseal()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        io::stdout().write_all(&unseal_resp.out_data)?;
        Ok(())
    }
}

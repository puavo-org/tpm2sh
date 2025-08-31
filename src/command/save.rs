// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Cli, Commands, Save},
    pipeline::{CommandIo, Entry as PipelineEntry, Tpm as PipelineTpm},
    session::get_sessions_from_args,
    uri::uri_to_tpm_handle,
    CliError, Command, CommandType, TpmDevice,
};
use lexopt::prelude::*;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
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

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = Save::default();
        arguments!(parser, arg, Self::help, {
            Long("to") => {
                args.to_uri = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });

        if args.to_uri.is_none() {
            return Err(CliError::Usage(
                "Missing required argument: --to <HANDLE_URI>".to_string(),
            ));
        }

        Ok(Commands::Save(args))
    }

    /// Runs `save`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;

        let object_to_save = io.pop_tpm()?;
        let object_handle_guard = io.resolve_tpm_context(device_arc.clone(), &object_to_save)?;
        let object_handle = object_handle_guard.handle();

        let persistent_handle = TpmPersistent(uri_to_tpm_handle(self.to_uri.as_ref().unwrap())?);
        let auth_handle = TpmRh::Owner;
        let handles = [auth_handle as u32, object_handle.into()];

        let evict_cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: object_handle.0.into(),
            persistent_handle,
        };
        let sessions = get_sessions_from_args(io, &evict_cmd, &handles, cli)?;
        let (resp, _) = {
            let mut chip = device_arc
                .lock()
                .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
            chip.execute(&evict_cmd, &sessions)?
        };
        resp.EvictControl()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        object_handle_guard.forget();

        let pipeline_tpm = PipelineTpm {
            context: format!("tpm://{persistent_handle:#010x}"),
            parent: object_to_save.parent,
        };

        io.push_object(PipelineEntry::Tpm(pipeline_tpm));
        Ok(())
    }
}

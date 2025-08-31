// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{collect_values, format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Cli, Commands, PcrEvent},
    parse_tpm_handle_from_uri,
    pipeline::CommandIo,
    resolve_uri_to_bytes,
    session::get_sessions_from_args,
    CliError, Command, CommandType, TpmDevice,
};

use std::{
    io::{Read, Write},
    sync::{Arc, Mutex},
};

use tpm2_protocol::{data::Tpm2bEvent, message::TpmPcrEventCommand};

const ABOUT: &str = "Extends a PCR with an event";
const USAGE: &str = "tpm2sh pcr-event [OPTIONS] <PCR_HANDLE_URI> <DATA_URI>";
const ARGS: &[CommandLineArgument] = &[
    (
        "PCR_HANDLE_URI",
        "URI of the PCR to extend (e.g., 'tpm://0x01')",
    ),
    (
        "DATA_URI",
        "URI of the data to extend with (e.g., 'data://hex,deadbeef')",
    ),
];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for PcrEvent {
    fn command_type(&self) -> CommandType {
        CommandType::Sink
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("pcr-event", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = PcrEvent::default();
        arguments!(parser, arg, Self::help, {
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        let values = collect_values(parser)?;
        if values.len() != 2 {
            return Err(CliError::Usage(format!(
                "'pcr-event' requires 2 arguments, but {} were provided",
                values.len()
            )));
        }
        let mut values_iter = values.into_iter();
        args.handle_uri = values_iter
            .next()
            .ok_or_else(|| CliError::Execution("value missing".to_string()))?;
        args.data_uri = values_iter
            .next()
            .ok_or_else(|| CliError::Execution("value missing".to_string()))?;
        Ok(Commands::PcrEvent(args))
    }

    /// Runs `pcr-event`.
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
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let pcr_handle = parse_tpm_handle_from_uri(&self.handle_uri)?;
        let handles = [pcr_handle];

        let data_bytes = resolve_uri_to_bytes(&self.data_uri, &[])?;
        let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
        let command = TpmPcrEventCommand {
            pcr_handle,
            event_data,
        };

        let sessions = get_sessions_from_args(io, &command, &handles, cli)?;
        let (resp, _) = chip.execute(&command, &sessions)?;
        resp.PcrEvent()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        writeln!(io.writer(), "Extended PCR {pcr_handle:#0x}")?;

        Ok(())
    }
}

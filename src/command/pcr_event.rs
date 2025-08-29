// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Commands, PcrEvent},
    get_auth_sessions, parse_args, parse_tpm_handle_from_uri, resolve_uri_to_bytes, Command,
    CommandIo, CommandType, TpmDevice, TpmError,
};
use lexopt::prelude::*;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
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
const OPTIONS: &[CommandLineOption] = &[
    (None, "--password", "<PASSWORD>", "Authorization value"),
    (Some("-h"), "--help", "", "Print help information"),
];

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

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = PcrEvent::default();
        let mut handle_uri_arg = None;
        let mut data_uri_arg = None;
        parse_args!(parser, arg, Self::help, {
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            Value(val) if handle_uri_arg.is_none() => {
                handle_uri_arg = Some(val.string()?);
            }
            Value(val) if data_uri_arg.is_none() => {
                data_uri_arg = Some(val.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });

        if let (Some(handle_uri), Some(data_uri)) = (handle_uri_arg, data_uri_arg) {
            args.handle_uri = handle_uri;
            args.data_uri = data_uri;
            Ok(Commands::PcrEvent(args))
        } else {
            Err(TpmError::Usage(
                "Missing required arguments: <PCR_HANDLE_URI> <DATA_URI>".to_string(),
            ))
        }
    }

    /// Runs `pcr-event`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), TpmError> {
        let device_arc =
            device.ok_or_else(|| TpmError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| TpmError::Execution("TPM device lock poisoned".to_string()))?;

        let pcr_handle = parse_tpm_handle_from_uri(&self.handle_uri)?;
        let handles = [pcr_handle];

        let data_bytes = resolve_uri_to_bytes(&self.data_uri, &[])?;
        let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
        let command = TpmPcrEventCommand {
            pcr_handle,
            event_data,
        };

        let sessions =
            get_auth_sessions(&command, &handles, None, self.password.password.as_deref())?;
        let (resp, _) = chip.execute(&command, &sessions)?;
        resp.PcrEvent()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        writeln!(io.writer(), "Extended PCR {pcr_handle:#0x}")?;

        Ok(())
    }
}

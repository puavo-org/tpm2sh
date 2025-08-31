// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments::{collect_values, format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Cli, Commands, PcrEvent},
    session::session_from_args,
    uri::uri_to_bytes,
    util::parse_pcr_uri,
    CliError, Command, TpmDevice,
};

use std::io::Write;
use std::sync::{Arc, Mutex};

use tpm2_protocol::{data::Tpm2bEvent, message::TpmPcrEventCommand};

const ABOUT: &str = "Extends a PCR with an event";
const USAGE: &str = "tpm2sh pcr-event [OPTIONS] <PCR_URI> <DATA_URI>";
const ARGS: &[CommandLineArgument] = &[
    ("PCR_URI", "PCR to extend (e.g., 'pcr://sha256,7')"),
    ("DATA_URI", "URI of the data (e.g., 'data://hex,deadbeef')"),
];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for PcrEvent {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("pcr-event", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = PcrEvent::default();
        let values = collect_values(parser)?;
        if values.len() != 2 {
            return Err(CliError::Usage(format!(
                "'pcr-event' requires 2 arguments, but {} were provided",
                values.len()
            )));
        }
        let mut values_iter = values.into_iter();
        args.pcr_uri = values_iter
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
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
        _writer: &mut W,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let (_bank, pcr_index) = parse_pcr_uri(&self.pcr_uri)?;

        let handles = [pcr_index];
        let data_bytes = uri_to_bytes(&self.data_uri, &[])?;
        let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
        let command = TpmPcrEventCommand {
            pcr_handle: handles[0],
            event_data,
        };
        let sessions = session_from_args(&command, &handles, cli)?;
        let (resp, _) = chip.execute(&command, &sessions)?;
        resp.PcrEvent()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        Ok(())
    }
}

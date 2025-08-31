// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{collect_values, format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Cli, Commands, PcrRead},
    get_pcr_count, parse_pcr_selection, pcr_response_to_output,
    pipeline::{CommandIo, Entry as PipelineEntry},
    CliError, Command, CommandType, TpmDevice,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::message::TpmPcrReadCommand;

const ABOUT: &str = "Reads PCR values from the TPM";
const USAGE: &str = "tpm2sh pcr-read <SELECTION>";
const ARGS: &[CommandLineArgument] = &[("SELECTION", "e.g. 'sha256:0,1,2+sha1:0'")];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for PcrRead {
    fn command_type(&self) -> CommandType {
        CommandType::Source
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("pcr-read", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        arguments!(parser, arg, Self::help, {
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        let values = collect_values(parser)?;
        if values.len() != 1 {
            return Err(CliError::Usage(format!(
                "'pcr-read' requires 1 argument, but {} were provided",
                values.len()
            )));
        }
        let selection = values
            .into_iter()
            .next()
            .ok_or_else(|| CliError::Execution("value missing".to_string()))?;
        Ok(Commands::PcrRead(PcrRead { selection }))
    }

    /// Runs `pcr-read`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        _cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        io.clear_input()?;
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let pcr_count = get_pcr_count(&mut chip)?;
        let pcr_selection_in = parse_pcr_selection(&self.selection, pcr_count)?;

        let cmd = TpmPcrReadCommand { pcr_selection_in };
        let (resp, _) = chip.execute(&cmd, &[])?;
        let pcr_read_resp = resp
            .PcrRead()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let pcr_output = pcr_response_to_output(&pcr_read_resp)?;

        io.push_object(PipelineEntry::PcrValues(pcr_output));
        Ok(())
    }
}

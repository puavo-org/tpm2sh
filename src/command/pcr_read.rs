// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments::{collect_values, format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Cli, Commands, PcrRead},
    pcr::{pcr_get_count, pcr_parse_selection, pcr_to_values},
    CliError, Command, TpmDevice,
};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::message::TpmPcrReadCommand;

const ABOUT: &str = "Reads PCR values from the TPM";
const USAGE: &str = "tpm2sh pcr-read <SELECTION>";
const ARGS: &[CommandLineArgument] = &[("SELECTION", "e.g. 'sha256:0,1,2+sha1:0'")];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for PcrRead {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("pcr-read", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
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
    fn run<W: Write>(
        &self,
        _cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
        writer: &mut W,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
        let pcr_count = pcr_get_count(&mut chip)?;
        let pcr_selection_in = pcr_parse_selection(&self.selection, pcr_count)?;
        let cmd = TpmPcrReadCommand { pcr_selection_in };
        let (resp, _) = chip.execute(&cmd, &[])?;
        let pcr_read_resp = resp
            .PcrRead()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let pcr_values = pcr_to_values(&pcr_read_resp)?;
        for (pcr_alg, pcr_bank_values) in &pcr_values.banks {
            for (pcr_index, pcr_value) in pcr_bank_values {
                writeln!(writer, "pcr://{pcr_alg},{pcr_index},{pcr_value}")?;
            }
        }
        Ok(())
    }
}

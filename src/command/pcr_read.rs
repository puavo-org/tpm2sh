// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Commands, Object, PcrRead},
    get_pcr_count, get_tpm_device, parse_args, parse_pcr_selection, pcr_response_to_output,
    Command, CommandIo, CommandType, TpmError,
};
use lexopt::prelude::*;
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

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut selection = None;
        parse_args!(parser, arg, Self::help, {
            Value(val) if selection.is_none() => {
                selection = Some(val.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });

        if let Some(selection) = selection {
            Ok(Commands::PcrRead(PcrRead { selection }))
        } else {
            Err(TpmError::Usage(
                "Missing required argument: <SELECTION>".to_string(),
            ))
        }
    }

    /// Runs `pcr-read`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self) -> Result<(), TpmError> {
        let mut chip = get_tpm_device()?;
        let mut io = CommandIo::new(std::io::stdout())?;
        let pcr_count = get_pcr_count(&mut chip)?;
        let pcr_selection_in = parse_pcr_selection(&self.selection, pcr_count)?;

        let cmd = TpmPcrReadCommand { pcr_selection_in };
        let (resp, _) = chip.execute(&cmd, &[])?;
        let pcr_read_resp = resp
            .PcrRead()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
        let pcr_output = pcr_response_to_output(&pcr_read_resp)?;

        io.push_object(Object::PcrValues(pcr_output));
        io.finalize()
    }
}

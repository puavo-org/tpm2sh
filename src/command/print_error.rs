// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{collect_values, format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Cli, Commands, PrintError},
    pipeline::CommandIo,
    util::parse_tpm_rc,
    CliError, Command, CommandType, TpmDevice,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};

const ABOUT: &str = "Encodes and print a TPM error code";
const USAGE: &str = "tpm2sh print-error <RC>";
const ARGS: &[CommandLineArgument] = &[("<RC>", "TPM error code (e.g., '0x100')")];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for PrintError {
    fn command_type(&self) -> CommandType {
        CommandType::Standalone
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("print-error", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        arguments!(parser, arg, Self::help, {
            _ => return Err(CliError::from(arg.unexpected())),
        });
        let values = collect_values(parser)?;
        if values.len() != 1 {
            return Err(CliError::Usage(format!(
                "'print-error' requires 1 argument, but {} were provided",
                values.len()
            )));
        }
        let rc_str = values
            .into_iter()
            .next()
            .ok_or_else(|| CliError::Execution("value missing".to_string()))?;
        Ok(Commands::PrintError(PrintError {
            rc: parse_tpm_rc(&rc_str)?,
        }))
    }

    fn is_local(&self) -> bool {
        true
    }

    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        _cli: &Cli,
        _device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        writeln!(io.writer(), "{}", self.rc)?;
        Ok(())
    }
}

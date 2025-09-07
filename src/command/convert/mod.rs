// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{handle_help, required, LocalCommand, Subcommand},
    command::{context::Context, CommandError},
    error::CliError,
    key::TpmKey,
};
use lexopt::{Arg, Parser, ValueExt};
use std::{fs, path::PathBuf};

#[derive(Debug, Default)]
pub struct Convert {
    pub input: PathBuf,
    pub output: PathBuf,
}

impl Subcommand for Convert {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut input = None;
        let mut output = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if input.is_none() => input = Some(val.parse()?),
                Arg::Value(val) if output.is_none() => output = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Convert {
            input: required(input, "<INPUT>")?,
            output: required(output, "<OUTPUT>")?,
        })
    }
}

impl LocalCommand for Convert {
    /// Runs `convert`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, _context: &mut Context) -> Result<(), CliError> {
        let input_bytes = fs::read(&self.input)
            .map_err(|e| CliError::File(self.input.display().to_string(), e))?;

        let tpm_key = TpmKey::from_pem(&input_bytes)
            .or_else(|_| TpmKey::from_der(&input_bytes))
            .map_err(|_| CommandError::InvalidKey("failed to parse input key".to_string()))?;

        let output_ext = self
            .output
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();

        let output_bytes = match output_ext {
            "pem" => tpm_key.to_pem()?.into_bytes(),
            "der" => tpm_key.to_der()?,
            _ => {
                return Err(CommandError::InvalidKey(
                    "output file extension must be .pem or .der".to_string(),
                )
                .into())
            }
        };

        fs::write(&self.output, output_bytes)
            .map_err(|e| CliError::File(self.output.display().to_string(), e))?;

        Ok(())
    }
}

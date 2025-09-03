// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{handle_help, required, KeyFormat, LocalCommand, Subcommand},
    key::TpmKey,
    uri::Uri,
    CliError, Context,
};
use lexopt::{Arg, Parser, ValueExt};

#[derive(Debug, Default)]
pub struct Convert {
    pub from: KeyFormat,
    pub to: KeyFormat,
    pub input: Uri,
}

impl Subcommand for Convert {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut from = KeyFormat::Pem;
        let mut to = KeyFormat::Der;
        let mut input = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("from") => from = parser.value()?.parse()?,
                Arg::Long("to") => to = parser.value()?.parse()?,
                Arg::Value(val) if input.is_none() => input = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Convert {
            from,
            to,
            input: required(input, "<INPUT>")?,
        })
    }
}

impl LocalCommand for Convert {
    /// Runs `convert`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, context: &mut Context) -> Result<(), CliError> {
        if self.from == self.to {
            return Err(CliError::Execution(
                "input and output formats cannot be the same".to_string(),
            ));
        }
        let input_bytes = self.input.to_bytes()?;
        let tpm_key = match self.from {
            KeyFormat::Pem => TpmKey::from_pem(&input_bytes)?,
            KeyFormat::Der => TpmKey::from_der(&input_bytes)?,
        };
        match self.to {
            KeyFormat::Pem => {
                let pem_string = tpm_key.to_pem()?;
                write!(context.writer, "{pem_string}")?;
            }
            KeyFormat::Der => {
                let der_bytes = tpm_key.to_der()?;
                context.writer.write_all(&der_bytes)?;
            }
        }
        Ok(())
    }
}

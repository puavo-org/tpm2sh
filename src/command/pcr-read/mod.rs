// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::{context::Context, CommandError},
    device::TpmDevice,
    error::{CliError, ParseError},
    key::tpm_alg_id_from_str,
    pcr,
    policy::{self, Expression, Parsing},
    uri::pcr_selection_to_list,
};
use lexopt::{Arg, Parser, ValueExt};

#[derive(Debug, Default)]
pub struct PcrRead {
    pub expression: String,
}

impl Subcommand for PcrRead {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut expression = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if expression.is_none() => expression = Some(val.string()?),
                _ => return handle_help(arg),
            }
        }
        Ok(PcrRead {
            expression: required(expression, "<EXPRESSION>")?,
        })
    }
}

impl DeviceCommand for PcrRead {
    /// Runs `pcr-read`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let pcr_count = pcr::pcr_get_count(device)?;
        let ast = policy::parse(&self.expression, Parsing::AuthorizationPolicy)?;

        let selection_str = match ast {
            Expression::Pcr {
                digest: Some(_), ..
            } => {
                return Err(CommandError::InvalidPcrSelection(
                    "pcr-read expression must not contain a digest".to_string(),
                )
                .into());
            }
            Expression::Pcr { selection, .. } => selection,
            _ => {
                return Err(
                    ParseError::Custom("expression must be a pcr() policy".to_string()).into(),
                );
            }
        };

        let pcr_selection_in = pcr_selection_to_list(&selection_str, pcr_count)?;
        let pcr_values = crate::pcr::read(device, &pcr_selection_in)?;

        let (alg_str, _) = selection_str.split_once(':').ok_or_else(|| {
            CommandError::InvalidPcrSelection(format!(
                "invalid PCR bank format in selection: '{selection_str}'"
            ))
        })?;
        let alg_id = tpm_alg_id_from_str(alg_str).map_err(CommandError::UnsupportedAlgorithm)?;

        let composite_digest = pcr::pcr_composite_digest(&pcr_values, alg_id)?;

        let final_expr = Expression::Pcr {
            selection: selection_str,
            digest: Some(hex::encode(composite_digest)),
            count: None,
        };

        writeln!(context.writer, "{final_expr}")?;
        Ok(())
    }
}

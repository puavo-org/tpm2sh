// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::LocalCommand,
    command::{context::Context, CommandError},
    error::CliError,
    key::TpmKey,
};
use argh::FromArgs;
use std::{fs, path::PathBuf};

/// Converts keys between ASN.1 formats.
/// Detects the format (PEM or DER) from the file extensions, and converts the key.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "convert")]
pub struct Convert {
    /// input file path
    #[argh(positional)]
    pub input: PathBuf,

    /// output file path
    #[argh(positional)]
    pub output: PathBuf,
}

impl LocalCommand for Convert {
    /// Runs `convert`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, _context: &mut Context) -> Result<(), CliError> {
        let input_ext = self
            .input
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();

        let output_ext = self
            .output
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();

        if !input_ext.is_empty() && input_ext == output_ext {
            return Err(CommandError::SameConversionFormat.into());
        }

        let input_bytes = fs::read(&self.input)
            .map_err(|e| CliError::File(self.input.display().to_string(), e))?;

        let tpm_key = TpmKey::from_pem(&input_bytes)
            .or_else(|_| TpmKey::from_der(&input_bytes))
            .map_err(|_| {
                CommandError::InvalidKey(
                    "failed to parse input key as PEM or DER format".to_string(),
                )
            })?;

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

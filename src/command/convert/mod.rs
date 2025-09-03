// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{Convert, KeyFormat, LocalCommand},
    key::TpmKey,
    CliError, Context,
};
use std::io::Write;

impl LocalCommand for Convert {
    /// Runs `convert`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(&self, context: &mut Context<W>) -> Result<(), CliError> {
        if self.from == self.to {
            return Err(CliError::Usage(
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

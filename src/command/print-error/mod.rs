// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{cli::LocalCommand, command::context::Context, error::CliError, util::parse_tpm_rc};
use argh::FromArgs;
use tpm2_protocol::data::TpmRc;

fn parse_rc_from_str(value: &str) -> Result<TpmRc, String> {
    parse_tpm_rc(value).map_err(|e| e.to_string())
}

/// Prints a human-readable description of a TPM error code.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "print-error")]
pub struct PrintError {
    /// TPM error code in decimal or hex format
    #[argh(positional, from_str_fn(parse_rc_from_str))]
    pub rc: TpmRc,
}

impl LocalCommand for PrintError {
    fn run(&self, context: &mut Context) -> Result<(), CliError> {
        writeln!(context.writer, "{}", self.rc)?;
        Ok(())
    }
}

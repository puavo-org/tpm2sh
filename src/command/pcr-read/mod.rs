// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    key::tpm_alg_id_from_str,
    pcr::{pcr_composite_digest, pcr_get_count},
    uri::Uri,
};
use lexopt::{Arg, Parser, ValueExt};

#[derive(Debug, Default)]
pub struct PcrRead {
    pub alg: String,
    pub pcr: Uri,
}

impl Subcommand for PcrRead {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut alg = None;
        let mut pcr = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if alg.is_none() => alg = Some(val.string()?),
                Arg::Value(val) if pcr.is_none() => pcr = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(PcrRead {
            alg: required(alg, "<ALG>")?,
            pcr: required(pcr, "<PCR>")?,
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
        let pcr_count = pcr_get_count(device)?;
        let pcr_selection_in = self.pcr.to_pcr_selection(pcr_count)?;
        let (_rc, pcr_read_resp) = device.pcr_read(&pcr_selection_in)?;
        let alg_id = tpm_alg_id_from_str(&self.alg).map_err(CliError::Execution)?;
        let composite_digest = pcr_composite_digest(&pcr_read_resp, alg_id)?;
        writeln!(
            context.writer,
            "pcr-digest://{}:{}",
            self.alg,
            hex::encode(composite_digest)
        )?;
        Ok(())
    }
}

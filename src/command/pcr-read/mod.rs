// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    pcr::{pcr_composite_digest, pcr_get_count},
    uri::Uri,
    CliError, Context, TpmDevice,
};
use lexopt::{Arg, Parser, ValueExt};

#[derive(Debug, Default)]
pub struct PcrRead {
    pub pcr: Uri,
}

impl Subcommand for PcrRead {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut pcr = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if pcr.is_none() => pcr = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(PcrRead {
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
        let pcr_read_resp = device.pcr_read(&pcr_selection_in)?;
        let composite_digest = pcr_composite_digest(&pcr_read_resp);
        let selection_str = self.pcr.strip_prefix("pcr://").unwrap_or(&self.pcr);
        writeln!(
            context.writer,
            "pcr({}, {})",
            selection_str,
            hex::encode(composite_digest)
        )?;
        Ok(())
    }
}

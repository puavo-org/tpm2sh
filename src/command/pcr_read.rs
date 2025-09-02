// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, PcrRead},
    pcr::{pcr_composite_digest, pcr_get_count},
    CliError, TpmDevice,
};
use std::io::Write;

impl DeviceCommand for PcrRead {
    /// Runs `pcr-read`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        _cli: &Cli,
        device: &mut TpmDevice,
        writer: &mut W,
    ) -> Result<crate::Resources, CliError> {
        let pcr_count = pcr_get_count(device)?;
        let pcr_selection_in = self.pcr.to_pcr_selection(pcr_count)?;
        let pcr_read_resp = device.pcr_read(&pcr_selection_in)?;
        let composite_digest = pcr_composite_digest(&pcr_read_resp);
        let selection_str = self.pcr.strip_prefix("pcr://").unwrap_or(&self.pcr);
        writeln!(
            writer,
            "pcr(\"{}\", \"{}\")",
            selection_str,
            hex::encode(composite_digest)
        )?;
        Ok(crate::Resources::new(Vec::new()))
    }
}

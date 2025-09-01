// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, PcrRead},
    pcr::pcr_get_count,
    CliError, TpmDevice,
};
use sha2::{Digest, Sha256};
use std::io::Write;
use tpm2_protocol::{message::TpmPcrReadCommand, TpmTransient};

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
    ) -> Result<Vec<TpmTransient>, CliError> {
        let pcr_count = pcr_get_count(device)?;
        let pcr_selection_in = self.pcr.to_pcr_selection(pcr_count)?;
        let cmd = TpmPcrReadCommand { pcr_selection_in };
        let (resp, _) = device.execute(&cmd, &[])?;
        let pcr_read_resp = resp
            .PcrRead()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        let mut concatenated_digests = Vec::new();
        for digest in pcr_read_resp.pcr_values.iter() {
            concatenated_digests.extend_from_slice(digest);
        }

        let composite_digest = Sha256::digest(&concatenated_digests);
        let selection_str = self.pcr.strip_prefix("pcr://").unwrap_or(&self.pcr);

        writeln!(
            writer,
            "pcr(\"{}\", \"{}\")",
            selection_str,
            hex::encode(composite_digest)
        )?;

        Ok(Vec::new())
    }
}

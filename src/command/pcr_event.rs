// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, PcrEvent},
    pcr::pcr_get_count,
    session::session_from_args,
    CliError, TpmDevice,
};

use std::io::Write;

use tpm2_protocol::{data::Tpm2bEvent, message::TpmPcrEventCommand, TpmTransient};

impl DeviceCommand for PcrEvent {
    /// Runs `pcr-event`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: &mut TpmDevice,
        _writer: &mut W,
    ) -> Result<Vec<TpmTransient>, CliError> {
        let pcr_count = pcr_get_count(device)?;
        let selection = self.pcr.to_pcr_selection(pcr_count)?;

        if selection.len() != 1 {
            return Err(CliError::Usage(
                "pcr-event requires a selection of exactly one PCR bank".to_string(),
            ));
        }
        let pcr_selection = &selection[0];

        let set_bits_count = pcr_selection
            .pcr_select
            .iter()
            .map(|byte| byte.count_ones())
            .sum::<u32>();

        if set_bits_count != 1 {
            return Err(CliError::Usage(format!(
                "pcr-event requires a selection of exactly one PCR (provided selection '{}' contains {})",
                self.pcr, set_bits_count
            )));
        }

        let mut pcr_index = 0;
        for (byte_idx, &byte) in pcr_selection.pcr_select.iter().enumerate() {
            if byte != 0 {
                let bit_idx = byte.trailing_zeros();
                pcr_index = u32::try_from(byte_idx * 8).unwrap() + bit_idx;
                break;
            }
        }

        let handles = [pcr_index];
        let data_bytes = self.data.to_bytes()?;
        let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
        let command = TpmPcrEventCommand {
            pcr_handle: handles[0],
            event_data,
        };
        let sessions = session_from_args(&command, &handles, cli)?;
        let (resp, _) = device.execute(&command, &sessions)?;
        resp.PcrEvent()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        Ok(Vec::new())
    }
}

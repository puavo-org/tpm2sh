// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, PcrEvent},
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
        let (_bank, pcr_index) = self.pcr_uri.to_pcr_spec()?;

        let handles = [pcr_index];
        let data_bytes = self.data_uri.to_bytes()?;
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

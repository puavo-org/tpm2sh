// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, PcrEvent},
    session::session_from_args,
    uri::uri_to_bytes,
    util::parse_pcr_uri,
    CliError, Command, TpmDevice,
};

use std::io::Write;
use std::sync::{Arc, Mutex};

use tpm2_protocol::{data::Tpm2bEvent, message::TpmPcrEventCommand};

impl Command for PcrEvent {
    /// Runs `pcr-event`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
        _writer: &mut W,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let (_bank, pcr_index) = parse_pcr_uri(&self.pcr_uri)?;

        let handles = [pcr_index];
        let data_bytes = uri_to_bytes(&self.data_uri, &[])?;
        let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
        let command = TpmPcrEventCommand {
            pcr_handle: handles[0],
            event_data,
        };
        let sessions = session_from_args(&command, &handles, cli)?;
        let (resp, _) = chip.execute(&command, &sessions)?;
        resp.PcrEvent()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        Ok(())
    }
}

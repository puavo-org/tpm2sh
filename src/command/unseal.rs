// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, Unseal},
    device::ScopedHandle,
    session::session_from_args,
    uri::uri_to_tpm_handle,
    CliError, Command, TpmDevice,
};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::{message::TpmUnsealCommand, TpmTransient};

impl Command for Unseal {
    /// Runs `unseal`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
        writer: &mut W,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;

        let handle = uri_to_tpm_handle(&self.handle_uri)?;
        let object_handle_guard = ScopedHandle::new(TpmTransient(handle), device_arc.clone());
        let object_handle = object_handle_guard.handle();

        let unseal_cmd = TpmUnsealCommand {
            item_handle: object_handle.0.into(),
        };
        let unseal_handles = [object_handle.into()];
        let unseal_sessions = session_from_args(&unseal_cmd, &unseal_handles, cli)?;

        let (unseal_resp, _) = {
            let mut chip = device_arc
                .lock()
                .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
            chip.execute(&unseal_cmd, &unseal_sessions)?
        };
        let unseal_resp = unseal_resp
            .Unseal()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        writer.write_all(&unseal_resp.out_data)?;
        Ok(())
    }
}

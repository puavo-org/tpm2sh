// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, Save},
    device::ScopedHandle,
    session::session_from_args,
    uri::uri_to_tpm_handle,
    CliError, Command, TpmDevice,
};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::{data::TpmRh, message::TpmEvictControlCommand, TpmPersistent};

impl Command for Save {
    /// Runs `save`.
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

        let object_handle_guard =
            ScopedHandle::from_uri(&device_arc, cli.log_format, &self.in_uri)?;
        let object_handle = object_handle_guard.handle();

        let persistent_handle = TpmPersistent(uri_to_tpm_handle(&self.to_uri)?);
        let auth_handle = TpmRh::Owner;
        let handles = [auth_handle as u32, object_handle.into()];

        let evict_cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: object_handle.0.into(),
            persistent_handle,
        };
        let sessions = session_from_args(&evict_cmd, &handles, cli)?;
        let (resp, _) = {
            let mut chip = device_arc
                .lock()
                .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
            chip.execute(cli.log_format, &evict_cmd, &sessions)?
        };
        resp.EvictControl()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        object_handle_guard.forget();

        writeln!(writer, "tpm://{persistent_handle:#010x}")?;
        Ok(())
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, Delete},
    session::session_from_args,
    uri::uri_to_tpm_handle,
    CliError, Command, TpmDevice,
};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::TpmRh,
    message::{TpmEvictControlCommand, TpmFlushContextCommand},
    TpmPersistent, TpmTransient,
};

impl Command for Delete {
    /// Runs `delete`.
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
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let handle = uri_to_tpm_handle(&self.handle_uri)?;

        if handle >= TpmRh::PersistentFirst as u32 {
            let persistent_handle = TpmPersistent(handle);
            let auth_handle = TpmRh::Owner;
            let handles = [auth_handle as u32, persistent_handle.into()];
            let evict_cmd = TpmEvictControlCommand {
                auth: (auth_handle as u32).into(),
                object_handle: persistent_handle.0.into(),
                persistent_handle,
            };
            let sessions = session_from_args(&evict_cmd, &handles, cli)?;
            let (resp, _) = chip.execute(&evict_cmd, &sessions)?;
            resp.EvictControl()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            writeln!(writer, "tpm://{persistent_handle:#010x}")?;
        } else if handle >= TpmRh::TransientFirst as u32 {
            let flush_handle = TpmTransient(handle);
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: flush_handle.into(),
            };
            let (resp, _) = chip.execute(&flush_cmd, &[])?;
            resp.FlushContext()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            writeln!(writer, "tpm://{flush_handle:#010x}")?;
        } else {
            return Err(CliError::InvalidHandle(format!(
                "'{handle:#010x}' is not a transient or persistent handle"
            )));
        }
        Ok(())
    }
}

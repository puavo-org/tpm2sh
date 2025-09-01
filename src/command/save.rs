// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, Save},
    session::session_from_args,
    CliError, TpmDevice,
};
use std::io::Write;
use tpm2_protocol::{data::TpmRh, message::TpmEvictControlCommand, TpmPersistent, TpmTransient};

impl DeviceCommand for Save {
    /// Runs `save`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: &mut TpmDevice,
        writer: &mut W,
    ) -> Result<Vec<TpmTransient>, CliError> {
        let (object_handle, needs_flush) = device.load_context(&self.in_uri)?;
        let mut handles_to_flush = Vec::new();
        if needs_flush {
            handles_to_flush.push(object_handle);
        }

        let persistent_handle = TpmPersistent(self.to_uri.to_tpm_handle()?);
        let auth_handle = TpmRh::Owner;
        let handles = [auth_handle as u32, object_handle.into()];

        let evict_cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: object_handle.0.into(),
            persistent_handle,
        };
        let sessions = session_from_args(&evict_cmd, &handles, cli)?;
        let (resp, _) = device.execute(&evict_cmd, &sessions)?;
        resp.EvictControl()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        handles_to_flush.retain(|&h| h != object_handle);

        writeln!(writer, "tpm://{persistent_handle:#010x}")?;
        Ok(handles_to_flush)
    }
}

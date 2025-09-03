// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Delete, DeviceCommand},
    CliError, Context, TpmDevice,
};
use std::io::Write;
use tpm2_protocol::{data::TpmRh, message::TpmFlushContextCommand, TpmPersistent, TpmTransient};

impl DeviceCommand for Delete {
    /// Runs `delete`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        device: &mut TpmDevice,
        context: &mut Context<W>,
    ) -> Result<(), CliError> {
        let handle = self.handle.to_tpm_handle()?;

        if handle >= TpmRh::PersistentFirst as u32 {
            let persistent_handle = TpmPersistent(handle);
            device.evict_control(context.cli, handle, persistent_handle)?;
            writeln!(context.writer, "tpm://{persistent_handle:#010x}")?;
        } else if handle >= TpmRh::TransientFirst as u32 {
            let flush_handle = TpmTransient(handle);
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: flush_handle.into(),
            };
            let (resp, _) = device.execute(&flush_cmd, &[])?;
            resp.FlushContext()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            writeln!(context.writer, "tpm://{flush_handle:#010x}")?;
        } else {
            return Err(CliError::InvalidHandle(format!(
                "'{handle:#010x}' is not a transient or persistent handle"
            )));
        }
        Ok(())
    }
}

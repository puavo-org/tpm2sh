// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{DeviceCommand, Save},
    CliError, Context, TpmDevice,
};
use std::io::Write;
use tpm2_protocol::TpmPersistent;

impl DeviceCommand for Save {
    /// Runs `save`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        device: &mut TpmDevice,
        context: &mut Context<W>,
    ) -> Result<(), CliError> {
        let (object_handle, _) = device.context_load(&self.in_uri)?;
        let persistent_handle = TpmPersistent(self.to_uri.to_tpm_handle()?);
        device.evict_control(context.cli, object_handle.0, persistent_handle)?;
        writeln!(context.writer, "tpm://{persistent_handle:#010x}")?;
        Ok(())
    }
}

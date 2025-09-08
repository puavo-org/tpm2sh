// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::DeviceCommand, command::context::Context, device::TpmDevice, error::CliError, policy::Uri,
};
use argh::FromArgs;

/// Deletes a transient or persistent object.
///
/// If a 'tpm://' URI is provided for a persistent handle, the object is evicted
/// from NV memory. If the URI points to a transient handle (either 'tpm://',
/// 'file://', or 'data://'), the object's context is flushed from the TPM.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "delete")]
pub struct Delete {
    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,

    /// URI of the object to delete ('tpm://', 'file://', or 'data://')
    #[argh(positional)]
    pub handle: Uri,
}

impl DeviceCommand for Delete {
    /// Runs `delete`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let handle = context.delete(device, &self.handle, self.session.as_ref())?;
        writeln!(context.writer, "tpm://{handle:#010x}")?;
        Ok(())
    }
}

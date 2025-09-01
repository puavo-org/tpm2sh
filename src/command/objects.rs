// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, Objects},
    CliError, Command, TpmDevice,
};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::data::TpmRh;

impl Command for Objects {
    /// Runs `objects`.
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
        let mut device = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
        let transient_handles = device.get_all_handles(cli, TpmRh::TransientFirst)?;
        for handle in transient_handles {
            writeln!(writer, "tpm://{handle:#010x}")?;
        }
        let persistent_handles = device.get_all_handles(cli, TpmRh::PersistentFirst)?;
        for handle in persistent_handles {
            writeln!(writer, "tpm://{handle:#010x}")?;
        }
        Ok(())
    }
}

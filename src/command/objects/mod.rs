// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{DeviceCommand, Objects},
    CliError, Context, TpmDevice,
};
use std::io::Write;
use tpm2_protocol::data::TpmRh;

impl DeviceCommand for Objects {
    /// Runs `objects`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        device: &mut TpmDevice,
        context: &mut Context<W>,
    ) -> Result<(), CliError> {
        let transient_handles = device.get_all_handles(TpmRh::TransientFirst)?;
        for handle in transient_handles {
            writeln!(context.writer, "tpm://{handle:#010x}")?;
        }
        let persistent_handles = device.get_all_handles(TpmRh::PersistentFirst)?;
        for handle in persistent_handles {
            writeln!(context.writer, "tpm://{handle:#010x}")?;
        }
        Ok(())
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Algorithms, DeviceCommand},
    CliError, Context, TpmDevice,
};
use std::io::Write;

impl DeviceCommand for Algorithms {
    /// Runs `algorithms`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        device: &mut TpmDevice,
        context: &mut Context<W>,
    ) -> Result<(), CliError> {
        let mut algorithms = device.get_all_algorithms()?;
        algorithms.sort_by(|a, b| a.1.cmp(&b.1));
        for (_, name) in algorithms {
            writeln!(context.writer, "{name}")?;
        }
        Ok(())
    }
}

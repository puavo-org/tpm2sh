// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Algorithms, Cli, DeviceCommand},
    CliError, TpmDevice,
};
use std::io::Write;
use tpm2_protocol::TpmTransient;

impl DeviceCommand for Algorithms {
    /// Runs `algorithms`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        _cli: &Cli,
        device: &mut TpmDevice,
        writer: &mut W,
    ) -> Result<Vec<TpmTransient>, CliError> {
        let mut algorithms = device.get_all_algorithms()?;
        algorithms.sort_by(|a, b| a.1.cmp(&b.1));

        for (_, name) in algorithms {
            if self.filter.as_ref().map_or(true, |f| name.contains(f)) {
                writeln!(writer, "{name}")?;
            }
        }
        Ok(Vec::new())
    }
}

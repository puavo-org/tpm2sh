// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Algorithms, Cli, DeviceCommand},
    key::enumerate_all,
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
        let chip_algorithms = device.get_all_algorithms()?;
        let cli_algorithms = enumerate_all();
        // FIXME: This is incorrect. The command should instead iterator through
        // chip algorithms only and figure out the name for each  of them, as
        // `tpm2-protocol` is now TCG spec complete. `enumerate_all()` should be
        // removed from the crate entirely.
        let mut names: Vec<_> = cli_algorithms
            .into_iter()
            .filter(|alg| chip_algorithms.contains(&alg.object_type))
            .map(|alg| alg.name)
            .collect();
        names.sort();
        for name in names {
            writeln!(writer, "{name}")?;
        }
        Ok(Vec::new())
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Algorithms, Cli},
    key::enumerate_all,
    CliError, Command, TpmDevice,
};
use regex::Regex;
use std::io::Write;
use std::sync::{Arc, Mutex};

impl Command for Algorithms {
    /// Runs `algorithms`.
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

        let chip_algorithms = device.get_all_algorithms(cli)?;
        let cli_algorithms = enumerate_all();

        let supported_algorithms: Vec<_> = cli_algorithms
            .into_iter()
            .filter(|alg| chip_algorithms.contains(&alg.object_type))
            .collect();
        let filtered_algorithms: Vec<_> = if let Some(pattern) = &self.filter {
            let re =
                Regex::new(pattern).map_err(|e| CliError::Usage(format!("invalid regex: {e}")))?;
            supported_algorithms
                .into_iter()
                .filter(|alg| re.is_match(&alg.name))
                .collect()
        } else {
            supported_algorithms
        };
        let mut sorted_names: Vec<_> = filtered_algorithms
            .into_iter()
            .map(|alg| alg.name)
            .collect();
        sorted_names.sort();
        for name in sorted_names {
            writeln!(writer, "{name}")?;
        }
        Ok(())
    }
}

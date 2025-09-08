// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli::DeviceCommand, command::context::Context, device::TpmDevice, error::CliError};
use argh::FromArgs;
use std::str::FromStr;
use tpm2_protocol::data::{TPM_RH_PERSISTENT_FIRST, TPM_RH_TRANSIENT_FIRST};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListType {
    Algorithm,
    Persistent,
    Transient,
}

impl FromStr for ListType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "algorithm" | "algorithms" => Ok(Self::Algorithm),
            "persistent" => Ok(Self::Persistent),
            "transient" => Ok(Self::Transient),
            _ => Err(format!("invalid list type: '{s}'")),
        }
    }
}

/// Lists TPM capabilities and objects.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "list")]
pub struct List {
    /// type of items to list (algorithm, persistent, or transient)
    #[argh(positional)]
    pub list_type: ListType,
}

impl DeviceCommand for List {
    /// Runs `list`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        match self.list_type {
            ListType::Algorithm => {
                let mut algorithms = device.get_all_algorithms()?;
                algorithms.sort_by(|a, b| a.1.cmp(&b.1));
                for (_, name) in algorithms {
                    writeln!(context.writer, "{name}")?;
                }
            }
            ListType::Persistent => {
                let handles = device.get_all_handles(TPM_RH_PERSISTENT_FIRST)?;
                for handle in handles {
                    writeln!(context.writer, "tpm://{handle:#010x}")?;
                }
            }
            ListType::Transient => {
                let handles = device.get_all_handles(TPM_RH_TRANSIENT_FIRST)?;
                for handle in handles {
                    writeln!(context.writer, "tpm://{handle:#010x}")?;
                }
            }
        }
        Ok(())
    }
}

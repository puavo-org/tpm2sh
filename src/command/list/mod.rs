// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
};
use lexopt::{Arg, Parser, ValueExt};
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
            "algorithm" => Ok(Self::Algorithm),
            "persistent" => Ok(Self::Persistent),
            "transient" => Ok(Self::Transient),
            _ => Err(format!("invalid list type: '{s}'")),
        }
    }
}

#[derive(Debug)]
pub struct List {
    pub list_type: ListType,
}

impl Subcommand for List {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut list_type = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if list_type.is_none() => list_type = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(List {
            list_type: required(list_type, "<TYPE>")?,
        })
    }
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

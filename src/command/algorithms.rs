// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Algorithms, Cli, Commands},
    device::TPM_CAP_PROPERTY_MAX,
    key::enumerate_all,
    CliError, Command, TpmDevice,
};
use lexopt::prelude::*;
use regex::Regex;
use std::collections::HashSet;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::data::{TpmAlgId, TpmCap, TpmuCapabilities};

const ABOUT: &str = "Lists available algorithms";
const USAGE: &str = "tpm2sh algorithms [OPTIONS] [FILTER]";
const ARGS: &[CommandLineArgument] = &[("FILTER", "A regex to filter the algorithm names")];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

fn get_chip_algorithms(
    device: Option<Arc<Mutex<TpmDevice>>>,
) -> Result<HashSet<TpmAlgId>, CliError> {
    let device_arc =
        device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
    let mut locked_device = device_arc
        .lock()
        .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

    let cap_data_vec = locked_device.get_capability(TpmCap::Algs, 0, TPM_CAP_PROPERTY_MAX)?;
    let algs: HashSet<TpmAlgId> = cap_data_vec
        .into_iter()
        .flat_map(|cap_data| {
            if let TpmuCapabilities::Algs(p) = cap_data.data {
                p.iter().map(|prop| prop.alg).collect::<Vec<_>>()
            } else {
                Vec::new()
            }
        })
        .collect();
    Ok(algs)
}

impl Command for Algorithms {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("algorithms", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = Algorithms { filter: None };
        arguments!(parser, arg, Self::help, {
            Value(val) if args.filter.is_none() => {
                args.filter = Some(val.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Algorithms(args))
    }

    /// Runs `algorithms`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        _cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
        writer: &mut W,
    ) -> Result<(), CliError> {
        let chip_algorithms = get_chip_algorithms(device)?;
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

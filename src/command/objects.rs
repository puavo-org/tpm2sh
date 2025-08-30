// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, Objects},
    parse_args, CliError, Command, CommandIo, CommandType, PipelineObject, Tpm, TpmDevice,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::data::TpmRh;

const ABOUT: &str = "Lists objects in volatile and non-volatile memory";
const USAGE: &str = "tpm2sh objects";
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for Objects {
    fn command_type(&self) -> CommandType {
        CommandType::Source
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("objects", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        parse_args!(parser, arg, Self::help, {
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Objects(Objects {}))
    }

    /// Runs `objects`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        io.clear_input()?;
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut locked_device = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let transient_handles = locked_device.get_all_handles(TpmRh::TransientFirst)?;
        for handle in transient_handles {
            let tpm_obj = Tpm {
                context: format!("tpm://{handle:#010x}"),
                parent: None,
            };
            io.push_object(PipelineObject::Tpm(tpm_obj));
        }

        let persistent_handles = locked_device.get_all_handles(TpmRh::PersistentFirst)?;
        for handle in persistent_handles {
            let tpm_obj = Tpm {
                context: format!("tpm://{handle:#010x}"),
                parent: None,
            };
            io.push_object(PipelineObject::Tpm(tpm_obj));
        }

        Ok(())
    }
}

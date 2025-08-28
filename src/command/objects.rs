// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, Objects},
    get_tpm_device, parse_args, Command, CommandIo, CommandType, PipelineObject, Tpm, TpmError,
};
use std::io::{Read, Write};
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

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        parse_args!(parser, arg, Self::help, {
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Objects(Objects {}))
    }

    /// Runs `objects`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run<R: Read, W: Write>(&self, io: &mut CommandIo<R, W>) -> Result<(), TpmError> {
        let mut device = get_tpm_device()?;

        let transient_handles = device.get_all_handles(TpmRh::TransientFirst)?;
        for handle in transient_handles {
            let tpm_obj = Tpm {
                context: format!("tpm://{handle:#010x}"),
                parent: None,
            };
            io.push_object(PipelineObject::Tpm(tpm_obj));
        }

        let persistent_handles = device.get_all_handles(TpmRh::PersistentFirst)?;
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

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Commands, Delete},
    get_auth_sessions, parse_args, parse_tpm_handle_from_uri, CliError, Command, CommandIo,
    CommandType, TpmDevice,
};
use lexopt::prelude::*;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::TpmRh,
    message::{TpmEvictControlCommand, TpmFlushContextCommand},
    TpmPersistent, TpmTransient,
};

const ABOUT: &str = "Deletes a transient or persistent object";
const USAGE: &str = "tpm2sh delete [OPTIONS] [HANDLE_URI]";
const ARGS: &[CommandLineArgument] = &[(
    "HANDLE_URI",
    "URI of the object to delete (e.g. 'tpm://0x80000001'). If omitted, uses active object.",
)];
const OPTIONS: &[CommandLineOption] = &[
    (None, "--password", "<PASSWORD>", "Authorization value"),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Delete {
    fn command_type(&self) -> CommandType {
        CommandType::Sink
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("delete", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = Delete::default();
        parse_args!(parser, arg, Self::help, {
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            Value(val) if args.handle_uri.is_none() => {
                args.handle_uri = Some(val.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Delete(args))
    }

    /// Runs `delete`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let handle = if let Some(uri) = &self.handle_uri {
            parse_tpm_handle_from_uri(uri)?
        } else {
            let tpm_obj = io.pop_tpm()?;
            parse_tpm_handle_from_uri(&tpm_obj.context)?
        };

        if handle >= TpmRh::PersistentFirst as u32 {
            let persistent_handle = TpmPersistent(handle);
            let auth_handle = TpmRh::Owner;
            let handles = [auth_handle as u32, persistent_handle.into()];
            let evict_cmd = TpmEvictControlCommand {
                auth: (auth_handle as u32).into(),
                object_handle: persistent_handle.0.into(),
                persistent_handle,
            };
            let sessions = get_auth_sessions(
                &evict_cmd,
                &handles,
                None,
                self.password.password.as_deref(),
            )?;
            let (resp, _) = chip.execute(&evict_cmd, &sessions)?;
            resp.EvictControl()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            println!("Deleted persistent handle {persistent_handle:#010x}");
        } else if handle >= TpmRh::TransientFirst as u32 {
            let flush_handle = TpmTransient(handle);
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: flush_handle.into(),
            };
            let (resp, _) = chip.execute(&flush_cmd, &[])?;
            resp.FlushContext()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            println!("Flushed transient handle {flush_handle:#010x}");
        } else {
            return Err(CliError::InvalidHandle(format!(
                "'{handle:#010x}' is not a transient or persistent handle"
            )));
        }
        Ok(())
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Cli, Commands, Delete},
    session::session_from_args,
    uri::uri_to_tpm_handle,
    CliError, Command, TpmDevice,
};
use lexopt::prelude::*;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::TpmRh,
    message::{TpmEvictControlCommand, TpmFlushContextCommand},
    TpmPersistent, TpmTransient,
};

const ABOUT: &str = "Deletes a transient or persistent object";
const USAGE: &str = "tpm2sh delete [OPTIONS] <HANDLE_URI>";
const ARGS: &[CommandLineArgument] = &[(
    "HANDLE_URI",
    "URI of the object to delete (e.g. 'tpm://0x81000001').",
)];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for Delete {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("delete", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = Delete::default();
        arguments!(parser, arg, Self::help, {
            Value(val) if args.handle_uri.is_none() => {
                args.handle_uri = Some(val.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        if args.handle_uri.is_none() {
            return Err(CliError::Usage(
                "Missing required argument <HANDLE_URI>".to_string(),
            ));
        }
        Ok(Commands::Delete(args))
    }

    /// Runs `delete`.
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
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let handle = uri_to_tpm_handle(self.handle_uri.as_ref().unwrap())?;

        if handle >= TpmRh::PersistentFirst as u32 {
            let persistent_handle = TpmPersistent(handle);
            let auth_handle = TpmRh::Owner;
            let handles = [auth_handle as u32, persistent_handle.into()];
            let evict_cmd = TpmEvictControlCommand {
                auth: (auth_handle as u32).into(),
                object_handle: persistent_handle.0.into(),
                persistent_handle,
            };
            let sessions = session_from_args(&evict_cmd, &handles, cli)?;
            let (resp, _) = chip.execute(&evict_cmd, &sessions)?;
            resp.EvictControl()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            writeln!(writer, "tpm://{persistent_handle:#010x}")?;
        } else if handle >= TpmRh::TransientFirst as u32 {
            let flush_handle = TpmTransient(handle);
            let flush_cmd = TpmFlushContextCommand {
                flush_handle: flush_handle.into(),
            };
            let (resp, _) = chip.execute(&flush_cmd, &[])?;
            resp.FlushContext()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            writeln!(writer, "tpm://{flush_handle:#010x}")?;
        } else {
            return Err(CliError::InvalidHandle(format!(
                "'{handle:#010x}' is not a transient or persistent handle"
            )));
        }
        Ok(())
    }
}

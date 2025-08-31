// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{Cli, Commands, Save},
    device::ScopedHandle,
    session::session_from_args,
    uri::uri_to_tpm_handle,
    CliError, Command, TpmDevice,
};
use lexopt::prelude::*;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::{data::TpmRh, message::TpmEvictControlCommand, TpmPersistent};

const ABOUT: &str = "Saves a transient object to non-volatile memory";
const USAGE: &str = "tpm2sh save --to <HANDLE_URI> --in <CONTEXT_URI> [OPTIONS]";
const ARGS: &[CommandLineArgument] = &[];
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--to",
        "<HANDLE_URI>",
        "URI for the persistent object to be created (e.g., 'tpm://0x81000001')",
    ),
    (
        None,
        "--in",
        "<CONTEXT_URI>",
        "URI of the transient object context to save (e.g., 'file:///path/to/context.bin')",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Save {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("save", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = Save::default();
        arguments!(parser, arg, Self::help, {
            Long("to") => {
                args.to_uri = Some(parser.value()?.string()?);
            }
            Long("in") => {
                args.in_uri = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });

        if args.to_uri.is_none() || args.in_uri.is_none() {
            return Err(CliError::Usage(
                "Missing required arguments: --to and --in".to_string(),
            ));
        }

        Ok(Commands::Save(args))
    }

    /// Runs `save`.
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

        let object_handle_guard =
            ScopedHandle::from_uri(&device_arc, self.in_uri.as_ref().unwrap())?;
        let object_handle = object_handle_guard.handle();

        let persistent_handle = TpmPersistent(uri_to_tpm_handle(self.to_uri.as_ref().unwrap())?);
        let auth_handle = TpmRh::Owner;
        let handles = [auth_handle as u32, object_handle.into()];

        let evict_cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: object_handle.0.into(),
            persistent_handle,
        };
        let sessions = session_from_args(&evict_cmd, &handles, cli)?;
        let (resp, _) = {
            let mut chip = device_arc
                .lock()
                .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
            chip.execute(&evict_cmd, &sessions)?
        };
        resp.EvictControl()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        object_handle_guard.forget();

        writeln!(writer, "tpm://{persistent_handle:#010x}")?;
        Ok(())
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineOption},
    cli::{Cli, Commands, Unseal},
    device::ScopedHandle,
    session::session_from_args,
    uri::uri_to_tpm_handle,
    CliError, Command, TpmDevice,
};
use lexopt::prelude::*;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::{message::TpmUnsealCommand, TpmTransient};

const ABOUT: &str = "Unseals a secret from a loaded TPM object";
const USAGE: &str = "tpm2sh unseal [OPTIONS] --handle <HANDLE_URI>";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--handle",
        "<HANDLE_URI>",
        "URI of the loaded sealed object to unseal (e.g., 'tpm://0x80000000')",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Unseal {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("unseal", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = Unseal::default();
        arguments!(parser, arg, Self::help, {
            Long("handle") => {
                args.handle_uri = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        if args.handle_uri.is_none() {
            return Err(CliError::Usage(
                "Missing required argument: --handle <HANDLE_URI>".to_string(),
            ));
        }
        Ok(Commands::Unseal(args))
    }

    /// Runs `unseal`.
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

        let handle = uri_to_tpm_handle(self.handle_uri.as_ref().unwrap())?;
        let object_handle_guard = ScopedHandle::new(TpmTransient(handle), device_arc.clone());
        let object_handle = object_handle_guard.handle();

        let unseal_cmd = TpmUnsealCommand {
            item_handle: object_handle.0.into(),
        };
        let unseal_handles = [object_handle.into()];
        let unseal_sessions = session_from_args(&unseal_cmd, &unseal_handles, cli)?;

        let (unseal_resp, _) = {
            let mut chip = device_arc
                .lock()
                .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
            chip.execute(&unseal_cmd, &unseal_sessions)?
        };
        let unseal_resp = unseal_resp
            .Unseal()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        object_handle_guard.flush()?;

        writer.write_all(&unseal_resp.out_data)?;
        Ok(())
    }
}

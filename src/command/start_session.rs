// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineOption},
    cli::{Cli, Commands, SessionType, StartSession},
    CliError, Command, TpmDevice,
};
use lexopt::prelude::*;
use rand::{thread_rng, RngCore};
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::{Tpm2b, Tpm2bNonce, TpmAlgId, TpmRh, TpmtSymDefObject},
    message::TpmStartAuthSessionCommand,
    tpm_hash_size,
};

const ABOUT: &str = "Starts an authorization session";
const USAGE: &str = "tpm2sh start-session [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        Some("-t"),
        "--type",
        "<TYPE>",
        "[default: hmac, possible: hmac, policy, trial]",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for StartSession {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("start-session", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = StartSession::default();
        arguments!(parser, arg, Self::help, {
            Short('t') | Long("type") => {
                args.session_type = parser.value()?.string()?.parse()?;
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        Ok(Commands::StartSession(args))
    }

    /// Runs `start-session`.
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
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
        let auth_hash = TpmAlgId::Sha256;
        let digest_len = tpm_hash_size(&auth_hash)
            .ok_or_else(|| CliError::Execution("Unsupported hash algorithm".to_string()))?;
        let mut nonce_bytes = vec![0; digest_len];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let cmd = TpmStartAuthSessionCommand {
            tpm_key: (TpmRh::Null as u32).into(),
            bind: (TpmRh::Null as u32).into(),
            nonce_caller: Tpm2bNonce::try_from(nonce_bytes.as_slice())?,
            encrypted_salt: Tpm2b::default(),
            session_type: self.session_type.into(),
            symmetric: TpmtSymDefObject::default(),
            auth_hash,
        };
        let (response, _) = chip.execute(&cmd, &[])?;
        let start_auth_session_resp = response
            .StartAuthSession()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let handle = start_auth_session_resp.session_handle;
        if self.session_type == SessionType::Policy {
            let digest = hex::encode(vec![0; digest_len]);
            writeln!(writer, "digest://sha256,{digest}")?;
        }
        writeln!(writer, "tpm://{handle:#010x}")?;
        Ok(())
    }
}

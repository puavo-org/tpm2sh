// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, StartSession},
    key, parse_args, Command, CommandIo, CommandType, HmacSession, PipelineObject, PolicySession,
    TpmDevice, TpmError,
};
use lexopt::prelude::*;
use rand::{thread_rng, RngCore};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::{Tpm2b, Tpm2bNonce, TpmAlgId, TpmRh, TpmtSymDefObject},
    message::TpmStartAuthSessionCommand,
};

const ABOUT: &str = "Starts an authorization session";
const USAGE: &str = "tpm2sh start-session [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--session-type",
        "<TYPE>",
        "[default: hmac, possible: hmac, policy, trial]",
    ),
    (
        None,
        "--hash-alg",
        "<ALG>",
        "[default: sha256, possible: sha256, sha384, sha512]",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for StartSession {
    fn command_type(&self) -> CommandType {
        CommandType::Source
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("start-session", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = StartSession::default();
        parse_args!(parser, arg, Self::help, {
            Long("session-type") => {
                args.session_type = parser.value()?.string()?.parse()?;
            }
            Long("hash-alg") => {
                args.hash_alg = parser.value()?.string()?.parse()?;
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::StartSession(args))
    }

    /// Runs `start-session`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), TpmError> {
        io.clear_input()?;
        let device_arc =
            device.ok_or_else(|| TpmError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| TpmError::Execution("TPM device lock poisoned".to_string()))?;

        let auth_hash = TpmAlgId::from(self.hash_alg);
        let digest_len = tpm2_protocol::tpm_hash_size(&auth_hash)
            .ok_or_else(|| TpmError::Execution("Unsupported hash algorithm".to_string()))?;
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
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

        let handle = start_auth_session_resp.session_handle;
        let algorithm = key::tpm_alg_id_to_str(auth_hash).to_string();

        let session_obj = if self.session_type == crate::cli::SessionType::Policy {
            PipelineObject::PolicySession(PolicySession {
                context: format!("tpm://{handle:#010x}"),
                algorithm,
                digest: hex::encode(vec![0; digest_len]),
            })
        } else {
            PipelineObject::HmacSession(HmacSession {
                context: format!("tpm://{handle:#010x}"),
                algorithm,
            })
        };

        io.push_object(session_obj);
        Ok(())
    }
}

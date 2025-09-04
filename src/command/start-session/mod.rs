// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, DeviceCommand, SessionType, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    session::AuthSession,
};
use lexopt::{Arg, Parser, ValueExt};
use rand::{thread_rng, RngCore};

use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bEncryptedSecret, Tpm2bNonce, TpmAlgId, TpmRh, TpmaSession,
        TpmtSymDefObject, TpmuSymKeyBits, TpmuSymMode,
    },
    message::TpmStartAuthSessionCommand,
    tpm_hash_size,
};

#[derive(Debug, Default)]
pub struct StartSession {
    pub session_type: SessionType,
}

impl Subcommand for StartSession {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut session_type = SessionType::default();
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("session-type") | Arg::Short('s') => {
                    session_type = parser.value()?.parse()?;
                }
                _ => return handle_help(arg),
            }
        }
        Ok(StartSession { session_type })
    }
}

impl DeviceCommand for StartSession {
    /// Runs `start-session`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let auth_hash = TpmAlgId::Sha256;
        let digest_len = tpm_hash_size(&auth_hash)
            .ok_or_else(|| CliError::Execution("Unsupported hash algorithm".to_string()))?;
        let mut nonce_bytes = vec![0; digest_len];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let cmd = TpmStartAuthSessionCommand {
            tpm_key: (TpmRh::Null as u32).into(),
            bind: (TpmRh::Null as u32).into(),
            nonce_caller: Tpm2bNonce::try_from(nonce_bytes.as_slice())?,
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: self.session_type.into(),
            symmetric: TpmtSymDefObject {
                algorithm: TpmAlgId::Null,
                key_bits: TpmuSymKeyBits::Null,
                mode: TpmuSymMode::Null,
            },
            auth_hash,
        };
        let (_rc, response, _) = device.execute(&cmd, &[])?;
        let start_auth_session_resp = response
            .StartAuthSession()
            .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
        let session = AuthSession {
            handle: start_auth_session_resp.session_handle,
            nonce_tpm: start_auth_session_resp.nonce_tpm,
            attributes: TpmaSession::empty(),
            hmac_key: Tpm2bAuth::default(),
            auth_hash,
        };
        writeln!(context.writer, "session://{session}")?;
        Ok(())
    }
}

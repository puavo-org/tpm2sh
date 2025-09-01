// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli::Cli, key::create_auth, util::build_to_vec, CliError};
use log::debug;
use rand::RngCore;
use tpm2_protocol::{
    data::{self, Tpm2bAuth, Tpm2bNonce, TpmAlgId, TpmRh, TpmaSession},
    message::TpmHeader,
    tpm_hash_size, TpmSession,
};

/// Manages the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub handle: TpmSession,
    pub nonce_tpm: data::Tpm2bNonce,
    pub attributes: data::TpmaSession,
    pub hmac_key: data::Tpm2bAuth,
    pub auth_hash: data::TpmAlgId,
}

/// Builds the authorization area for a password-based session.
///
/// # Errors
///
/// Returns `CliError` on failure.
fn build_password_session(password: &str) -> Result<Vec<data::TpmsAuthCommand>, CliError> {
    debug!(target: "cli::session", "building password session: password_len = {}", password.len());
    Ok(vec![data::TpmsAuthCommand {
        session_handle: TpmSession(TpmRh::Password as u32),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password.as_bytes())?,
    }])
}

/// Acquires the authorization session from the global arguments. `--password`
/// and `--session` are mutually exclusive arguments, and using both with result
/// an error. For the time being, `--session` support only HMAC sessions.
///
/// FIXME: `data://` is missing for sessions (only `tpm://` works).
///
/// # Errors
///
/// Returns a `CliError::Usage` if authorization is not valid.
pub fn session_from_args<C: TpmHeader>(
    command: &C,
    handles: &[u32],
    cli: &Cli,
) -> Result<Vec<data::TpmsAuthCommand>, CliError> {
    match (cli.session.clone(), cli.password.clone()) {
        (Some(_), Some(_)) => Err(CliError::Usage(
            "'--session' and '--password' are mutually exclusive".to_string(),
        )),
        (Some(uri), None) => {
            let session = AuthSession {
                handle: TpmSession(uri.to_tpm_handle()?),
                nonce_tpm: Tpm2bNonce::default(),
                attributes: TpmaSession::default(),
                hmac_key: Tpm2bAuth::default(),
                auth_hash: TpmAlgId::Sha256,
            };
            let params = build_to_vec(command)?;
            let nonce_size = tpm_hash_size(&session.auth_hash).ok_or_else(|| {
                CliError::Usage(format!("'{}' is unknown algorithm", session.auth_hash))
            })?;
            let mut nonce_bytes = vec![0; nonce_size];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce_caller = data::Tpm2bNonce::try_from(nonce_bytes.as_slice())?;
            Ok(vec![create_auth(
                &session,
                &nonce_caller,
                C::COMMAND,
                handles,
                &params,
            )?])
        }
        (None, Some(password)) => build_password_session(&password),
        (None, None) => build_password_session(""),
    }
}

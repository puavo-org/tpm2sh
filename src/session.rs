// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Cli,
    key::create_auth,
    pipeline::{CommandIo, Entry as PipelineEntry},
    uri::uri_to_tpm_handle,
    util::build_to_vec,
    CliError,
};
use log::debug;
use rand::RngCore;
use std::io::{Read, Write};
use tpm2_protocol::{
    data::{self, Tpm2bAuth, Tpm2bNonce, TpmRh, TpmaSession},
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
fn build_password_session(password: Option<&str>) -> Result<Vec<data::TpmsAuthCommand>, CliError> {
    match password {
        Some(password) => {
            debug!(target: "cli::session", "building password session: password_len = {}", password.len());
            Ok(vec![data::TpmsAuthCommand {
                session_handle: TpmSession(TpmRh::Password as u32),
                nonce: Tpm2bNonce::default(),
                session_attributes: TpmaSession::empty(),
                hmac: Tpm2bAuth::try_from(password.as_bytes())?,
            }])
        }
        None => Ok(Vec::new()),
    }
}

/// Computes the authorization HMAC for a command session.
///
/// # Errors
///
/// Returns a `CliError` if the session's hash algorithm is not
/// supported, or if an HMAC operation fails.
fn get_auth_for_hmac_session<C>(
    command: &C,
    handles: &[u32],
    session: &AuthSession,
) -> Result<Vec<data::TpmsAuthCommand>, CliError>
where
    C: TpmHeader,
{
    let params = build_to_vec(command)?;

    let nonce_size = tpm_hash_size(&session.auth_hash).ok_or_else(|| {
        CliError::Execution(format!(
            "session has an invalid hash algorithm: {}",
            session.auth_hash
        ))
    })?;

    let mut nonce_bytes = vec![0; nonce_size];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let nonce_caller = data::Tpm2bNonce::try_from(nonce_bytes.as_slice())?;

    Ok(vec![create_auth(
        session,
        &nonce_caller,
        C::COMMAND,
        handles,
        &params,
    )?])
}

/// Prepares the authorization sessions for a command based on the global arguments.
///
/// # Errors
///
/// Returns a `CliError` if authorization cannot be constructed.
pub fn get_sessions_from_args<R: Read, W: Write, C: TpmHeader>(
    io: &mut CommandIo<R, W>,
    command: &C,
    handles: &[u32],
    cli: &Cli,
) -> Result<Vec<data::TpmsAuthCommand>, CliError> {
    if cli.session_uri.is_some() && cli.password.is_some() {
        return Err(CliError::Usage(
            "Cannot use --session and --password at the same time".to_string(),
        ));
    }

    if let Some(uri) = &cli.session_uri {
        let session_entry = io.resolve_entry_from_pipe_uri(uri)?.clone();
        if let PipelineEntry::HmacSession(s) = session_entry {
            let session = AuthSession {
                handle: TpmSession(uri_to_tpm_handle(&s.context)?),
                nonce_tpm: Tpm2bNonce::default(),
                attributes: TpmaSession::default(),
                hmac_key: Tpm2bAuth::default(),
                auth_hash: crate::key::tpm_alg_id_from_str(&s.algorithm)
                    .map_err(CliError::Usage)?,
            };
            return get_auth_for_hmac_session(command, handles, &session);
        }
        return Err(CliError::Usage(format!(
            "URI '{uri}' does not point to a valid session object"
        )));
    }

    if cli.password.is_some() {
        return build_password_session(cli.password.as_deref());
    }

    match io.pop_hmac_session() {
        Ok(s) => {
            let session = AuthSession {
                handle: TpmSession(uri_to_tpm_handle(&s.context)?),
                nonce_tpm: Tpm2bNonce::default(),
                attributes: TpmaSession::default(),
                hmac_key: Tpm2bAuth::default(),
                auth_hash: crate::key::tpm_alg_id_from_str(&s.algorithm)
                    .map_err(CliError::Usage)?,
            };
            get_auth_for_hmac_session(command, handles, &session)
        }
        Err(_) => build_password_session(if C::WITH_SESSIONS { Some("") } else { None }),
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::CommandError,
    error::{CliError, ParseError},
    key::{create_auth, tpm_alg_id_from_str, tpm_alg_id_to_str},
    policy::{self, Expression, Parsing},
    uri::Uri,
    util::build_to_vec,
};
use log::debug;
use rand::RngCore;
use std::fmt;
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

impl AuthSession {
    fn from_ast(ast: &Expression) -> Result<Self, ParseError> {
        if let Expression::Session {
            handle,
            nonce,
            attrs,
            key,
            alg,
        } = ast
        {
            Ok(AuthSession {
                handle: TpmSession(*handle),
                nonce_tpm: Tpm2bNonce::try_from(nonce.as_slice())
                    .map_err(|e| ParseError::Custom(e.to_string()))?,
                attributes: TpmaSession::from_bits_truncate(*attrs),
                hmac_key: Tpm2bAuth::try_from(key.as_slice())
                    .map_err(|e| ParseError::Custom(e.to_string()))?,
                auth_hash: tpm_alg_id_from_str(alg).map_err(ParseError::Custom)?,
            })
        } else {
            Err(ParseError::Custom(
                "expression is not a session".to_string(),
            ))
        }
    }
}

impl fmt::Display for AuthSession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "handle={:#010x};nonce={};attrs={:02x};key={};alg={}",
            self.handle.0,
            hex::encode(self.nonce_tpm),
            self.attributes.bits(),
            hex::encode(self.hmac_key),
            tpm_alg_id_to_str(self.auth_hash)
        )
    }
}

/// Builds the authorization area for a password-based session.
///
/// # Errors
///
/// Returns `CliError` on failure.
fn build_password_session(password: &str) -> Result<Vec<data::TpmsAuthCommand>, CliError> {
    debug!(target: "cli::session", "building password session: password_len = {}", password.len());
    Ok(vec![data::TpmsAuthCommand {
        session_handle: TpmSession(TpmRh::Pw as u32),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password.as_bytes()).map_err(CommandError::from)?,
    }])
}

/// Builds authorization sessions from a URI.
///
/// # Errors
///
/// Returns a `CliError` if authorization is not valid.
pub fn session_from_uri<C: TpmHeader>(
    command: &C,
    handles: &[u32],
    session_uri: Option<&Uri>,
) -> Result<Vec<data::TpmsAuthCommand>, CliError> {
    let Some(uri) = session_uri else {
        return build_password_session("");
    };

    match uri.ast() {
        Expression::Password(password) => build_password_session(password),
        Expression::Session { .. } | Expression::Data { .. } | Expression::FilePath(_) => {
            let session = match uri.ast() {
                Expression::Session { .. } => AuthSession::from_ast(uri.ast())?,
                Expression::Data { .. } | Expression::FilePath(_) => {
                    let session_bytes = uri.to_bytes()?;
                    let session_str =
                        std::str::from_utf8(&session_bytes).map_err(ParseError::from)?;
                    let ast = policy::parse(session_str, Parsing::AuthorizationPolicy)?;
                    AuthSession::from_ast(&ast)?
                }
                _ => unreachable!(),
            };

            let params = build_to_vec(command)?;
            let nonce_size = tpm_hash_size(&session.auth_hash).ok_or_else(|| {
                CommandError::UnsupportedAlgorithm(format!(
                    "'{}' is unknown algorithm",
                    session.auth_hash
                ))
            })?;
            let mut nonce_bytes = vec![0; nonce_size];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce_caller =
                data::Tpm2bNonce::try_from(nonce_bytes.as_slice()).map_err(CommandError::from)?;
            Ok(vec![create_auth(
                &session,
                &nonce_caller,
                C::COMMAND,
                handles,
                &params,
            )?])
        }
        _ => Err(CliError::Command(CommandError::InvalidUriScheme {
            expected: "password://, file://, data://, or session://".to_string(),
            actual: uri.to_string(),
        })),
    }
}

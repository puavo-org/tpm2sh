// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Cli,
    error::ParseError,
    key::{create_auth, tpm_alg_id_from_str, tpm_alg_id_to_str},
    util::{self, build_to_vec},
    CliError,
};
use log::debug;
use pest::Parser;
use pest_derive::Parser;
use rand::RngCore;
use std::{fmt, str::FromStr};
use tpm2_protocol::{
    data::{self, Tpm2bAuth, Tpm2bNonce, TpmRh, TpmaSession},
    message::TpmHeader,
    tpm_hash_size, TpmSession,
};

#[derive(Parser)]
#[grammar = "session.pest"]
pub struct SessionParser;

/// Manages the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub handle: TpmSession,
    pub nonce_tpm: data::Tpm2bNonce,
    pub attributes: data::TpmaSession,
    pub hmac_key: data::Tpm2bAuth,
    pub auth_hash: data::TpmAlgId,
}

impl FromStr for AuthSession {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let pairs_token = SessionParser::parse(Rule::session_content, s)
            .map_err(|e| ParseError::Custom(e.to_string()))?
            .next()
            .unwrap()
            .into_inner()
            .next()
            .unwrap();

        let mut handle = None;
        let mut nonce_tpm = None;
        let mut attributes = None;
        let mut hmac_key = None;
        let mut auth_hash = None;

        for pair in pairs_token.into_inner() {
            if pair.as_rule() == Rule::pair {
                let specific_pair = pair.into_inner().next().unwrap();
                let rule = specific_pair.as_rule();
                let value_str = specific_pair.into_inner().next().unwrap().as_str();

                match rule {
                    Rule::handle_pair => {
                        let h = util::parse_hex_u32(value_str)
                            .map_err(|e| ParseError::Custom(e.to_string()))?;
                        handle = Some(TpmSession(h));
                    }
                    Rule::nonce_pair => {
                        let decoded = hex::decode(value_str)?;
                        let nonce = data::Tpm2bNonce::try_from(decoded.as_slice())
                            .map_err(|e| ParseError::Custom(e.to_string()))?;
                        nonce_tpm = Some(nonce);
                    }
                    Rule::attrs_pair => {
                        let byte = u8::from_str_radix(value_str, 16)?;
                        attributes = Some(data::TpmaSession::from_bits_truncate(byte));
                    }
                    Rule::key_pair => {
                        let decoded = hex::decode(value_str)?;
                        let key = data::Tpm2bAuth::try_from(decoded.as_slice())
                            .map_err(|e| ParseError::Custom(e.to_string()))?;
                        hmac_key = Some(key);
                    }
                    Rule::alg_pair => {
                        auth_hash =
                            Some(tpm_alg_id_from_str(value_str).map_err(ParseError::Custom)?);
                    }
                    _ => unreachable!(),
                }
            }
        }

        Ok(AuthSession {
            handle: handle
                .ok_or_else(|| ParseError::Custom("session URI missing 'handle'".into()))?,
            nonce_tpm: nonce_tpm
                .ok_or_else(|| ParseError::Custom("session URI missing 'nonce'".into()))?,
            attributes: attributes
                .ok_or_else(|| ParseError::Custom("session URI missing 'attrs'".into()))?,
            hmac_key: hmac_key
                .ok_or_else(|| ParseError::Custom("session URI missing 'key'".into()))?,
            auth_hash: auth_hash
                .ok_or_else(|| ParseError::Custom("session URI missing 'alg'".into()))?,
        })
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
        session_handle: TpmSession(TpmRh::Password as u32),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password.as_bytes())?,
    }])
}

/// Acquires the authorization session from the global arguments. `--password`
/// and `--session` are mutually exclusive arguments.
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
            let session = if uri.starts_with("file://") || uri.starts_with("data://") {
                let session_bytes = uri.to_bytes()?;
                let session_str = std::str::from_utf8(&session_bytes)?;
                AuthSession::from_str(session_str)?
            } else if let Some(content) = uri.strip_prefix("session://") {
                AuthSession::from_str(content)?
            } else {
                return Err(CliError::Usage(
                    "the '--session' argument requires a 'file://', 'data://', or 'session://' URI"
                        .to_string(),
                ));
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

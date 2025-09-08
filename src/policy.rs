// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This module contains the parser and executor for the unified policy language.

use crate::{
    command::CommandError,
    device::{TpmDevice, TpmDeviceError},
    error::{CliError, ParseError},
    key::tpm_alg_id_from_str,
    pcr::{pcr_composite_digest, pcr_get_count},
    session::{session_from_uri, SessionType},
    uri::pcr_selection_to_list,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_while, take_while1},
    character::complete::{anychar, char, space0},
    combinator::{map, map_res, opt, recognize},
    multi::{many0, many1, separated_list1},
    sequence::{delimited, pair, preceded, separated_pair, terminated, tuple},
    IResult,
};
use rand::RngCore;
use std::{fmt, path::Path};
use tpm2_protocol::{
    data::{
        Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, TpmAlgId, TpmCc, TpmRh, TpmlDigest, TpmtSymDefObject,
    },
    message::{
        TpmFlushContextCommand, TpmPolicyGetDigestCommand, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicySecretCommand, TpmStartAuthSessionCommand,
    },
    tpm_hash_size, TpmSession,
};

/// Represents the state of a single PCR register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcr {
    pub bank: TpmAlgId,
    pub index: u32,
    pub value: Vec<u8>,
}

/// The Abstract Syntax Tree (AST) for the unified policy language.
#[derive(Debug, PartialEq, Clone)]
pub enum Expression {
    Pcr {
        selection: String,
        digest: Option<String>,
        count: Option<u32>,
    },
    Secret {
        auth_handle_uri: Box<Expression>,
        password: Option<String>,
    },
    Or(Vec<Expression>),
    TpmHandle(u32),
    FilePath(String),
    Data {
        encoding: String,
        value: String,
    },
    Session {
        handle: u32,
        nonce: Vec<u8>,
        attrs: u8,
        key: Vec<u8>,
        alg: String,
    },
    Password(String),
}

impl fmt::Display for Expression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Expression::Pcr {
                selection,
                digest,
                count,
            } => {
                write!(f, "pcr({selection}")?;
                if let Some(d) = digest {
                    write!(f, ", {d}")?;
                }
                if let Some(c) = count {
                    write!(f, ", count={c}")?;
                }
                write!(f, ")")
            }
            Expression::Secret {
                auth_handle_uri,
                password,
            } => {
                write!(f, "secret({auth_handle_uri}")?;
                if let Some(p) = password {
                    write!(f, ", \"{p}\"")?;
                }
                write!(f, ")")
            }
            Expression::Or(branches) => {
                let branch_strs: Vec<String> = branches.iter().map(ToString::to_string).collect();
                write!(f, "or({})", branch_strs.join(", "))
            }
            Expression::TpmHandle(handle) => write!(f, "tpm://{handle:#010x}"),
            Expression::FilePath(path) => write!(f, "file://{path}"),
            Expression::Data { encoding, value } => write!(f, "data://{encoding},{value}"),
            Expression::Session {
                handle,
                nonce,
                attrs,
                key,
                alg,
            } => {
                write!(
                    f,
                    "session://handle={handle:#010x};nonce={};attrs={attrs:02x};key={};alg={alg}",
                    hex::encode(nonce),
                    hex::encode(key)
                )
            }
            Expression::Password(password) => write!(f, "password://{password}"),
        }
    }
}

impl Default for Expression {
    fn default() -> Self {
        Self::FilePath(String::new())
    }
}

/// Defines the parsing context to validate expressions for specific commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Parsing {
    /// Accepts `tpm://`, `file://`, and `data://` URIs.
    Object,
    /// Accepts only `file://` and `data://` URIs.
    Data,
    /// Accepts a PCR selection string, optionally wrapped in `pcr(...)`.
    PcrSelection,
    /// Accepts the full policy language grammar.
    AuthorizationPolicy,
    /// Accepts `session://`, `file://`, or `data://` URIs.
    Session,
}

impl Expression {
    /// Resolves a URI-like expression into bytes.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the expression is not data-like or a file cannot be read.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::CliError> {
        match self {
            Self::FilePath(path) => std::fs::read(Path::new(path))
                .map_err(|e| crate::error::CliError::File(path.clone(), e)),
            Self::Data { encoding, value } => match encoding.as_str() {
                "utf8" => Ok(value.as_bytes().to_vec()),
                "hex" => Ok(hex::decode(value).map_err(ParseError::from)?),
                "base64" => Ok(base64_engine.decode(value).map_err(ParseError::from)?),
                _ => Err(ParseError::Custom(format!(
                    "Unsupported data URI encoding: '{encoding}'"
                ))
                .into()),
            },
            _ => Err(ParseError::Custom(format!("Not a data-like expression: {self:?}")).into()),
        }
    }

    /// Parses a TPM handle from a `tpm://` expression.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the expression is not a `TpmHandle`.
    pub fn to_tpm_handle(&self) -> Result<u32, crate::error::CliError> {
        match self {
            Self::TpmHandle(handle) => Ok(*handle),
            _ => Err(ParseError::Custom(format!("Not a TPM handle expression: {self:?}")).into()),
        }
    }
}

fn is_hex_digit(c: char) -> bool {
    c.is_ascii_hexdigit()
}

fn is_dec_digit(c: char) -> bool {
    c.is_ascii_digit()
}

fn from_hex_str_u32(input: &str) -> Result<u32, std::num::ParseIntError> {
    u32::from_str_radix(input, 16)
}

fn from_hex_str_u8(input: &str) -> Result<u8, std::num::ParseIntError> {
    u8::from_str_radix(input, 16)
}

fn hex_u32(input: &str) -> IResult<&str, u32> {
    map_res(
        preceded(tag("0x"), take_while1(is_hex_digit)),
        from_hex_str_u32,
    )(input)
}

fn hex_u8(input: &str) -> IResult<&str, u8> {
    map_res(take_while1(is_hex_digit), from_hex_str_u8)(input)
}

fn pcr_index(input: &str) -> IResult<&str, u32> {
    map_res(take_while1(is_dec_digit), |s: &str| s.parse::<u32>())(input)
}

fn pcr_list(input: &str) -> IResult<&str, Vec<u32>> {
    separated_list1(char(','), pcr_index)(input)
}

fn alg(input: &str) -> IResult<&str, &str> {
    alt((tag("sha1"), tag("sha256"), tag("sha384"), tag("sha512")))(input)
}

fn pcr_bank(input: &str) -> IResult<&str, String> {
    map(
        separated_pair(alg, char(':'), pcr_list),
        |(alg_str, indices)| {
            format!(
                "{}:{}",
                alg_str,
                indices
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            )
        },
    )(input)
}

fn pcr_selection_body(input: &str) -> IResult<&str, String> {
    map(separated_list1(char('+'), pcr_bank), |banks| {
        banks.join("+")
    })(input)
}

fn unquoted_string(input: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c != ',' && c != ')' && !c.is_whitespace())(input)
}

fn string_argument(input: &str) -> IResult<&str, String> {
    map(
        alt((
            delimited(char('\"'), recognize(many0(is_not("\""))), char('\"')),
            unquoted_string,
        )),
        |s: &str| s.to_string(),
    )(input)
}

fn count_parameter(input: &str) -> IResult<&str, u32> {
    map_res(
        preceded(tag("count="), take_while1(is_dec_digit)),
        |s: &str| s.parse::<u32>(),
    )(input)
}

fn comma_sep<'a, F, O>(f: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    preceded(terminated(char(','), space0), f)
}

fn pcr_expression(input: &str) -> IResult<&str, Expression> {
    map(
        tuple((
            map(pcr_selection_body, |s| s.to_string()),
            opt(comma_sep(map(take_while1(is_hex_digit), |s: &str| {
                s.to_string()
            }))),
            opt(comma_sep(count_parameter)),
        )),
        |(selection, digest, count)| Expression::Pcr {
            selection,
            digest,
            count,
        },
    )(input)
}

fn secret_expression(input: &str) -> IResult<&str, Expression> {
    map(
        tuple((parse_expression, opt(comma_sep(string_argument)))),
        |(uri_expr, password)| Expression::Secret {
            auth_handle_uri: Box::new(uri_expr),
            password,
        },
    )(input)
}

fn or_expression(input: &str) -> IResult<&str, Expression> {
    map(
        pair(
            parse_expression,
            many1(preceded(terminated(char(','), space0), parse_expression)),
        ),
        |(first, mut rest)| {
            let mut branches = vec![first];
            branches.append(&mut rest);
            Expression::Or(branches)
        },
    )(input)
}

fn call<'a, F, O>(name: &'static str, f: F) -> impl FnMut(&'a str) -> IResult<&'a str, O>
where
    F: FnMut(&'a str) -> IResult<&'a str, O>,
{
    delimited(
        terminated(tag(name), char('(')),
        delimited(space0, f, space0),
        char(')'),
    )
}

fn tpm_uri(input: &str) -> IResult<&str, Expression> {
    map(preceded(tag("tpm://"), hex_u32), Expression::TpmHandle)(input)
}

fn file_uri(input: &str) -> IResult<&str, Expression> {
    map(
        preceded(tag("file://"), take_while1(|c| c != ',' && c != ')')),
        |s: &str| Expression::FilePath(s.to_string()),
    )(input)
}

fn data_uri(input: &str) -> IResult<&str, Expression> {
    map(
        preceded(
            tag("data://"),
            separated_pair(
                alt((tag("utf8"), tag("hex"), tag("base64"))),
                char(','),
                take_while(|c: char| c != ',' && c != ')'),
            ),
        ),
        |(enc, val): (&str, &str)| Expression::Data {
            encoding: enc.to_string(),
            value: val.to_string(),
        },
    )(input)
}

fn pcr_uri(input: &str) -> IResult<&str, Expression> {
    map(preceded(tag("pcr://"), pcr_selection_body), |selection| {
        Expression::Pcr {
            selection,
            digest: None,
            count: None,
        }
    })(input)
}

fn session_kv_pair(input: &str) -> IResult<&str, (&str, &str)> {
    separated_pair(
        alt((
            tag("handle"),
            tag("nonce"),
            tag("attrs"),
            tag("key"),
            tag("alg"),
        )),
        char('='),
        alt((
            recognize(hex_u32),
            recognize(hex_u8),
            alg,
            take_while(is_hex_digit),
        )),
    )(input)
}

fn session_kv_list(input: &str) -> IResult<&str, Vec<(&str, &str)>> {
    separated_list1(char(';'), session_kv_pair)(input)
}

fn session_body(input: &str) -> IResult<&str, Expression> {
    map_res(session_kv_list, |pairs| -> Result<_, String> {
        let mut handle = None;
        let mut nonce = None;
        let mut attrs = None;
        let mut key = None;
        let mut alg = None;
        for (k, v) in pairs {
            match k {
                "handle" => {
                    let stripped_v = v
                        .strip_prefix("0x")
                        .ok_or_else(|| "handle value must start with 0x".to_string())?;
                    handle = Some(from_hex_str_u32(stripped_v).map_err(|e| e.to_string())?);
                }
                "nonce" => nonce = Some(hex::decode(v).map_err(|e| e.to_string())?),
                "attrs" => attrs = Some(from_hex_str_u8(v).map_err(|e| e.to_string())?),
                "key" => key = Some(hex::decode(v).map_err(|e| e.to_string())?),
                "alg" => alg = Some(v.to_string()),
                _ => unreachable!(),
            }
        }
        Ok(Expression::Session {
            handle: handle.ok_or_else(|| "missing handle".to_string())?,
            nonce: nonce.ok_or_else(|| "missing nonce".to_string())?,
            attrs: attrs.ok_or_else(|| "missing attrs".to_string())?,
            key: key.ok_or_else(|| "missing key".to_string())?,
            alg: alg.ok_or_else(|| "missing alg".to_string())?,
        })
    })(input)
}

fn session_uri(input: &str) -> IResult<&str, Expression> {
    preceded(tag("session://"), session_body)(input)
}

fn password_uri(input: &str) -> IResult<&str, Expression> {
    map(
        preceded(tag("password://"), recognize(many0(anychar))),
        |s: &str| Expression::Password(s.to_string()),
    )(input)
}

/// Parses any valid expression.
fn parse_expression(input: &str) -> IResult<&str, Expression> {
    alt((
        call("pcr", pcr_expression),
        call("secret", secret_expression),
        call("or", or_expression),
        tpm_uri,
        file_uri,
        data_uri,
        pcr_uri,
        session_uri,
        password_uri,
    ))(input)
}

/// Parses an expression string, ensuring the entire input is consumed and conforms to the mode.
///
/// # Errors
///
/// Returns a `ParseError` if the input is not a valid expression for the given mode,
/// or if there is trailing input left after parsing.
pub fn parse(input: &str, mode: Parsing) -> Result<Expression, ParseError> {
    let (remaining, expr) =
        parse_expression(input).map_err(|e| ParseError::Custom(e.to_string()))?;

    if !remaining.is_empty() {
        return Err(ParseError::Custom(format!(
            "unexpected trailing input: '{remaining}'"
        )));
    }

    let is_valid = match (mode, &expr) {
        (Parsing::PcrSelection, Expression::Pcr { digest, count, .. }) => {
            digest.is_none() && count.is_none()
        }
        (Parsing::AuthorizationPolicy, _)
        | (
            Parsing::Object,
            Expression::TpmHandle(_) | Expression::FilePath(_) | Expression::Data { .. },
        )
        | (Parsing::Data, Expression::FilePath(_) | Expression::Data { .. })
        | (
            Parsing::Session,
            Expression::Session { .. }
            | Expression::FilePath(_)
            | Expression::Data { .. }
            | Expression::Password(_),
        ) => true,
        _ => false,
    };

    if is_valid {
        Ok(expr)
    } else {
        Err(ParseError::Custom(format!(
            "expression '{input}' is not valid for the expected mode '{mode:?}'"
        )))
    }
}

pub struct PolicyExecutor<'a> {
    pcr_count: usize,
    device: &'a mut TpmDevice,
    session_hash_alg: TpmAlgId,
}

impl<'a> PolicyExecutor<'a> {
    pub fn new(pcr_count: usize, device: &'a mut TpmDevice, session_hash_alg: TpmAlgId) -> Self {
        Self {
            pcr_count,
            device,
            session_hash_alg,
        }
    }

    pub fn device(&mut self) -> &mut TpmDevice {
        self.device
    }

    /// Executes a policy AST against a given trial session handle.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if any underlying TPM command fails or if the policy
    /// expression is malformed or invalid for execution.
    pub fn execute_policy_ast(
        &mut self,
        session_handle: TpmSession,
        ast: &Expression,
    ) -> Result<(), CliError> {
        match ast {
            Expression::Pcr {
                selection,
                digest,
                count,
            } => {
                self.execute_pcr_policy(session_handle, selection, digest.as_ref(), count.as_ref())
            }
            Expression::Secret {
                auth_handle_uri,
                password,
            } => self.execute_secret_policy(session_handle, auth_handle_uri, password.as_ref()),
            Expression::Or(branches) => self.execute_or_policy(session_handle, branches),
            _ => Err(
                ParseError::Custom("unsupported expression for policy command".to_string()).into(),
            ),
        }
    }

    fn execute_pcr_policy(
        &mut self,
        session_handle: TpmSession,
        selection_str: &str,
        digest: Option<&String>,
        _count: Option<&u32>,
    ) -> Result<(), CliError> {
        let pcr_digest_bytes = if let Some(digest_hex) = digest {
            hex::decode(digest_hex).map_err(ParseError::from)?
        } else {
            let pcr_selection_in = pcr_selection_to_list(selection_str, self.pcr_count)?;
            let pcr_values = crate::pcr::read(self.device, &pcr_selection_in)?;
            pcr_composite_digest(&pcr_values, self.session_hash_alg)?
        };

        let pcr_selection = pcr_selection_to_list(selection_str, self.pcr_count)?;
        let pcr_digest =
            Tpm2bDigest::try_from(pcr_digest_bytes.as_slice()).map_err(CommandError::from)?;

        let cmd = TpmPolicyPcrCommand {
            policy_session: session_handle.0.into(),
            pcr_digest,
            pcrs: pcr_selection,
        };
        let (_rc, _, _) = self.device.execute(&cmd, &[])?;
        Ok(())
    }

    fn execute_secret_policy(
        &mut self,
        session_handle: TpmSession,
        auth_handle_uri: &Expression,
        password: Option<&String>,
    ) -> Result<(), CliError> {
        let auth_handle = match auth_handle_uri {
            Expression::TpmHandle(handle) => Ok(*handle),
            _ => Err(ParseError::Custom(
                "secret policy requires a tpm:// handle".to_string(),
            )),
        }?;
        let cmd = TpmPolicySecretCommand {
            auth_handle: auth_handle.into(),
            policy_session: session_handle.0.into(),
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };
        let handles = [auth_handle, session_handle.into()];
        let mut temp_uri_storage = None;
        if let Some(p) = password {
            temp_uri_storage = Some(format!("password://{p}").parse()?);
        }
        let sessions = session_from_uri(&cmd, &handles, temp_uri_storage.as_ref())?;
        let (_rc, _, _) = self.device.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_or_policy(
        &mut self,
        session_handle: TpmSession,
        branches: &[Expression],
    ) -> Result<(), CliError> {
        let mut branch_digests = TpmlDigest::new();
        for branch_ast in branches {
            let branch_handle =
                start_trial_session(self.device, SessionType::Trial, self.session_hash_alg)?;
            self.execute_policy_ast(branch_handle, branch_ast)?;

            let digest = get_policy_digest(self.device, branch_handle)?;
            branch_digests
                .try_push(digest)
                .map_err(CommandError::from)?;

            flush_session(self.device, branch_handle)?;
        }

        let cmd = TpmPolicyOrCommand {
            policy_session: session_handle.0.into(),
            p_hash_list: branch_digests,
        };
        let (_rc, _, _) = self.device.execute(&cmd, &[])?;
        Ok(())
    }
}

pub(crate) fn start_trial_session(
    device: &mut TpmDevice,
    session_type: SessionType,
    hash_alg: TpmAlgId,
) -> Result<TpmSession, CliError> {
    let digest_len = tpm_hash_size(&hash_alg).ok_or_else(|| {
        CommandError::UnsupportedAlgorithm(format!(
            "Unsupported hash algorithm for session: {hash_alg}"
        ))
    })?;
    let mut nonce_bytes = vec![0; digest_len];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cmd = TpmStartAuthSessionCommand {
        tpm_key: (TpmRh::Null as u32).into(),
        bind: (TpmRh::Null as u32).into(),
        nonce_caller: Tpm2bNonce::try_from(nonce_bytes.as_slice()).map_err(CommandError::from)?,
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: session_type.into(),
        symmetric: TpmtSymDefObject::default(),
        auth_hash: hash_alg,
    };
    let (_rc, resp, _) = device.execute(&cmd, &[])?;
    let start_resp = resp
        .StartAuthSession()
        .map_err(|_| TpmDeviceError::MismatchedResponse {
            command: TpmCc::StartAuthSession,
        })?;
    Ok(start_resp.session_handle)
}

pub(crate) fn flush_session(device: &mut TpmDevice, handle: TpmSession) -> Result<(), CliError> {
    let cmd = TpmFlushContextCommand {
        flush_handle: handle.into(),
    };
    let (_rc, _, _) = device.execute(&cmd, &[])?;
    Ok(())
}

pub(crate) fn get_policy_digest(
    device: &mut TpmDevice,
    session_handle: TpmSession,
) -> Result<Tpm2bDigest, CliError> {
    let cmd = TpmPolicyGetDigestCommand {
        policy_session: session_handle.0.into(),
    };
    let (_rc, resp, _) = device.execute(&cmd, &[])?;
    let digest_resp = resp
        .PolicyGetDigest()
        .map_err(|_| TpmDeviceError::MismatchedResponse {
            command: TpmCc::PolicyGetDigest,
        })?;
    Ok(digest_resp.policy_digest)
}

/// Recursively traverses a policy AST and fills in any missing PCR digests by reading from the TPM.
///
/// # Errors
///
/// Returns a `CliError` if reading PCR values from the TPM fails or if a
/// PCR selection string is malformed.
pub fn fill_pcr_digests(ast: &mut Expression, device: &mut TpmDevice) -> Result<(), CliError> {
    match ast {
        Expression::Pcr {
            selection, digest, ..
        } => {
            if digest.is_none() {
                let pcr_count = pcr_get_count(device)?;
                let pcr_selection_in = pcr_selection_to_list(selection, pcr_count)?;
                let pcr_values = crate::pcr::read(device, &pcr_selection_in)?;
                let (alg_str, _) =
                    selection
                        .split_once(':')
                        .ok_or(CommandError::InvalidPcrSelection(format!(
                            "invalid PCR bank format in selection: '{selection}'"
                        )))?;
                let alg_id =
                    tpm_alg_id_from_str(alg_str).map_err(CommandError::UnsupportedAlgorithm)?;
                let composite_digest = pcr_composite_digest(&pcr_values, alg_id)?;
                *digest = Some(hex::encode(composite_digest));
            }
        }
        Expression::Or(branches) => {
            for branch in branches {
                fill_pcr_digests(branch, device)?;
            }
        }
        Expression::Secret {
            auth_handle_uri, ..
        } => {
            fill_pcr_digests(auth_handle_uri, device)?;
        }
        _ => {}
    }
    Ok(())
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This module contains the parser and executor for the unified policy language.

use crate::{
    crypto::crypto_hmac,
    device::{TpmDevice, TpmDeviceError},
    util::build_to_vec,
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
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{fmt, ops::Deref, path::Path, str::FromStr};
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, TpmAlgId, TpmCap, TpmCc, TpmRc,
        TpmRh, TpmSe, TpmaSession, TpmlDigest, TpmlPcrSelection, TpmsAuthCommand, TpmsPcrSelection,
        TpmtSymDefObject, TpmuCapabilities, TPM_PCR_SELECT_MAX,
    },
    message::{
        TpmFlushContextCommand, TpmHeader, TpmPcrReadCommand, TpmPolicyGetDigestCommand,
        TpmPolicyOrCommand, TpmPolicyPcrCommand, TpmPolicySecretCommand,
        TpmStartAuthSessionCommand,
    },
    tpm_hash_size, TpmBuffer, TpmErrorKind, TpmSession,
};

#[derive(Debug)]
pub enum PolicyError {
    Device(TpmDeviceError),
    InvalidAlgorithm(TpmAlgId),
    InvalidAlgorithmName(String),
    InvalidPcrSelection(String),
    InvalidExpression(String),
    InvalidValue(String),
    Io(std::io::Error),
    Tpm(TpmErrorKind),
    TpmRc(TpmRc),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(e) => write!(f, "device: {e}"),
            Self::InvalidAlgorithm(alg) => write!(f, "invalid algorithm: {alg:?}"),
            Self::InvalidAlgorithmName(name) => write!(f, "invalid algorithm name: '{name}'"),
            Self::InvalidPcrSelection(s) => write!(f, "invalid PCR selection: {s}"),
            Self::InvalidExpression(s) => write!(f, "invalid expression: {s}"),
            Self::InvalidValue(s) => write!(f, "invalid value: {s}"),
            Self::Io(s) => write!(f, "I/O: {s}"),
            Self::Tpm(err) => write!(f, "TPM: {err}"),
            Self::TpmRc(rc) => write!(f, "TPM RC: {rc}"),
        }
    }
}

impl std::error::Error for PolicyError {}

impl From<hex::FromHexError> for PolicyError {
    fn from(err: hex::FromHexError) -> Self {
        Self::InvalidValue(err.to_string())
    }
}
impl From<base64::DecodeError> for PolicyError {
    fn from(err: base64::DecodeError) -> Self {
        Self::InvalidValue(err.to_string())
    }
}
impl From<std::num::ParseIntError> for PolicyError {
    fn from(err: std::num::ParseIntError) -> Self {
        Self::InvalidValue(err.to_string())
    }
}
impl From<std::str::Utf8Error> for PolicyError {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::InvalidValue(err.to_string())
    }
}
impl From<std::io::Error> for PolicyError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<TpmRc> for PolicyError {
    fn from(rc: TpmRc) -> Self {
        Self::TpmRc(rc)
    }
}

impl From<TpmErrorKind> for PolicyError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Tpm(err)
    }
}

impl From<TpmDeviceError> for PolicyError {
    fn from(err: TpmDeviceError) -> Self {
        Self::Device(err)
    }
}

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
    /// Returns a `PolicyError` if the expression is not data-like or a file cannot be read.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        match self {
            Self::FilePath(path) => Ok(std::fs::read(Path::new(path))?),
            Self::Data { encoding, value } => match encoding.as_str() {
                "utf8" => Ok(value.as_bytes().to_vec()),
                "hex" => Ok(hex::decode(value)?),
                "base64" => Ok(base64_engine.decode(value)?),
                _ => Err(PolicyError::InvalidExpression(format!(
                    "Unsupported data URI encoding: '{encoding}'"
                ))),
            },
            _ => Err(PolicyError::InvalidExpression(format!(
                "Not a data-like expression: {self:?}"
            ))),
        }
    }

    /// Parses a TPM handle from a `tpm://` expression.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyError` if the expression is not a `TpmHandle`.
    pub fn to_tpm_handle(&self) -> Result<u32, PolicyError> {
        match self {
            Self::TpmHandle(handle) => Ok(*handle),
            _ => Err(PolicyError::InvalidExpression(format!(
                "Not a TPM handle expression: {self:?}"
            ))),
        }
    }
}

/// Converts a user-friendly string to a `TpmAlgId`.
///
/// # Errors
///
/// If the algorithm tag is unknown, `PolicyError` will be returned.
pub fn alg_from_str(s: &str) -> Result<TpmAlgId, PolicyError> {
    match s {
        "rsa" => Ok(TpmAlgId::Rsa),
        "sha1" => Ok(TpmAlgId::Sha1),
        "hmac" => Ok(TpmAlgId::Hmac),
        "aes" => Ok(TpmAlgId::Aes),
        "keyedhash" => Ok(TpmAlgId::KeyedHash),
        "xor" => Ok(TpmAlgId::Xor),
        "sha256" => Ok(TpmAlgId::Sha256),
        "sha384" => Ok(TpmAlgId::Sha384),
        "sha512" => Ok(TpmAlgId::Sha512),
        "null" => Ok(TpmAlgId::Null),
        "sm3_256" => Ok(TpmAlgId::Sm3_256),
        "sm4" => Ok(TpmAlgId::Sm4),
        "ecc" => Ok(TpmAlgId::Ecc),
        _ => Err(PolicyError::InvalidAlgorithmName(s.to_string())),
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
/// Returns a `PolicyError` if the input is not a valid expression for the given mode,
/// or if there is trailing input left after parsing.
pub fn parse(input: &str, mode: Parsing) -> Result<Expression, PolicyError> {
    let (remaining, expr) =
        parse_expression(input).map_err(|e| PolicyError::InvalidExpression(e.to_string()))?;

    if !remaining.is_empty() {
        return Err(PolicyError::InvalidExpression(format!(
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
        Err(PolicyError::InvalidExpression(format!(
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
    /// Returns a `PolicyError` if any underlying TPM command fails or if the policy
    /// expression is malformed or invalid for execution.
    pub fn execute_policy_ast(
        &mut self,
        session_handle: TpmSession,
        ast: &Expression,
    ) -> Result<(), PolicyError> {
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
            _ => Err(PolicyError::InvalidExpression(
                "unsupported expression for policy command".to_string(),
            )),
        }
    }

    fn execute_pcr_policy(
        &mut self,
        session_handle: TpmSession,
        selection_str: &str,
        digest: Option<&String>,
        _count: Option<&u32>,
    ) -> Result<(), PolicyError> {
        let pcr_digest_bytes = if let Some(digest_hex) = digest {
            hex::decode(digest_hex)?
        } else {
            let pcr_selection_in = pcr_selection_to_list(selection_str, self.pcr_count)?;
            let pcr_values = read(self.device, &pcr_selection_in)?;
            pcr_composite_digest(&pcr_values, self.session_hash_alg)?
        };

        let pcr_selection = pcr_selection_to_list(selection_str, self.pcr_count)?;
        let pcr_digest = Tpm2bDigest::try_from(pcr_digest_bytes.as_slice())?;

        let cmd = TpmPolicyPcrCommand {
            policy_session: session_handle.0.into(),
            pcr_digest,
            pcrs: pcr_selection,
        };
        let (_, _) = self.device.execute(&cmd, &[])?;
        Ok(())
    }

    fn execute_secret_policy(
        &mut self,
        session_handle: TpmSession,
        auth_handle_uri: &Expression,
        password: Option<&String>,
    ) -> Result<(), PolicyError> {
        let auth_handle = match auth_handle_uri {
            Expression::TpmHandle(handle) => Ok(*handle),
            _ => Err(PolicyError::InvalidExpression(
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
        let (_, _) = self.device.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_or_policy(
        &mut self,
        session_handle: TpmSession,
        branches: &[Expression],
    ) -> Result<(), PolicyError> {
        let mut branch_digests = TpmlDigest::new();
        for branch_ast in branches {
            let branch_handle =
                start_trial_session(self.device, SessionType::Trial, self.session_hash_alg)?;
            self.execute_policy_ast(branch_handle, branch_ast)?;

            let digest = get_policy_digest(self.device, branch_handle)?;
            branch_digests.try_push(digest)?;

            flush_session(self.device, branch_handle)?;
        }

        let cmd = TpmPolicyOrCommand {
            policy_session: session_handle.0.into(),
            p_hash_list: branch_digests,
        };
        let (_, _) = self.device.execute(&cmd, &[])?;
        Ok(())
    }
}

pub(crate) fn start_trial_session(
    device: &mut TpmDevice,
    session_type: SessionType,
    hash_alg: TpmAlgId,
) -> Result<TpmSession, PolicyError> {
    let digest_len = tpm_hash_size(&hash_alg).ok_or(PolicyError::InvalidAlgorithm(hash_alg))?;
    let mut nonce_bytes = vec![0; digest_len];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);

    let cmd = TpmStartAuthSessionCommand {
        tpm_key: (TpmRh::Null as u32).into(),
        bind: (TpmRh::Null as u32).into(),
        nonce_caller: Tpm2bNonce::try_from(nonce_bytes.as_slice())?,
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: session_type.into(),
        symmetric: TpmtSymDefObject::default(),
        auth_hash: hash_alg,
    };
    let (resp, _) = device.execute(&cmd, &[])?;
    let start_resp = resp
        .StartAuthSession()
        .map_err(|_| TpmDeviceError::MismatchedResponse {
            command: TpmCc::StartAuthSession,
        })?;
    Ok(start_resp.session_handle)
}

pub(crate) fn flush_session(device: &mut TpmDevice, handle: TpmSession) -> Result<(), PolicyError> {
    let cmd = TpmFlushContextCommand {
        flush_handle: handle.into(),
    };
    let (_, _) = device.execute(&cmd, &[])?;
    Ok(())
}

pub(crate) fn get_policy_digest(
    device: &mut TpmDevice,
    session_handle: TpmSession,
) -> Result<Tpm2bDigest, PolicyError> {
    let cmd = TpmPolicyGetDigestCommand {
        policy_session: session_handle.0.into(),
    };
    let (resp, _) = device.execute(&cmd, &[])?;
    let digest_resp = resp
        .PolicyGetDigest()
        .map_err(|_| TpmDeviceError::MismatchedResponse {
            command: TpmCc::PcrRead,
        })?;
    Ok(digest_resp.policy_digest)
}

/// Recursively traverses a policy AST and fills in any missing PCR digests by reading from the TPM.
///
/// # Errors
///
/// Returns a `PolicyError` if reading PCR values from the TPM fails or if a
/// PCR selection string is malformed.
pub fn fill_pcr_digests(ast: &mut Expression, device: &mut TpmDevice) -> Result<(), PolicyError> {
    match ast {
        Expression::Pcr {
            selection, digest, ..
        } => {
            if digest.is_none() {
                let pcr_count = pcr_get_count(device)?;
                let pcr_selection_in = pcr_selection_to_list(selection, pcr_count)?;
                let pcr_values = read(device, &pcr_selection_in)?;
                let (alg_str, _) =
                    selection
                        .split_once(':')
                        .ok_or(PolicyError::InvalidPcrSelection(format!(
                            "invalid PCR bank format in selection: '{selection}'"
                        )))?;
                let alg_id = alg_from_str(alg_str)?;
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

/// Reads the selected PCRs and returns them in a structured format.
///
/// This function serves as the high-level API for reading PCRs, abstracting away
/// the complexity of the raw TPM response.
///
/// # Errors
///
/// Returns a `PolicyError` if the TPM command fails or the response is inconsistent.
pub fn read(
    device: &mut TpmDevice,
    pcr_selection_in: &TpmlPcrSelection,
) -> Result<Vec<Pcr>, PolicyError> {
    let cmd = TpmPcrReadCommand {
        pcr_selection_in: *pcr_selection_in,
    };
    let (resp, _) = device.execute(&cmd, &[])?;
    let pcr_read_resp = resp
        .PcrRead()
        .map_err(|_| TpmDeviceError::MismatchedResponse {
            command: TpmCc::PcrRead,
        })?;

    let mut pcrs = Vec::new();
    let mut digest_iter = pcr_read_resp.pcr_values.iter();

    for selection in pcr_read_resp.pcr_selection_out.iter() {
        for (byte_idx, &byte) in selection.pcr_select.iter().enumerate() {
            if byte == 0 {
                continue;
            }
            for bit_idx in 0..8 {
                if (byte >> bit_idx) & 1 == 1 {
                    let pcr_index = u32::try_from(byte_idx * 8 + bit_idx).map_err(|_| {
                        PolicyError::InvalidPcrSelection("PCR index conversion failed".to_string())
                    })?;
                    let value = digest_iter.next().ok_or_else(|| {
                        PolicyError::InvalidPcrSelection("PCR selection mismatch".to_string())
                    })?;
                    pcrs.push(Pcr {
                        bank: selection.hash,
                        index: pcr_index,
                        value: value.to_vec(),
                    });
                }
            }
        }
    }

    Ok(pcrs)
}

/// Gets the number of PCRs from the TPM.
pub(crate) fn pcr_get_count(device: &mut TpmDevice) -> Result<usize, PolicyError> {
    let cap_data = device.get_capability(TpmCap::Pcrs, 0, crate::device::TPM_CAP_PROPERTY_MAX)?;
    let Some(first_cap) = cap_data.into_iter().next() else {
        return Err(PolicyError::InvalidPcrSelection(
            "TPM reported no capabilities for PCRs.".to_string(),
        ));
    };

    if let TpmuCapabilities::Pcrs(pcrs) = first_cap.data {
        if let Some(first_bank) = pcrs.iter().next() {
            Ok(first_bank.pcr_select.len() * 8)
        } else {
            Err(PolicyError::InvalidPcrSelection(
                "TPM reported no active PCR banks.".to_string(),
            ))
        }
    } else {
        Err(PolicyError::Device(TpmDeviceError::InvalidResponse(
            "Unexpected capability data type when querying for PCRs.".to_string(),
        )))
    }
}

/// Computes a composite digest from a set of PCRs using a specified algorithm.
///
/// # Errors
///
/// Returns a `PolicyError` on failure.
pub(crate) fn pcr_composite_digest(pcrs: &[Pcr], alg: TpmAlgId) -> Result<Vec<u8>, PolicyError> {
    let mut composite = Vec::new();
    for pcr in pcrs {
        composite.extend_from_slice(&pcr.value);
    }
    match alg {
        TpmAlgId::Sha256 => Ok(Sha256::digest(&composite).to_vec()),
        TpmAlgId::Sha384 => Ok(Sha384::digest(&composite).to_vec()),
        TpmAlgId::Sha512 => Ok(Sha512::digest(&composite).to_vec()),
        _ => Err(PolicyError::InvalidAlgorithm(alg)),
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SessionType {
    #[default]
    Hmac,
    Policy,
    Trial,
}

impl FromStr for SessionType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hmac" => Ok(Self::Hmac),
            "policy" => Ok(Self::Policy),
            "trial" => Ok(Self::Trial),
            _ => Err("invalid session type".to_string()),
        }
    }
}

impl From<SessionType> for TpmSe {
    fn from(val: SessionType) -> Self {
        match val {
            SessionType::Hmac => Self::Hmac,
            SessionType::Policy => Self::Policy,
            SessionType::Trial => Self::Trial,
        }
    }
}

/// Manages the state of an active authorization session.
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub handle: TpmSession,
    pub nonce_tpm: Tpm2bNonce,
    pub attributes: TpmaSession,
    pub hmac_key: Tpm2bAuth,
    pub auth_hash: TpmAlgId,
}

impl AuthSession {
    fn from_ast(ast: &Expression) -> Result<Self, PolicyError> {
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
                    .map_err(|e| PolicyError::InvalidExpression(e.to_string()))?,
                attributes: TpmaSession::from_bits_truncate(*attrs),
                hmac_key: Tpm2bAuth::try_from(key.as_slice())
                    .map_err(|e| PolicyError::InvalidExpression(e.to_string()))?,
                auth_hash: alg_from_str(alg)?,
            })
        } else {
            Err(PolicyError::InvalidExpression(
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
            format!("{:?}", self.auth_hash).to_lowercase()
        )
    }
}

/// Builds the authorization area for a password-based session.
///
/// # Errors
///
/// Returns `PolicyError` on failure.
fn build_password_session(password: &str) -> Result<Vec<TpmsAuthCommand>, PolicyError> {
    Ok(vec![TpmsAuthCommand {
        session_handle: TpmSession(TpmRh::Pw as u32),
        nonce: Tpm2bNonce::default(),
        session_attributes: TpmaSession::empty(),
        hmac: Tpm2bAuth::try_from(password.as_bytes())?,
    }])
}

/// Builds authorization sessions from a URI.
///
/// # Errors
///
/// Returns a `PolicyError` if authorization is not valid.
pub fn session_from_uri<C: TpmHeader>(
    command: &C,
    handles: &[u32],
    session_uri: Option<&Uri>,
) -> Result<Vec<TpmsAuthCommand>, PolicyError> {
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
                    let session_str = std::str::from_utf8(&session_bytes)?;
                    let ast = parse(session_str, Parsing::AuthorizationPolicy)?;
                    AuthSession::from_ast(&ast)?
                }
                _ => unreachable!(),
            };

            let params = build_to_vec(command)?;
            let nonce_size = tpm_hash_size(&session.auth_hash)
                .ok_or(PolicyError::InvalidAlgorithm(session.auth_hash))?;
            let mut nonce_bytes = vec![0; nonce_size];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let nonce_caller = Tpm2bNonce::try_from(nonce_bytes.as_slice())?;
            Ok(vec![create_auth(
                &session,
                &nonce_caller,
                C::COMMAND,
                handles,
                &params,
            )?])
        }
        _ => Err(PolicyError::InvalidExpression(format!(
            "invalid URI scheme for session: expected password://, file://, data://, or session://, found {uri}"
        ))),
    }
}

/// Computes the authorization HMAC for a command session.
///
/// # Errors
///
/// Returns a `PolicyError` if the session's hash algorithm is not
/// supported, or if an HMAC operation fails.
fn create_auth(
    session: &AuthSession,
    nonce_caller: &Tpm2bNonce,
    command_code: TpmCc,
    handles: &[u32],
    parameters: &[u8],
) -> Result<TpmsAuthCommand, PolicyError> {
    let cp_hash_payload = {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(command_code as u32).to_be_bytes());
        for handle in handles {
            payload.extend_from_slice(&handle.to_be_bytes());
        }
        payload.extend_from_slice(parameters);
        payload
    };

    let cp_hash = match session.auth_hash {
        TpmAlgId::Sha256 => Sha256::digest(&cp_hash_payload).to_vec(),
        TpmAlgId::Sha384 => Sha384::digest(&cp_hash_payload).to_vec(),
        TpmAlgId::Sha512 => Sha512::digest(&cp_hash_payload).to_vec(),
        alg => return Err(PolicyError::InvalidAlgorithm(alg)),
    };

    let hmac_bytes = crypto_hmac(
        session.auth_hash,
        &session.hmac_key,
        &[
            &cp_hash,
            &session.nonce_tpm,
            nonce_caller,
            &[session.attributes.bits()],
        ],
    )?;

    Ok(TpmsAuthCommand {
        session_handle: session.handle,
        nonce: *nonce_caller,
        session_attributes: session.attributes,
        hmac: Tpm2bAuth::try_from(hmac_bytes.as_slice())?,
    })
}

/// Parses a PCR selection string (e.g., "sha256:0,7+sha1:1") into a TPM list.
pub(crate) fn pcr_selection_to_list(
    selection_str: &str,
    pcr_count: usize,
) -> Result<TpmlPcrSelection, PolicyError> {
    let mut list = TpmlPcrSelection::new();
    let pcr_select_size = pcr_count.div_ceil(8);
    if pcr_select_size > TPM_PCR_SELECT_MAX {
        return Err(PolicyError::InvalidPcrSelection(format!(
            "required pcr select size {pcr_select_size} exceeds maximum {TPM_PCR_SELECT_MAX}"
        )));
    }

    for bank_str in selection_str.split('+') {
        let (alg_str, indices_str) = bank_str.split_once(':').ok_or_else(|| {
            PolicyError::InvalidPcrSelection(format!("invalid bank format: '{bank_str}'"))
        })?;
        let alg = PcrAlgId::from_str(alg_str)
            .map_err(|()| {
                PolicyError::InvalidPcrSelection(format!("invalid algorithm: {alg_str}"))
            })?
            .0;

        let mut pcr_select_bytes = vec![0u8; pcr_select_size];
        for index_str in indices_str.split(',') {
            let pcr_index: usize = index_str.parse()?;

            if pcr_index >= pcr_count {
                return Err(PolicyError::InvalidPcrSelection(format!(
                    "pcr index {pcr_index} is out of range for a TPM with {pcr_count} PCRs"
                )));
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }
        list.try_push(TpmsPcrSelection {
            hash: alg,
            pcr_select: TpmBuffer::try_from(pcr_select_bytes.as_slice())?,
        })?;
    }
    Ok(list)
}

struct PcrAlgId(TpmAlgId);

impl FromStr for PcrAlgId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha1" => Ok(Self(TpmAlgId::Sha1)),
            "sha256" => Ok(Self(TpmAlgId::Sha256)),
            "sha384" => Ok(Self(TpmAlgId::Sha384)),
            "sha512" => Ok(Self(TpmAlgId::Sha512)),
            _ => Err(()),
        }
    }
}

/// URI data type used for the input data. The input is fully validated,
/// and only legit URIs get passed to the subcommands.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Uri(String, Expression);

impl Deref for Uri {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Uri {
    type Err = PolicyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ast = parse(s, Parsing::AuthorizationPolicy)?;
        Ok(Self(s.to_string(), ast))
    }
}

impl Uri {
    /// Returns the parsed AST of the URI
    #[must_use]
    pub fn ast(&self) -> &Expression {
        &self.1
    }

    /// Resolves a URI string into bytes.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyError` if the URI is malformed or a file cannot be read.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PolicyError> {
        self.1.to_bytes()
    }

    /// Parses a TPM handle from a `tpm://` URI string.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyError` if the URI is not a `tpm://` URI.
    pub fn to_tpm_handle(&self) -> Result<u32, PolicyError> {
        self.1.to_tpm_handle()
    }

    /// Parses a PCR selection from a `pcr://` URI string.
    ///
    /// # Errors
    ///
    /// Returns a `PolicyError` if the URI is not a `pcr://` URI.
    pub fn to_pcr_selection(&self, pcr_count: usize) -> Result<TpmlPcrSelection, PolicyError> {
        match &self.1 {
            Expression::Pcr { selection, .. } => pcr_selection_to_list(selection, pcr_count),
            _ => Err(PolicyError::InvalidExpression(format!(
                "Not a PCR URI: '{}'",
                self.0
            ))),
        }
    }
}

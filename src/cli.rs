// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    util, Alg, Command, CommandType, ContextData, ObjectData, PcrOutput, SessionData, TpmError,
};
use std::str::FromStr;
use tpm2_protocol::{
    data::{TpmRc, TpmRh},
    TpmPersistent,
};

#[derive(Debug, Clone)]
pub enum Object {
    Context(ContextData),
    Handle(u32),
    KeyData(String),
    Key(ObjectData),
    PcrValues(PcrOutput),
    Session(SessionData),
}

impl Object {
    #[must_use]
    pub fn to_json(&self) -> json::JsonValue {
        match self {
            Self::Handle(handle) => json::object! {
                "type": "handle",
                "data": { "handle": format!("{handle:#010x}") }
            },
            Self::Key(data) => json::object! {
                "type": "object",
                "data": data.to_json()
            },
            Self::Context(data) => json::object! {
                "type": "context",
                "data": data.to_json()
            },
            Self::Session(data) => json::object! {
                "type": "session",
                "data": data.to_json()
            },
            Self::PcrValues(data) => json::object! {
                "type": "pcr-values",
                "data": data.to_json()
            },
            Self::KeyData(s) => json::object! {
                "type": "key-data",
                "data": { "value": s.clone() }
            },
        }
    }

    /// Deserializes an `Object` from a `json::JsonValue`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Parse` if the JSON object is malformed.
    pub fn from_json(value: &json::JsonValue) -> Result<Self, TpmError> {
        let obj_type = value["type"].as_str().ok_or_else(|| {
            TpmError::Parse("object in pipeline missing 'type' field".to_string())
        })?;
        let data = &value["data"];
        if data.is_null() {
            return Err(TpmError::Parse(
                "object in pipeline missing 'data' field".to_string(),
            ));
        }

        match obj_type {
            "handle" => {
                let handle_str = data["handle"].as_str().ok_or_else(|| {
                    TpmError::Parse("handle object missing 'handle' string".to_string())
                })?;
                let handle = util::parse_hex_u32(handle_str)?;
                Ok(Self::Handle(handle))
            }
            "object" => Ok(Self::Key(ObjectData::from_json(data)?)),
            "context" => Ok(Self::Context(ContextData::from_json(data)?)),
            "session" => Ok(Self::Session(SessionData::from_json(data)?)),
            "pcr-values" => Ok(Self::PcrValues(PcrOutput::from_json(data)?)),
            "key-data" => {
                let s = data["value"].as_str().ok_or_else(|| {
                    TpmError::Parse("string object missing 'value' field".to_string())
                })?;
                Ok(Self::KeyData(s.to_string()))
            }
            _ => Err(TpmError::Parse(format!(
                "Unknown object type in pipeline: '{obj_type}'"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub enum LogFormat {
    #[default]
    Plain,
    Pretty,
}

impl FromStr for LogFormat {
    type Err = TpmError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plain" => Ok(Self::Plain),
            "pretty" => Ok(Self::Pretty),
            _ => Err(TpmError::Usage(format!("Invalid log format: '{s}'"))),
        }
    }
}

#[derive(Debug, Default)]
pub struct Cli {
    pub device: String,
    pub log_format: LogFormat,
    pub command: Option<Commands>,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum Hierarchy {
    #[default]
    Owner,
    Platform,
    Endorsement,
}

impl FromStr for Hierarchy {
    type Err = TpmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(Hierarchy::Owner),
            "platform" => Ok(Hierarchy::Platform),
            "endorsement" => Ok(Hierarchy::Endorsement),
            _ => Err(TpmError::Usage(format!("Invalid hierarchy: '{s}'"))),
        }
    }
}

impl From<Hierarchy> for TpmRh {
    fn from(h: Hierarchy) -> Self {
        match h {
            Hierarchy::Owner => TpmRh::Owner,
            Hierarchy::Platform => TpmRh::Platform,
            Hierarchy::Endorsement => TpmRh::Endorsement,
        }
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
    type Err = TpmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hmac" => Ok(SessionType::Hmac),
            "policy" => Ok(SessionType::Policy),
            "trial" => Ok(SessionType::Trial),
            _ => Err(TpmError::Usage(format!("Invalid session type: '{s}'"))),
        }
    }
}

impl From<SessionType> for tpm2_protocol::data::TpmSe {
    fn from(val: SessionType) -> Self {
        match val {
            SessionType::Hmac => Self::Hmac,
            SessionType::Policy => Self::Policy,
            SessionType::Trial => Self::Trial,
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub enum SessionHashAlg {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

impl FromStr for SessionHashAlg {
    type Err = TpmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha256" => Ok(SessionHashAlg::Sha256),
            "sha384" => Ok(SessionHashAlg::Sha384),
            "sha512" => Ok(SessionHashAlg::Sha512),
            _ => Err(TpmError::Usage(format!(
                "Invalid session hash algorithm: '{s}'"
            ))),
        }
    }
}

impl From<SessionHashAlg> for tpm2_protocol::data::TpmAlgId {
    fn from(alg: SessionHashAlg) -> Self {
        match alg {
            SessionHashAlg::Sha256 => Self::Sha256,
            SessionHashAlg::Sha384 => Self::Sha384,
            SessionHashAlg::Sha512 => Self::Sha512,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyFormat {
    #[default]
    Json,
    Pem,
    Der,
}

impl FromStr for KeyFormat {
    type Err = TpmError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(KeyFormat::Json),
            "pem" => Ok(KeyFormat::Pem),
            "der" => Ok(KeyFormat::Der),
            _ => Err(TpmError::Usage(format!("Invalid key format: '{s}'"))),
        }
    }
}

#[derive(Debug)]
pub enum Commands {
    Algorithms(Algorithms),
    Convert(Convert),
    CreatePrimary(CreatePrimary),
    Delete(Delete),
    Import(Import),
    Load(Load),
    Objects(Objects),
    PcrEvent(PcrEvent),
    PcrRead(PcrRead),
    Policy(Policy),
    PrintError(PrintError),
    PrintStack(PrintStack),
    ResetLock(ResetLock),
    Save(Save),
    Seal(Seal),
    StartSession(StartSession),
    Unseal(Unseal),
}

impl Command for Commands {
    fn command_type(&self) -> CommandType {
        match self {
            Self::Algorithms(args) => args.command_type(),
            Self::Convert(args) => args.command_type(),
            Self::CreatePrimary(args) => args.command_type(),
            Self::Delete(args) => args.command_type(),
            Self::Import(args) => args.command_type(),
            Self::Load(args) => args.command_type(),
            Self::Objects(args) => args.command_type(),
            Self::PcrEvent(args) => args.command_type(),
            Self::PcrRead(args) => args.command_type(),
            Self::Policy(args) => args.command_type(),
            Self::PrintError(args) => args.command_type(),
            Self::PrintStack(args) => args.command_type(),
            Self::ResetLock(args) => args.command_type(),
            Self::Save(args) => args.command_type(),
            Self::Seal(args) => args.command_type(),
            Self::StartSession(args) => args.command_type(),
            Self::Unseal(args) => args.command_type(),
        }
    }

    fn help()
    where
        Self: Sized,
    {
        unimplemented!();
    }

    fn parse(_parser: &mut lexopt::Parser) -> Result<Self, TpmError>
    where
        Self: Sized,
    {
        unimplemented!();
    }

    fn is_local(&self) -> bool {
        match self {
            Self::Algorithms(args) => args.is_local(),
            Self::Convert(args) => args.is_local(),
            Self::CreatePrimary(args) => args.is_local(),
            Self::Delete(args) => args.is_local(),
            Self::Import(args) => args.is_local(),
            Self::Load(args) => args.is_local(),
            Self::Objects(args) => args.is_local(),
            Self::PcrEvent(args) => args.is_local(),
            Self::PcrRead(args) => args.is_local(),
            Self::Policy(args) => args.is_local(),
            Self::PrintError(args) => args.is_local(),
            Self::PrintStack(args) => args.is_local(),
            Self::ResetLock(args) => args.is_local(),
            Self::Save(args) => args.is_local(),
            Self::Seal(args) => args.is_local(),
            Self::StartSession(args) => args.is_local(),
            Self::Unseal(args) => args.is_local(),
        }
    }

    fn run(&self) -> Result<(), crate::TpmError> {
        match self {
            Self::Algorithms(args) => args.run(),
            Self::Convert(args) => args.run(),
            Self::CreatePrimary(args) => args.run(),
            Self::Delete(args) => args.run(),
            Self::Import(args) => args.run(),
            Self::Load(args) => args.run(),
            Self::Objects(args) => args.run(),
            Self::PcrEvent(args) => args.run(),
            Self::PcrRead(args) => args.run(),
            Self::Policy(args) => args.run(),
            Self::PrintError(args) => args.run(),
            Self::PrintStack(args) => args.run(),
            Self::ResetLock(args) => args.run(),
            Self::Save(args) => args.run(),
            Self::Seal(args) => args.run(),
            Self::StartSession(args) => args.run(),
            Self::Unseal(args) => args.run(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PasswordArgs {
    pub password: Option<String>,
}

#[derive(Debug, Default)]
pub struct CreatePrimary {
    pub hierarchy: Hierarchy,
    pub algorithm: Alg,
    pub handle: Option<TpmPersistent>,
    pub password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Save {
    pub from: String,
    pub to: String,
    pub password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Delete {
    pub handle: String,
    pub password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Import {
    pub parent_password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Algorithms {
    pub filter: Option<String>,
}

#[derive(Debug, Default)]
pub struct Load {
    pub parent_password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Objects {}

#[derive(Debug, Default)]
pub struct PcrRead {
    pub selection: String,
}

#[derive(Debug, Default)]
pub struct PcrEvent {
    pub handle: u32,
    pub data: String,
    pub password: PasswordArgs,
}

#[derive(Debug)]
pub struct PrintError {
    pub rc: TpmRc,
}

#[derive(Debug, Default)]
pub struct PrintStack {}

#[derive(Debug, Default)]
pub struct ResetLock {
    pub password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct StartSession {
    pub session_type: SessionType,
    pub hash_alg: SessionHashAlg,
}

#[derive(Debug, Default)]
pub struct Seal {
    pub parent_password: PasswordArgs,
    pub object_password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Unseal {
    pub password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Convert {
    pub from: KeyFormat,
    pub to: KeyFormat,
}

#[derive(Debug, Default)]
pub struct Policy {
    pub expression: String,
    pub password: PasswordArgs,
}

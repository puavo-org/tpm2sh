// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{CliError, Command, CommandType, TpmDevice};
use std::{
    io::{Read, Write},
    str::FromStr,
    sync::{Arc, Mutex},
};
use tpm2_protocol::data::TpmRh;

#[derive(Debug, Clone, Copy, Default)]
pub enum LogFormat {
    #[default]
    Plain,
    Pretty,
}

impl FromStr for LogFormat {
    type Err = CliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plain" => Ok(Self::Plain),
            "pretty" => Ok(Self::Pretty),
            _ => Err(CliError::Usage(format!("Invalid log format: '{s}'"))),
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
    type Err = CliError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(Hierarchy::Owner),
            "platform" => Ok(Hierarchy::Platform),
            "endorsement" => Ok(Hierarchy::Endorsement),
            _ => Err(CliError::Usage(format!("Invalid hierarchy: '{s}'"))),
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
    type Err = CliError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "hmac" => Ok(SessionType::Hmac),
            "policy" => Ok(SessionType::Policy),
            "trial" => Ok(SessionType::Trial),
            _ => Err(CliError::Usage(format!("Invalid session type: '{s}'"))),
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
    type Err = CliError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha256" => Ok(SessionHashAlg::Sha256),
            "sha384" => Ok(SessionHashAlg::Sha384),
            "sha512" => Ok(SessionHashAlg::Sha512),
            _ => Err(CliError::Usage(format!(
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
    type Err = CliError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "json" => Ok(KeyFormat::Json),
            "pem" => Ok(KeyFormat::Pem),
            "der" => Ok(KeyFormat::Der),
            _ => Err(CliError::Usage(format!("Invalid key format: '{s}'"))),
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

    fn parse(_parser: &mut lexopt::Parser) -> Result<Self, CliError>
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

    fn run<R: Read, W: Write>(
        &self,
        io: &mut crate::pipeline::CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), crate::CliError> {
        match self {
            Self::Algorithms(args) => args.run(io, device),
            Self::Convert(args) => args.run(io, device),
            Self::CreatePrimary(args) => args.run(io, device),
            Self::Delete(args) => args.run(io, device),
            Self::Import(args) => args.run(io, device),
            Self::Load(args) => args.run(io, device),
            Self::Objects(args) => args.run(io, device),
            Self::PcrEvent(args) => args.run(io, device),
            Self::PcrRead(args) => args.run(io, device),
            Self::Policy(args) => args.run(io, device),
            Self::PrintError(args) => args.run(io, device),
            Self::PrintStack(args) => args.run(io, device),
            Self::ResetLock(args) => args.run(io, device),
            Self::Save(args) => args.run(io, device),
            Self::Seal(args) => args.run(io, device),
            Self::StartSession(args) => args.run(io, device),
            Self::Unseal(args) => args.run(io, device),
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
    pub algorithm: crate::Alg,
    pub handle_uri: Option<String>,
    pub password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Save {
    pub to_uri: Option<String>,
    pub password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Delete {
    pub handle_uri: Option<String>,
    pub password: PasswordArgs,
}

#[derive(Debug, Default)]
pub struct Import {
    pub key_uri: Option<String>,
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
pub struct Objects;

#[derive(Debug, Default)]
pub struct PcrRead {
    pub selection: String,
}

#[derive(Debug, Default)]
pub struct PcrEvent {
    pub handle_uri: String,
    pub data_uri: String,
    pub password: PasswordArgs,
}

#[derive(Debug)]
pub struct PrintError {
    pub rc: tpm2_protocol::data::TpmRc,
}

#[derive(Debug, Default)]
pub struct PrintStack;

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
    pub data_uri: Option<String>,
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
    pub input_uri: Option<String>,
    pub parent_uri: Option<String>,
}

#[derive(Debug, Default)]
pub struct Policy {
    pub expression: String,
}

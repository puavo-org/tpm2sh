// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::{
        context::Context, convert::Convert, create_primary::CreatePrimary, delete::Delete,
        list::List, load::Load, pcr_event::PcrEvent, policy::Policy, print_error::PrintError,
        reset_lock::ResetLock, seal::Seal, start_session::StartSession,
    },
    device::{TpmDevice, TpmDeviceError},
    error::CliError,
    Command,
};
use argh::FromArgs;
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};
use tpm2_protocol::data::TpmRh;

/// Subcommand not requiring TPM device access.
pub trait LocalCommand {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, context: &mut Context) -> Result<(), CliError>;
}

/// Subcommand requiring TPM device access.
pub trait DeviceCommand {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError>;
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum LogFormat {
    #[default]
    Plain,
    Pretty,
}

impl FromStr for LogFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "plain" => Ok(Self::Plain),
            "pretty" => Ok(Self::Pretty),
            _ => Err("invalid log format: must be 'plain' or 'pretty'".to_string()),
        }
    }
}

/// TPM 2.0 shell
#[derive(FromArgs, Debug)]
pub struct Cli {
    /// device path
    #[argh(option, short = 'd', default = "\"/dev/tpmrm0\".to_string()")]
    pub device: String,

    /// logging format (plain or pretty)
    #[argh(option, default = "Default::default()")]
    pub log_format: LogFormat,

    #[argh(subcommand)]
    pub command: Commands,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum Commands {
    Convert(Convert),
    CreatePrimary(CreatePrimary),
    Delete(Delete),
    List(List),
    Load(Load),
    PcrEvent(PcrEvent),
    Policy(Policy),
    PrintError(PrintError),
    ResetLock(ResetLock),
    Seal(Seal),
    StartSession(StartSession),
}

impl Command for Commands {
    fn is_local(&self) -> bool {
        matches!(self, Self::Convert(_) | Self::PrintError(_))
    }

    fn run(
        &self,
        device: Option<Arc<Mutex<TpmDevice>>>,
        context: &mut Context,
    ) -> Result<(), CliError> {
        match self {
            Self::Convert(args) => args.run(context),
            Self::PrintError(args) => args.run(context),
            Self::CreatePrimary(args) => {
                let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| TpmDeviceError::LockPoisoned)?;
                args.run(&mut guard, context)
            }
            Self::Delete(args) => {
                let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| TpmDeviceError::LockPoisoned)?;
                args.run(&mut guard, context)
            }
            Self::List(args) => {
                let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| TpmDeviceError::LockPoisoned)?;
                args.run(&mut guard, context)
            }
            Self::Load(args) => {
                let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| TpmDeviceError::LockPoisoned)?;
                args.run(&mut guard, context)
            }
            Self::PcrEvent(args) => {
                let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| TpmDeviceError::LockPoisoned)?;
                args.run(&mut guard, context)
            }
            Self::Policy(args) => {
                let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| TpmDeviceError::LockPoisoned)?;
                args.run(&mut guard, context)
            }
            Self::ResetLock(args) => {
                let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| TpmDeviceError::LockPoisoned)?;
                args.run(&mut guard, context)
            }
            Self::Seal(args) => {
                let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| TpmDeviceError::LockPoisoned)?;
                args.run(&mut guard, context)
            }
            Self::StartSession(args) => {
                let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                let mut guard = device_arc
                    .lock()
                    .map_err(|_| TpmDeviceError::LockPoisoned)?;
                args.run(&mut guard, context)
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Hierarchy {
    #[default]
    Owner,
    Platform,
    Endorsement,
}

impl FromStr for Hierarchy {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(Self::Owner),
            "platform" => Ok(Self::Platform),
            "endorsement" => Ok(Self::Endorsement),
            _ => {
                Err("invalid hierarchy: must be 'owner', 'platform', or 'endorsement'".to_string())
            }
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
pub enum KeyFormat {
    #[default]
    Pem,
    Der,
}

impl FromStr for KeyFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pem" => Ok(Self::Pem),
            "der" => Ok(Self::Der),
            _ => Err("invalid key format: must be 'pem' or 'der'".to_string()),
        }
    }
}

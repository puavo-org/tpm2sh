// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::{
        CommandError, Convert, CreatePrimary, Delete, List, Load, PcrEvent, Policy, PrintError,
        ResetLock, Seal, StartSession,
    },
    context::Context,
    device::TpmDevice,
    Command,
};
use anyhow::Result;
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
    fn run(&self, context: &mut Context) -> Result<()>;
}

/// Subcommand requiring TPM device access.
pub trait DeviceCommand {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<()>;
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

    fn run(&self, device: Option<Arc<Mutex<TpmDevice>>>, context: &mut Context) -> Result<()> {
        if self.is_local() {
            return match self {
                Self::Convert(args) => args.run(context),
                Self::PrintError(args) => args.run(context),
                _ => unreachable!(),
            };
        }

        let device_arc = device.ok_or(CommandError::NotProvided)?;
        let mut guard = device_arc.lock().map_err(|_| CommandError::LockPoisoned)?;

        match self {
            Self::CreatePrimary(args) => args.run(&mut guard, context),
            Self::Delete(args) => args.run(&mut guard, context),
            Self::List(args) => args.run(&mut guard, context),
            Self::Load(args) => args.run(&mut guard, context),
            Self::PcrEvent(args) => args.run(&mut guard, context),
            Self::Policy(args) => args.run(&mut guard, context),
            Self::ResetLock(args) => args.run(&mut guard, context),
            Self::Seal(args) => args.run(&mut guard, context),
            Self::StartSession(args) => args.run(&mut guard, context),
            _ => unreachable!(),
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

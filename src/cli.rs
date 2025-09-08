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
};
use anyhow::Result;
use argh::FromArgs;
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};
use tpm2_protocol::data::TpmRh;

/// A subcommand of the main CLI application.
pub trait SubCommand {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns an error if the execution fails.
    fn run(&self, device: Option<&mut TpmDevice>, context: &mut Context) -> Result<()>;
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
    pub command: Command,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
pub enum Command {
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

impl Command {
    #[must_use]
    pub fn is_local(&self) -> bool {
        matches!(self, Self::Convert(_) | Self::PrintError(_))
    }

    fn as_subcommand(&self) -> &dyn SubCommand {
        match self {
            Self::Convert(args) => args,
            Self::CreatePrimary(args) => args,
            Self::Delete(args) => args,
            Self::List(args) => args,
            Self::Load(args) => args,
            Self::PcrEvent(args) => args,
            Self::Policy(args) => args,
            Self::PrintError(args) => args,
            Self::ResetLock(args) => args,
            Self::Seal(args) => args,
            Self::StartSession(args) => args,
        }
    }

    /// Runs the command.
    ///
    /// # Errors
    ///
    /// Returns an error if the device lock cannot be acquired or if the subcommand fails.
    pub fn run(&self, device: Option<&Arc<Mutex<TpmDevice>>>, context: &mut Context) -> Result<()> {
        let mut guard = device
            .map(|d| d.lock().map_err(|_| CommandError::LockPoisoned))
            .transpose()?;

        self.as_subcommand().run(guard.as_deref_mut(), context)
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

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{device::TpmDevice, error::CliError, key::Alg, uri::Uri, Command};
use clap::{
    builder::styling::{AnsiColor, Color, Style, Styles},
    Args, Parser, Subcommand, ValueEnum,
};
use std::{
    fmt,
    io::Write,
    sync::{Arc, Mutex},
};
use tpm2_protocol::data::{TpmRc, TpmRh, TpmSe};
use tpm2_protocol::TpmTransient;

/// Subcommand not requiring TPM device access.
pub trait LocalCommand {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        writer: &mut W,
    ) -> Result<Vec<(TpmTransient, bool)>, CliError>;
}

/// Subcommand requiring TPM device access.
pub trait DeviceCommand {
    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: &mut TpmDevice,
        writer: &mut W,
    ) -> Result<Vec<(TpmTransient, bool)>, CliError>;
}

const STYLES: Styles = Styles::styled()
    .header(Style::new().bold())
    .usage(Style::new().bold())
    .literal(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Green))))
    .placeholder(Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))));

pub(crate) const USAGE_TEMPLATE: &str = "
{about-with-newline}
{usage-heading} {usage}

{options-heading}
{options}
";

const HELP_TEMPLATE: &str = "
{about-with-newline}
{usage-heading} {usage}

{subcommands-heading}
{subcommands}

{options-heading}
{options}
";

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum LogFormat {
    #[default]
    Plain,
    Pretty,
}

impl fmt::Display for LogFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain => write!(f, "Plain"),
            Self::Pretty => write!(f, "Pretty"),
        }
    }
}

/// TPM 2.0 shell
#[derive(Parser, Debug, Default)]
#[command(version, about, styles = STYLES, help_template = HELP_TEMPLATE)]
pub struct Cli {
    #[arg(
        short = 'd',
        long,
        default_value = "/dev/tpmrm0",
        global = true,
        help = "TPM device path"
    )]
    pub device: String,

    #[arg(long, value_enum, default_value_t = LogFormat::Plain, global = true, help = "Logging format")]
    pub log_format: LogFormat,

    #[arg(
        short = 'p',
        long,
        global = true,
        help = "Default authorization password for objects and sessions"
    )]
    pub password: Option<String>,

    #[arg(
        short = 'S',
        long,
        global = true,
        value_name = "URI",
        help = "Session object URI (e.g., 'tpm://0x03000000')"
    )]
    pub session: Option<Uri>,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Clone, Copy, Default, ValueEnum)]
pub enum Hierarchy {
    #[default]
    Owner,
    Platform,
    Endorsement,
}

impl fmt::Display for Hierarchy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Owner => write!(f, "Owner"),
            Self::Platform => write!(f, "Platform"),
            Self::Endorsement => write!(f, "Endorsement"),
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum SessionType {
    #[default]
    Hmac,
    Policy,
    Trial,
}

impl fmt::Display for SessionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hmac => write!(f, "Hmac"),
            Self::Policy => write!(f, "Policy"),
            Self::Trial => write!(f, "Trial"),
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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum KeyFormat {
    #[default]
    Pem,
    Der,
}

impl fmt::Display for KeyFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pem => write!(f, "Pem"),
            Self::Der => write!(f, "Der"),
        }
    }
}

macro_rules! tpm2sh_command {
    (
        local: [$($local_command:ident),* $(,)?],
        device: [$($device_command:ident),* $(,)?]
        $(,)?
    ) => {
        #[derive(Subcommand, Debug)]
        pub enum Commands {
            $($local_command($local_command),)*
            $($device_command($device_command),)*
        }

        impl Command for Commands {
            fn is_local(&self) -> bool {
                match self {
                    $(Self::$local_command(_) => true,)*
                    $(Self::$device_command(_) => false,)*
                }
            }

            fn run<W: Write>(
                &self,
                cli: &Cli,
                device: Option<Arc<Mutex<TpmDevice>>>,
                writer: &mut W,
            ) -> Result<Vec<(TpmTransient, bool)>, CliError> {
                match self {
                    $(
                        Self::$local_command(args) => {
                            args.run(cli, writer)
                        }
                    ,)*
                    $(
                        Self::$device_command(args) => {
                            let device_arc = device.ok_or_else(|| {
                                CliError::Execution("TPM device not provided".to_string())
                            })?;
                            let mut guard = device_arc
                                .lock()
                                .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

                            args.run(cli, &mut guard, writer)
                        }
                    ,)*
                }
            }
        }
    };
}

tpm2sh_command!(
    local: [Convert, PrintError],
    device: [
        Algorithms,
        CreatePrimary,
        Delete,
        Import,
        Load,
        Objects,
        PcrEvent,
        PcrRead,
        Policy,
        ResetLock,
        Save,
        Seal,
        StartSession,
        Unseal,
    ],
);

/// Lists available algorithms
#[derive(Args, Debug, Default)]
pub struct Algorithms {
    #[arg(help = "A regex to filter the algorithm names")]
    pub filter: Option<String>,
}

/// Converts keys between ASN.1 formats
#[derive(Args, Debug, Default)]
pub struct Convert {
    #[arg(long, value_enum, default_value_t = KeyFormat::Pem, help = "Input format")]
    pub from: KeyFormat,
    #[arg(long, value_enum, default_value_t = KeyFormat::Der, help = "Output format")]
    pub to: KeyFormat,
    #[arg(help = "URI of the input object (e.g., 'file:///path/to/key.pem')")]
    pub input: Uri,
}

/// Creates a primary key
#[derive(Args, Debug, Default)]
pub struct CreatePrimary {
    #[arg(short = 'H', long, value_enum, default_value_t = Hierarchy::Owner, help = "Hierarchy for the new key")]
    pub hierarchy: Hierarchy,
    #[arg(long, help = "Public key algorithm. Run 'algorithms' for options")]
    pub algorithm: Alg,
    #[arg(
        long,
        value_name = "HANDLEURI",
        help = "Store object to non-volatile memory (e.g., 'tpm://0x81000001')"
    )]
    pub handle: Option<Uri>,
}

/// Deletes a transient or persistent object
#[derive(Args, Debug, Default)]
pub struct Delete {
    #[arg(
        value_name = "HANDLE",
        help = "URI of the object to delete (e.g. 'tpm://0x81000001')"
    )]
    pub handle: Uri,
}

/// Arguments for commands requiring a parent object.
#[derive(Args, Debug, Default)]
pub struct ParentArgs {
    #[arg(
        short = 'P',
        long,
        required = true,
        value_name = "URI",
        help = "Parent object URI (e.g., 'tpm://0x80000001', 'file:///context.bin')"
    )]
    pub parent: Uri,
}

/// Imports an external key
#[derive(Args, Debug, Default)]
pub struct Import {
    #[command(flatten)]
    pub parent: ParentArgs,
    #[arg(
        long,
        value_name = "KEY",
        help = "URI of the external private key to import (e.g., 'file:///path/to/key.pem')"
    )]
    pub key: Uri,
}

/// Loads a TPM key
#[derive(Args, Debug, Default)]
pub struct Load {
    #[command(flatten)]
    pub parent: ParentArgs,
    #[arg(long, value_name = "URI", help = "URI of the public part of the key")]
    pub public: Uri,
    #[arg(long, value_name = "URI", help = "URI of the private part of the key")]
    pub private: Uri,
}

/// Lists objects in volatile and non-volatile memory
#[derive(Args, Debug, Default)]
pub struct Objects;

/// Extends a PCR with an event
#[derive(Args, Debug, Default)]
pub struct PcrEvent {
    #[arg(value_name = "PCR", help = "PCR to extend (e.g., 'pcr://sha256:7')")]
    pub pcr: Uri,
    #[arg(
        value_name = "DATA",
        help = "URI of the data (e.g., 'data://hex,deadbeef')"
    )]
    pub data: Uri,
}

/// Reads PCRs
#[derive(Args, Debug, Default)]
pub struct PcrRead {
    #[arg(
        value_name = "PCR",
        help = "PCR selection (e.g. 'pcr://sha256:0,1,2+sha1:0')"
    )]
    pub pcr: Uri,
}

/// Builds a policy using a policy expression
#[derive(Args, Debug, Default)]
pub struct Policy {
    #[arg(
        value_name = "EXPRESSION",
        help = "Policy expression (e.g., 'pcr(\"sha256:0\",\"...\")')"
    )]
    pub expression: String,
}

/// Encodes and print a TPM error code
#[derive(Args, Debug)]
pub struct PrintError {
    #[arg(value_parser = crate::util::parse_tpm_rc_str, help = "TPM error code (e.g., '0x100')")]
    pub rc: TpmRc,
}

/// Resets the dictionary attack lockout timer
#[derive(Args, Debug, Default)]
pub struct ResetLock;

/// Saves to non-volatile memory
#[derive(Args, Debug, Default)]
pub struct Save {
    #[arg(
        long,
        value_name = "HANDLE",
        help = "URI for the persistent object to be created (e.g., 'tpm://0x81000001')"
    )]
    pub to_uri: Uri,
    #[arg(
        long = "in",
        value_name = "CONTEXT",
        help = "URI of the transient object context to save (e.g., 'file:///path/to/context.bin')"
    )]
    pub in_uri: Uri,
}

/// Seals a keyedhash object
#[derive(Args, Debug, Default)]
pub struct Seal {
    #[command(flatten)]
    pub parent: ParentArgs,
    #[arg(
        long,
        value_name = "URI",
        help = "URI of the secret to seal (e.g., 'data://utf8,mysecret')"
    )]
    pub data: Uri,
    #[arg(
        long,
        value_name = "PASSWORD",
        help = "Authorization for the new sealed object"
    )]
    pub object_password: Option<String>,
}

/// Starts an authorization session
#[derive(Args, Debug, Default)]
pub struct StartSession {
    #[arg(short, long, value_enum, default_value_t = SessionType::Hmac, help = "Session type")]
    pub session_type: SessionType,
}

/// Unseals a keyedhash object
#[derive(Args, Debug, Default)]
pub struct Unseal {
    #[arg(
        long,
        value_name = "HANDLE",
        help = "URI of the loaded sealed object to unseal (e.g., 'tpm://0x80000000')"
    )]
    pub handle: Uri,
}

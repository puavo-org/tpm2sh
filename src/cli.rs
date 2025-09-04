// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::{
        algorithms::Algorithms, convert::Convert, create_primary::CreatePrimary, delete::Delete,
        import::Import, load::Load, objects::Objects, pcr_event::PcrEvent, pcr_read::PcrRead,
        policy::Policy, print_error::PrintError, reset_lock::ResetLock, save::Save, seal::Seal,
        start_session::StartSession, unseal::Unseal,
    },
    device::TpmDevice,
    error::CliError,
    uri::Uri,
    Command, Context, ParseResult,
};
use lexopt::{Arg, Parser, ValueExt};
use std::{
    str::FromStr,
    sync::{Arc, Mutex},
};
use tpm2_protocol::data::{TpmRh, TpmSe};

/// A trait for CLI subcommands.
pub trait Subcommand: Sized {
    const USAGE: &'static str;
    const HELP: &'static str;

    /// Parse subcommand.
    ///
    /// # Errors
    ///
    /// Returns a `lexopt::Error` if parsing fails.
    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error>;
}

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
            _ => Err("invalid log format".to_string()),
        }
    }
}

/// TPM 2.0 shell
#[derive(Debug, Default)]
pub struct Cli {
    pub device: String,
    pub log_format: LogFormat,
    pub password: Option<String>,
    pub session: Option<Uri>,
    pub command: Option<Commands>,
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
            _ => Err("invalid hierarchy".to_string()),
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
            _ => Err("invalid key format".to_string()),
        }
    }
}

macro_rules! subcommand {
    (
        local: [$($local_command:ident),* $(,)?],
        device: [$($device_command:ident),* $(,)?]
        $(,)?
    ) => {
        #[derive(Debug)]
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

            fn run(&self, device: Option<Arc<Mutex<TpmDevice>>>, context: &mut Context) -> Result<(), CliError> {
                match self {
                    $(
                        Self::$local_command(args) => {
                            args.run(context)
                        }
                    ,)*
                    $(
                        Self::$device_command(args) => {
                            let device_arc = device.ok_or(CliError::DeviceNotProvided)?;
                            let mut guard = device_arc
                                .lock()
                                .map_err(|_| CliError::DeviceLockPoisoned)?;

                            args.run(&mut guard, context)
                        }
                    ,)*
                }
            }
        }
    };
}

subcommand!(
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

/// Returns a specific error on `-h` or `--help`.
///
/// # Errors
///
/// Returns a `lexopt::Error` if parsing fails.
pub fn handle_help<T>(arg: Arg) -> Result<T, lexopt::Error> {
    if arg == Arg::Short('h') || arg == Arg::Long("help") {
        return Err(lexopt::Error::Custom("help requested".into()));
    }
    Err(arg.unexpected())
}

/// Helper for enforcing a required command argument.
///
/// # Errors
///
/// Returns a `lexopt::Error` if parsing fails.
pub fn required<T>(arg: Option<T>, name: &'static str) -> Result<T, lexopt::Error> {
    arg.ok_or_else(|| format!("missing required argument {name}").into())
}

/// Helper to dispatch parsing to the correct `Subcommand` impl.
///
/// # Errors
///
/// Returns a `Result<ParseResult, lexopt::Error` if dispatching fails.
#[allow(clippy::result_large_err)]
fn dispatch<S, W>(parser: &mut Parser, wrapper: W) -> Result<Commands, ParseResult>
where
    S: Subcommand,
    W: Fn(S) -> Commands,
{
    match S::parse(parser) {
        Ok(args) => Ok(wrapper(args)),
        Err(lexopt::Error::Custom(err)) if err.to_string() == "help requested" => {
            Err(ParseResult::Help(S::HELP))
        }
        Err(e) => Err(ParseResult::ErrorAndUsage {
            error: e.to_string(),
            usage: S::USAGE,
        }),
    }
}

struct SubcommandObject {
    name: &'static str,
    help: &'static str,
    dispatch: fn(&mut Parser) -> Result<Commands, ParseResult>,
}

static SUBCOMMANDS: &[SubcommandObject] = &[
    SubcommandObject {
        name: "algorithms",
        help: Algorithms::HELP,
        dispatch: |p| dispatch(p, Commands::Algorithms),
    },
    SubcommandObject {
        name: "convert",
        help: Convert::HELP,
        dispatch: |p| dispatch(p, Commands::Convert),
    },
    SubcommandObject {
        name: "create-primary",
        help: CreatePrimary::HELP,
        dispatch: |p| dispatch(p, Commands::CreatePrimary),
    },
    SubcommandObject {
        name: "delete",
        help: Delete::HELP,
        dispatch: |p| dispatch(p, Commands::Delete),
    },
    SubcommandObject {
        name: "import",
        help: Import::HELP,
        dispatch: |p| dispatch(p, Commands::Import),
    },
    SubcommandObject {
        name: "load",
        help: Load::HELP,
        dispatch: |p| dispatch(p, Commands::Load),
    },
    SubcommandObject {
        name: "objects",
        help: Objects::HELP,
        dispatch: |p| dispatch(p, Commands::Objects),
    },
    SubcommandObject {
        name: "pcr-event",
        help: PcrEvent::HELP,
        dispatch: |p| dispatch(p, Commands::PcrEvent),
    },
    SubcommandObject {
        name: "pcr-read",
        help: PcrRead::HELP,
        dispatch: |p| dispatch(p, Commands::PcrRead),
    },
    SubcommandObject {
        name: "policy",
        help: Policy::HELP,
        dispatch: |p| dispatch(p, Commands::Policy),
    },
    SubcommandObject {
        name: "print-error",
        help: PrintError::HELP,
        dispatch: |p| dispatch(p, Commands::PrintError),
    },
    SubcommandObject {
        name: "reset-lock",
        help: ResetLock::HELP,
        dispatch: |p| dispatch(p, Commands::ResetLock),
    },
    SubcommandObject {
        name: "save",
        help: Save::HELP,
        dispatch: |p| dispatch(p, Commands::Save),
    },
    SubcommandObject {
        name: "seal",
        help: Seal::HELP,
        dispatch: |p| dispatch(p, Commands::Seal),
    },
    SubcommandObject {
        name: "start-session",
        help: StartSession::HELP,
        dispatch: |p| dispatch(p, Commands::StartSession),
    },
    SubcommandObject {
        name: "unseal",
        help: Unseal::HELP,
        dispatch: |p| dispatch(p, Commands::Unseal),
    },
];

/// The main entry point for command-line argument parsing.
#[allow(clippy::too_many_lines, clippy::missing_errors_doc)]
pub fn parse_args() -> Result<ParseResult, lexopt::Error> {
    let mut cli = Cli {
        device: "/dev/tpmrm0".to_string(),
        ..Default::default()
    };
    let mut parser = lexopt::Parser::from_env();
    let mut cmd_name_opt = None;

    while let Some(arg) = parser.next()? {
        match arg {
            Arg::Short('h') | Arg::Long("help") => {
                let help_text = if let Some(Arg::Value(val)) = parser.next()? {
                    let cmd_name = val.to_string_lossy();
                    SUBCOMMANDS
                        .iter()
                        .find(|cmd| cmd.name == cmd_name.as_ref())
                        .map(|cmd| cmd.help)
                        .ok_or_else(|| {
                            lexopt::Error::from(format!("unknown command '{cmd_name}'"))
                        })?
                } else {
                    include_str!("help.txt")
                };
                return Ok(ParseResult::Help(help_text));
            }
            Arg::Short('V') | Arg::Long("version") => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            Arg::Short('d') | Arg::Long("device") => {
                cli.device = parser.value()?.string()?;
            }
            Arg::Long("log-format") => {
                cli.log_format = parser.value()?.parse()?;
            }
            Arg::Short('p') | Arg::Long("password") => {
                cli.password = Some(parser.value()?.string()?);
            }
            Arg::Short('S') | Arg::Long("session") => {
                cli.session = Some(parser.value()?.parse()?);
            }
            Arg::Value(cmd) => {
                cmd_name_opt = Some(cmd.string()?);
                break;
            }
            _ => {
                return Err(arg.unexpected());
            }
        }
    }

    let Some(cmd_name) = cmd_name_opt else {
        return Ok(ParseResult::Usage(include_str!("usage.txt")));
    };

    if cmd_name == "help" {
        return Ok(ParseResult::Help(include_str!("help.txt")));
    }

    let Some(subcommand) = SUBCOMMANDS.iter().find(|c| c.name == cmd_name) else {
        return Err(format!("unknown command '{cmd_name}'").into());
    };

    match (subcommand.dispatch)(&mut parser) {
        Ok(command) => {
            cli.command = Some(command);
            Ok(ParseResult::Command(cli))
        }
        Err(parse_result) => Ok(parse_result),
    }
}

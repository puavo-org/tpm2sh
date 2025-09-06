// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    command::{
        context::Context, convert::Convert, create_primary::CreatePrimary, delete::Delete,
        list::List, load::Load, pcr_event::PcrEvent, pcr_read::PcrRead, policy::Policy,
        print_error::PrintError, reset_lock::ResetLock, seal::Seal, start_session::StartSession,
        unseal::Unseal,
    },
    device::{TpmDevice, TpmDeviceError},
    error::CliError,
    uri::Uri,
    Command, ParseResult,
};
use lexopt::{Arg, Parser, ValueExt};
use std::{
    fmt::Write,
    str::FromStr,
    sync::{Arc, Mutex},
};
use tpm2_protocol::data::{TpmRh, TpmSe};

const PARENT_OPTION_HELP: &str = "--parent <URI>\n'data://', 'file://' or 'tpm://'";

/// A trait for CLI subcommands.
pub trait Subcommand: Sized {
    const USAGE: &'static str;
    const HELP: &'static str;
    const ARGUMENTS: &'static str;
    const OPTIONS: &'static str;
    const SUMMARY: &'static str;
    const OPTION_PARENT: bool = false;

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

macro_rules! subcommand_registry {
    (
        local: [$(( $local_command:ident, $local_name:literal )),* $(,)?],
        device: [$(( $device_command:ident, $device_name:literal )),* $(,)?]
        $(,)?
    ) => {
        #[derive(Debug)]
        pub enum Commands {
            $( $local_command($local_command), )*
            $( $device_command($device_command), )*
        }

        impl Command for Commands {
            fn is_local(&self) -> bool {
                match self {
                    $( Self::$local_command(_) => true, )*
                    $( Self::$device_command(_) => false, )*
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
                            let device_arc = device.ok_or(TpmDeviceError::NotProvided)?;
                            let mut guard = device_arc
                                .lock()
                                .map_err(|_| TpmDeviceError::LockPoisoned)?;
                            args.run(&mut guard, context)
                        }
                    ,)*
                }
            }
        }

        static SUBCOMMANDS: &[SubcommandObject] = &[$ (
            SubcommandObject {
                name: $local_name,
                summary: $local_command::SUMMARY,
                help: $local_command::HELP,
                arguments: $local_command::ARGUMENTS,
                options: $local_command::OPTIONS,
                option_parent: $local_command::OPTION_PARENT,
                dispatch: |p| dispatch(p, Commands::$local_command),
            },
        )* $ (
            SubcommandObject {
                name: $device_name,
                summary: $device_command::SUMMARY,
                help: $device_command::HELP,
                arguments: $device_command::ARGUMENTS,
                options: $device_command::OPTIONS,
                option_parent: $device_command::OPTION_PARENT,
                dispatch: |p| dispatch(p, Commands::$device_command),
            },
        )*];
    };
}

subcommand_registry!(
    local: [
        (Convert, "convert"),
        (PrintError, "print-error"),
    ],
    device: [
        (CreatePrimary, "create-primary"),
        (Delete, "delete"),
        (List, "list"),
        (Load, "load"),
        (PcrEvent, "pcr-event"),
        (PcrRead, "pcr-read"),
        (Policy, "policy"),
        (ResetLock, "reset-lock"),
        (Seal, "seal"),
        (StartSession, "start-session"),
        (Unseal, "unseal"),
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

/// Helper for parsing a `--parent <URI>` option.
///
/// # Errors
///
/// Returns a `lexopt::Error` if the option is duplicated or its value is invalid.
pub fn parse_parent_option(
    parser: &mut Parser,
    parent: &mut Option<Uri>,
) -> Result<(), lexopt::Error> {
    if parent.is_some() {
        return Err("the '--parent' option was provided more than once".into());
    }
    *parent = Some(parser.value()?.parse()?);
    Ok(())
}

/// Helper for parsing subcommands that take no arguments.
///
/// # Errors
///
/// Returns a `lexopt::Error` if any arguments other than `--help` are provided.
pub fn parse_no_args<T: Default>(parser: &mut Parser) -> Result<T, lexopt::Error> {
    while let Some(arg) = parser.next()? {
        handle_help(arg)?;
    }
    Ok(T::default())
}

fn format_section(title: &str, content: &str, indent: usize) -> String {
    if content.trim().is_empty() {
        return String::new();
    }
    let mut section = format!("\n{title}:\n");
    let lines: Vec<_> = content.lines().collect();

    for chunk in lines.chunks_exact(2) {
        let name = chunk[0].trim_end();
        let desc = chunk[1].trim();
        let indented_name = format!("{}{}", " ".repeat(indent), name);
        let padding = 40_usize.saturating_sub(indented_name.len());
        writeln!(&mut section, "{indented_name}{}{desc}", " ".repeat(padding),).unwrap();
    }
    section
}

fn build_options_string(has_parent: bool, custom_options: &'static str) -> String {
    let mut options = String::new();
    if has_parent {
        options.push_str(PARENT_OPTION_HELP);
    }
    if !custom_options.trim().is_empty() {
        if !options.is_empty() {
            options.push('\n');
        }
        options.push_str(custom_options);
    }
    options
}

fn format_help(header: &str, args: &str, opts: &str) -> String {
    let mut help = String::from(header);
    help.push_str(&format_section("Arguments", args, 2));
    help.push_str(&format_section("Options", opts, 8));
    help.push_str("\nGlobal options:\n\n");
    help.push_str(include_str!("options.txt"));
    help
}

/// Formats the main help message for the application.
#[must_use]
pub fn format_main_help() -> String {
    let mut commands_str = String::new();
    for cmd in SUBCOMMANDS {
        writeln!(&mut commands_str, "{}\n{}", cmd.name, cmd.summary.trim()).unwrap();
    }

    let mut help = String::from("TPM 2.0 shell\n\nUsage: tpm2sh [OPTIONS] [COMMAND]");
    help.push_str(&format_section("Commands", &commands_str, 2));
    help.push_str("\nOptions:\n\n");
    help.push_str(include_str!("options.txt"));
    help
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
            let header = format!("{}\n\n{}", S::SUMMARY.trim(), S::HELP);
            let options = build_options_string(S::OPTION_PARENT, S::OPTIONS);
            Err(ParseResult::Help(format_help(
                &header,
                S::ARGUMENTS,
                &options,
            )))
        }
        Err(e) => Err(ParseResult::ErrorAndUsage {
            error: e.to_string(),
            usage: S::USAGE,
        }),
    }
}

struct SubcommandObject {
    name: &'static str,
    summary: &'static str,
    help: &'static str,
    arguments: &'static str,
    options: &'static str,
    option_parent: bool,
    dispatch: fn(&mut Parser) -> Result<Commands, ParseResult>,
}

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
                        .map(|cmd| {
                            let header = format!("{}\n\n{}", cmd.summary.trim(), cmd.help);
                            let options = build_options_string(cmd.option_parent, cmd.options);
                            format_help(&header, cmd.arguments, &options)
                        })
                        .ok_or_else(|| {
                            lexopt::Error::from(format!("unknown command '{cmd_name}'"))
                        })?
                } else {
                    format_main_help()
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
        return Ok(ParseResult::Help(format_main_help()));
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

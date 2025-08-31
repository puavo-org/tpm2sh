// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{
        Algorithms, Cli, Commands, Convert, CreatePrimary, Delete, Import, Load, Objects, PcrEvent,
        PcrRead, Policy, PrintError, ResetLock, Save, Seal, StartSession, Unseal,
    },
    CliError, Command,
};
use lexopt::ValueExt;
use std::{ffi::OsString, fmt::Write};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub type CommandLineOption<'a> = (Option<&'a str>, &'a str, &'a str, &'a str);
pub type CommandLineArgument<'a> = (&'a str, &'a str);

#[macro_export]
macro_rules! arguments {
    ($parser:ident, $arg:ident, $help_fn:expr, { $($matcher:tt)* }) => {
        while let Some($arg) = $parser.next()? {
            match $arg {
                lexopt::Arg::Short('h') | lexopt::Arg::Long("help") => {
                    return Err($crate::CliError::Help);
                }
                $($matcher)*
            }
        }
    };
}

/// Collects all subsequent free-standing values from the parser into a vector.
#[allow(clippy::while_let_loop)]
pub(crate) fn collect_values(parser: &mut lexopt::Parser) -> Result<Vec<String>, lexopt::Error> {
    let mut values = Vec::new();
    loop {
        match parser.clone().next()? {
            Some(lexopt::Arg::Value(_)) => {
                values.push(parser.value()?.string()?);
            }
            _ => break,
        }
    }
    Ok(values)
}

fn format_help_section(title: &str, items: &[(String, &str)], max_len: usize) -> String {
    let mut output = format!("\n{title}:\n");
    for (left, right) in items {
        let _ = writeln!(output, "    {left:<max_len$}  {right}");
    }
    output
}

fn format_options<'a>((short, long, val, desc): &CommandLineOption<'a>) -> (String, &'a str) {
    let mut left = if let Some(s) = short {
        format!("{s}, ")
    } else {
        "    ".to_string()
    };
    left.push_str(long);
    if !val.is_empty() {
        left.push(' ');
        left.push_str(val);
    }
    (left, desc)
}

#[must_use]
pub fn format_subcommand_help(
    name: &str,
    about: &str,
    usage: &str,
    args: &[CommandLineArgument],
    options: &[CommandLineOption],
) -> String {
    let mut output = format!("tpm2sh-{name}\n{about}\n\nUSAGE:\n    {usage}");
    let arg_items: Vec<(String, &str)> = args
        .iter()
        .map(|(name, desc)| ((*name).to_string(), *desc))
        .collect();
    let opt_items: Vec<(String, &str)> = options.iter().map(format_options).collect();
    let max_len = arg_items
        .iter()
        .chain(opt_items.iter())
        .map(|(left, _)| left.len())
        .max()
        .unwrap_or(0);
    if !args.is_empty() {
        output.push_str(&format_help_section("ARGS", &arg_items, max_len));
    }
    if !options.is_empty() {
        output.push_str(&format_help_section("OPTIONS", &opt_items, max_len));
    }

    output
}

struct Subcommand {
    name: &'static str,
    about: &'static str,
    help: fn(),
    parse: fn(&mut lexopt::Parser) -> Result<Commands, CliError>,
}

const SUBCOMMANDS: &[Subcommand] = &[
    Subcommand {
        name: "algorithms",
        about: "Lists available algorithms",
        help: Algorithms::help,
        parse: Algorithms::parse,
    },
    Subcommand {
        name: "convert",
        about: "Converts keys between ASN.1 and JSON format",
        help: Convert::help,
        parse: Convert::parse,
    },
    Subcommand {
        name: "create-primary",
        about: "Creates a primary key",
        help: CreatePrimary::help,
        parse: CreatePrimary::parse,
    },
    Subcommand {
        name: "delete",
        about: "Deletes a transient or persistent object",
        help: Delete::help,
        parse: Delete::parse,
    },
    Subcommand {
        name: "import",
        about: "Imports an external key",
        help: Import::help,
        parse: Import::parse,
    },
    Subcommand {
        name: "load",
        about: "Loads a TPM key",
        help: Load::help,
        parse: Load::parse,
    },
    Subcommand {
        name: "objects",
        about: "Lists objects in volatile and non-volatile memory",
        help: Objects::help,
        parse: Objects::parse,
    },
    Subcommand {
        name: "pcr-event",
        about: "Extends a PCR with an event",
        help: PcrEvent::help,
        parse: PcrEvent::parse,
    },
    Subcommand {
        name: "pcr-read",
        about: "Reads PCRs",
        help: PcrRead::help,
        parse: PcrRead::parse,
    },
    Subcommand {
        name: "policy",
        about: "Builds a policy using a policy expression",
        help: Policy::help,
        parse: Policy::parse,
    },
    Subcommand {
        name: "print-error",
        about: "Encodes and print a TPM error code",
        help: PrintError::help,
        parse: PrintError::parse,
    },
    Subcommand {
        name: "reset-lock",
        about: "Resets the dictionary attack lockout timer",
        help: ResetLock::help,
        parse: ResetLock::parse,
    },
    Subcommand {
        name: "save",
        about: "Saves to non-volatile memory",
        help: Save::help,
        parse: Save::parse,
    },
    Subcommand {
        name: "seal",
        about: "Seals a keyedhash object",
        help: Seal::help,
        parse: Seal::parse,
    },
    Subcommand {
        name: "start-session",
        about: "Starts an authorization session",
        help: StartSession::help,
        parse: StartSession::parse,
    },
    Subcommand {
        name: "unseal",
        about: "Unseals a keyedhash object",
        help: Unseal::help,
        parse: Unseal::parse,
    },
];
const GLOBAL_OPTIONS: &[CommandLineOption] = &[
    (Some("-d"), "--device", "<DEVICE>", "[default: /dev/tpmrm0]"),
    (
        Some("-p"),
        "--password",
        "<PASSWORD>",
        "Default authorization password",
    ),
    (
        Some("-P"),
        "--parent",
        "<URI>",
        "Parent object URI (e.g., 'tpm://0x40000001', 'file:///.../context.bin')",
    ),
    (
        Some("-S"),
        "--session",
        "<URI>",
        "Session object URI (e.g., 'tpm://0x03000000')",
    ),
    (
        None,
        "--log-format",
        "<FORMAT>",
        "[default: plain, possible: plain, pretty]",
    ),
    (Some("-h"), "--help", "", "Print help information"),
    (Some("-V"), "--version", "", "Print version information"),
];
fn print_usage() {
    let mut output =
        format!("tpm2sh {VERSION}\nTPM 2.0 shell\n\nUSAGE:\n    tpm2sh [OPTIONS] <COMMAND>");
    let opt_items: Vec<(String, &str)> = GLOBAL_OPTIONS.iter().map(format_options).collect();
    let max_len = opt_items
        .iter()
        .map(|(left, _)| left.len())
        .max()
        .unwrap_or(0);
    output.push_str(&format_help_section("OPTIONS", &opt_items, max_len));
    println!("{output}");
}

pub fn print_main_help() {
    print_usage();
    let mut output = "\nSUBCOMMANDS:\n".to_string();
    for cmd in SUBCOMMANDS {
        let _ = writeln!(output, "    {: <20} {}", cmd.name, cmd.about);
    }
    println!("{output}");
}

fn print_version() {
    println!("tpm2sh {VERSION}");
}

/// Dispatch parsing to the correct subcommand implementation.
fn dispatch_subcommand(name: &OsString, parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
    let name_str = name
        .to_str()
        .ok_or_else(|| CliError::Usage("Invalid non-UTF8 command".to_string()))?;

    let Some(cmd) = SUBCOMMANDS.iter().find(|c| c.name == name_str) else {
        return Err(CliError::Usage(format!("Unknown command: '{name_str}'")));
    };

    match (cmd.parse)(parser) {
        Err(CliError::Usage(msg)) => {
            eprintln!("{msg}\n");
            (cmd.help)();
            Err(CliError::UsageHandled)
        }
        Err(CliError::Help) => {
            (cmd.help)();
            Err(CliError::HelpHandled)
        }
        res => res,
    }
}

/// Parse command-line arguments.
///
/// # Errors
///
/// Returns a `CliError::Execute` on a failure.
pub fn parse_cli() -> Result<Option<Cli>, CliError> {
    use lexopt::prelude::*;
    let mut cli = Cli {
        device: "/dev/tpmrm0".to_string(),
        ..Default::default()
    };
    let mut parser = lexopt::Parser::from_env();

    while let Some(arg) = parser.next()? {
        match arg {
            Short('h') | Long("help") => {
                return Err(CliError::Help);
            }
            Short('V') | Long("version") => {
                print_version();
                return Ok(None);
            }
            Short('d') | Long("device") => {
                cli.device = parser.value()?.string()?;
            }
            Short('p') | Long("password") => {
                cli.password = Some(parser.value()?.string()?);
            }
            Short('P') | Long("parent") => {
                cli.parent = Some(parser.value()?.string()?);
            }
            Short('S') | Long("session") => {
                cli.session = Some(parser.value()?.string()?);
            }
            Long("log-format") => {
                cli.log_format = parser.value()?.string()?.parse()?;
            }
            Value(val) => {
                cli.command = Some(dispatch_subcommand(&val, &mut parser)?);
                break;
            }
            _ => return Err(CliError::from(arg.unexpected())),
        }
    }

    if cli.command.is_none() {
        print_usage();
        return Err(CliError::UsageHandled);
    }

    Ok(Some(cli))
}

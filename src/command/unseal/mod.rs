// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{
        handle_help, parse_parent_option, parse_session_option, required, DeviceCommand, Subcommand,
    },
    command::{context::Context, CommandError},
    device::{TpmDevice, TpmDeviceError},
    error::{CliError, ParseError},
    key::TpmKey,
    policy::Expression,
    session::session_from_uri,
    uri::Uri,
};
use lexopt::{Arg, Parser, ValueExt};
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic, TpmCc},
    message::TpmLoadCommand,
    message::TpmUnsealCommand,
    TpmParse, TpmTransient,
};

#[derive(Debug, Default)]
pub struct Unseal {
    pub uri: Uri,
    pub parent: Option<Uri>,
    pub session: Option<Uri>,
}

impl Subcommand for Unseal {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");
    const OPTION_PARENT: bool = true;
    const OPTION_SESSION: bool = true;

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut uri = None;
        let mut parent = None;
        let mut session = None;

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("parent") => parse_parent_option(parser, &mut parent)?,
                Arg::Long("session") => parse_session_option(parser, &mut session)?,
                Arg::Value(val) if uri.is_none() => uri = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Unseal {
            uri: required(uri, "<URI>")?,
            parent,
            session,
        })
    }
}

/// Checks if a byte slice contains valid, printable UTF-8.
///
/// "Printable" is defined as not containing any control characters except for
/// common whitespace (newline, carriage return, tab).
fn is_printable_utf8(data: &[u8]) -> bool {
    if let Ok(s) = std::str::from_utf8(data) {
        !s.chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    } else {
        false
    }
}

impl DeviceCommand for Unseal {
    /// Runs `unseal`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let object_handle = match self.uri.ast() {
            Expression::TpmHandle(handle) => TpmTransient(*handle),
            Expression::FilePath(_) | Expression::Data { .. } => {
                let parent_uri = self.parent.as_ref().ok_or_else(|| {
                    CliError::Command(CommandError::Custom(
                        "the '--parent' option is required when unsealing from a file or data URI"
                            .to_string(),
                    ))
                })?;
                let parent_handle = context.load(device, parent_uri)?;

                let key_bytes = self.uri.to_bytes()?;
                let tpm_key = TpmKey::from_pem(&key_bytes)
                    .or_else(|_| TpmKey::from_der(&key_bytes))
                    .map_err(|_| {
                        CommandError::InvalidKey(
                            "failed to parse input as TSS2 PRIVATE KEY".to_string(),
                        )
                    })?;

                let (in_public, _) =
                    Tpm2bPublic::parse(tpm_key.pub_key.as_bytes()).map_err(ParseError::from)?;
                let (in_private, _) =
                    Tpm2bPrivate::parse(tpm_key.priv_key.as_bytes()).map_err(ParseError::from)?;

                let load_cmd = TpmLoadCommand {
                    parent_handle: parent_handle.0.into(),
                    in_private,
                    in_public,
                };
                let handles = [parent_handle.into()];
                let sessions = session_from_uri(&load_cmd, &handles, self.session.as_ref())?;
                let (_rc, resp, _) = device.execute(&load_cmd, &sessions)?;
                let load_resp = resp
                    .Load()
                    .map_err(|_| TpmDeviceError::MismatchedResponse {
                        command: TpmCc::Load,
                    })?;

                context.track(load_resp.object_handle)?;
                load_resp.object_handle
            }
            _ => {
                return Err(CliError::Command(CommandError::InvalidUriScheme {
                    expected: "tpm://, file://, or data://".to_string(),
                    actual: self.uri.to_string(),
                }));
            }
        };

        let unseal_cmd = TpmUnsealCommand {
            item_handle: object_handle.0.into(),
        };
        let unseal_handles = [object_handle.into()];
        let unseal_sessions =
            session_from_uri(&unseal_cmd, &unseal_handles, self.session.as_ref())?;

        let (_rc, unseal_resp, _) = device.execute(&unseal_cmd, &unseal_sessions)?;
        let unseal_resp = unseal_resp
            .Unseal()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::Unseal,
            })?;

        if is_printable_utf8(&unseal_resp.out_data) {
            let s = std::str::from_utf8(&unseal_resp.out_data).expect("already checked for utf-8");
            writeln!(context.writer, "data://utf8,{s}")?;
        } else {
            writeln!(
                context.writer,
                "data://hex,{}",
                hex::encode(unseal_resp.out_data)
            )?;
        }
        Ok(())
    }
}

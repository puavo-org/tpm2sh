// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    session::session_from_args,
    uri::Uri,
};
use lexopt::{Arg, Parser, ValueExt};
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::TpmLoadCommand,
    TpmParse,
};

#[derive(Debug, Default)]
pub struct Load {
    pub parent: Uri,
    pub public: Uri,
    pub private: Uri,
}

impl Subcommand for Load {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut parent = None;
        let mut public = None;
        let mut private = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("parent") | Arg::Short('P') => parent = Some(parser.value()?.parse()?),
                Arg::Long("public") => public = Some(parser.value()?.parse()?),
                Arg::Long("private") => private = Some(parser.value()?.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Load {
            parent: required(parent, "--parent")?,
            public: required(public, "--public")?,
            private: required(private, "--private")?,
        })
    }
}

impl DeviceCommand for Load {
    /// Runs `load`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let parent_handle = context.load(device, &self.parent)?;
        let pub_bytes = self.public.to_bytes()?;
        let priv_bytes = self.private.to_bytes()?;
        let (in_public, _) = Tpm2bPublic::parse(&pub_bytes)?;
        let (in_private, _) = Tpm2bPrivate::parse(&priv_bytes)?;
        let load_cmd = TpmLoadCommand {
            parent_handle: parent_handle.0.into(),
            in_private,
            in_public,
        };
        let handles = [parent_handle.into()];
        let sessions = session_from_args(&load_cmd, &handles, context.cli)?;
        let (resp, _) = device.execute(&load_cmd, &sessions)?;
        let resp = resp
            .Load()
            .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
        context.save(device, resp.object_handle)?;
        Ok(())
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    policy::{self, fill_pcr_digests, PolicyExecutor},
    session::SessionType,
};
use lexopt::{Arg, Parser, ValueExt};
use tpm2_protocol::data::TpmAlgId;

#[derive(Debug, Default)]
pub struct Policy {
    pub expression: String,
    pub compose: bool,
}

impl Subcommand for Policy {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut expression = None;
        let mut compose = false;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("compose") => compose = true,
                Arg::Value(val) if expression.is_none() => expression = Some(val.string()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Policy {
            expression: required(expression, "<EXPRESSION>")?,
            compose,
        })
    }
}

impl DeviceCommand for Policy {
    /// Run 'policy'.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` on failure.
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let mut ast = policy::parse(&self.expression, policy::Parsing::AuthorizationPolicy)?;

        fill_pcr_digests(&mut ast, device)?;

        if self.compose {
            let pcr_count = crate::pcr::pcr_get_count(device)?;
            let session_hash_alg = TpmAlgId::Sha256;
            let session_handle =
                policy::start_trial_session(device, SessionType::Trial, session_hash_alg)?;
            let mut executor = PolicyExecutor::new(pcr_count, device, session_hash_alg);
            executor.execute_policy_ast(session_handle, &ast)?;
            let final_digest = policy::get_policy_digest(executor.device(), session_handle)?;
            policy::flush_session(executor.device(), session_handle)?;
            writeln!(context.writer, "{}", hex::encode(&*final_digest))?;
        } else {
            writeln!(context.writer, "{ast}")?;
        }
        Ok(())
    }
}

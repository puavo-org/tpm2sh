// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::DeviceCommand,
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    policy::SessionType,
    policy::{self, fill_pcr_digests, PolicyExecutor},
};
use argh::FromArgs;
use tpm2_protocol::data::TpmAlgId;

/// Builds authorization policies.
///
/// A policy expression defines a condition that must be met, for example,
/// 'pcr(sha256:0,...)' or 'secret(tpm://...)'.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "policy")]
pub struct Policy {
    /// compose the policy and output only the final digest
    #[argh(switch)]
    pub compose: bool,

    /// policy expression
    #[argh(positional)]
    pub expression: String,
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
            let pcr_count = crate::policy::pcr_get_count(device)?;
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

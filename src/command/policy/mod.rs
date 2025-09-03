// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{self, handle_help, required, Cli, DeviceCommand, SessionType, Subcommand},
    error::ParseError,
    parser::{parse_policy, PolicyExpr},
    pcr::{pcr_composite_digest, pcr_get_count},
    session::session_from_args,
    uri::pcr_selection_to_list,
    CliError, Context, TpmDevice,
};
use lexopt::{Arg, Parser, ValueExt};

use tpm2_protocol::{
    data::{
        Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, TpmAlgId, TpmRh, TpmlDigest,
        TpmtSymDefObject,
    },
    message::{
        TpmFlushContextCommand, TpmPolicyGetDigestCommand, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicySecretCommand, TpmStartAuthSessionCommand,
    },
    TpmSession,
};

#[derive(Debug, Default)]
pub struct Policy {
    pub expression: String,
}

impl Subcommand for Policy {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut expression = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if expression.is_none() => expression = Some(val.string()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Policy {
            expression: required(expression, "<EXPRESSION>")?,
        })
    }
}

struct PolicyExecutor<'a> {
    pcr_count: usize,
    device: &'a mut TpmDevice,
}

impl PolicyExecutor<'_> {
    fn execute_pcr_policy(
        &mut self,
        _cli: &Cli,
        session_handle: TpmSession,
        selection_str: &str,
        digest: Option<&String>,
        _count: Option<&u32>,
    ) -> Result<(), CliError> {
        let pcr_digest_bytes = if let Some(digest_hex) = digest {
            hex::decode(digest_hex).map_err(ParseError::from)?
        } else {
            let pcr_selection_in = pcr_selection_to_list(selection_str, self.pcr_count)?;
            let read_resp = self.device.pcr_read(&pcr_selection_in)?;
            pcr_composite_digest(&read_resp)
        };

        let pcr_selection = pcr_selection_to_list(selection_str, self.pcr_count)?;
        let pcr_digest = Tpm2bDigest::try_from(pcr_digest_bytes.as_slice())?;

        let cmd = TpmPolicyPcrCommand {
            policy_session: session_handle.0.into(),
            pcr_digest,
            pcrs: pcr_selection,
        };
        let handles = [session_handle.into()];
        let sessions = session_from_args(&cmd, &handles, &Cli::default())?;
        self.device.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_secret_policy(
        &mut self,
        _cli: &Cli,
        session_handle: TpmSession,
        auth_handle_uri: &PolicyExpr,
        password: Option<&String>,
    ) -> Result<(), CliError> {
        let auth_handle = match auth_handle_uri {
            PolicyExpr::TpmHandle(handle) => Ok(*handle),
            _ => Err(ParseError::Custom(
                "secret policy requires a tpm:// handle".to_string(),
            )),
        }?;
        let cmd = TpmPolicySecretCommand {
            auth_handle: auth_handle.into(),
            policy_session: session_handle.0.into(),
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };
        let handles = [auth_handle, session_handle.into()];
        let temp_cli = Cli {
            password: password.cloned(),
            ..Default::default()
        };
        let sessions = session_from_args(&cmd, &handles, &temp_cli)?;
        self.device.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_or_policy(
        &mut self,
        cli: &Cli,
        session_handle: TpmSession,
        branches: &[PolicyExpr],
    ) -> Result<(), CliError> {
        let mut branch_digests = TpmlDigest::new();
        for branch_ast in branches {
            let branch_handle =
                start_trial_session(self.device, cli, SessionType::Trial, TpmAlgId::Sha256)?;
            self.execute_policy_ast(cli, branch_handle, branch_ast)?;

            let digest = get_policy_digest(self.device, cli, branch_handle)?;
            branch_digests.try_push(digest)?;

            flush_session(self.device, cli, branch_handle)?;
        }

        let cmd = TpmPolicyOrCommand {
            policy_session: session_handle.0.into(),
            p_hash_list: branch_digests,
        };
        let handles = [session_handle.into()];
        let sessions = session_from_args(&cmd, &handles, &Cli::default())?;
        self.device.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_policy_ast(
        &mut self,
        cli: &Cli,
        session_handle: TpmSession,
        ast: &PolicyExpr,
    ) -> Result<(), CliError> {
        match ast {
            PolicyExpr::Pcr {
                selection,
                digest,
                count,
            } => self.execute_pcr_policy(
                cli,
                session_handle,
                selection,
                digest.as_ref(),
                count.as_ref(),
            ),
            PolicyExpr::Secret {
                auth_handle_uri,
                password,
            } => {
                self.execute_secret_policy(cli, session_handle, auth_handle_uri, password.as_ref())
            }
            PolicyExpr::Or(branches) => self.execute_or_policy(cli, session_handle, branches),
            _ => Err(
                ParseError::Custom("unsupported expression for policy command".to_string()).into(),
            ),
        }
    }
}

fn start_trial_session(
    device: &mut TpmDevice,
    _cli: &Cli,
    session_type: cli::SessionType,
    hash_alg: TpmAlgId,
) -> Result<TpmSession, CliError> {
    let cmd = TpmStartAuthSessionCommand {
        tpm_key: (TpmRh::Null as u32).into(),
        bind: (TpmRh::Null as u32).into(),
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2bEncryptedSecret::default(),
        session_type: session_type.into(),
        symmetric: TpmtSymDefObject::default(),
        auth_hash: hash_alg,
    };
    let (resp, _) = device.execute(&cmd, &[])?;
    let start_resp = resp
        .StartAuthSession()
        .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(start_resp.session_handle)
}

fn flush_session(device: &mut TpmDevice, _cli: &Cli, handle: TpmSession) -> Result<(), CliError> {
    let cmd = TpmFlushContextCommand {
        flush_handle: handle.into(),
    };
    device.execute(&cmd, &[])?;
    Ok(())
}

fn get_policy_digest(
    device: &mut TpmDevice,
    _cli: &Cli,
    session_handle: TpmSession,
) -> Result<Tpm2bDigest, CliError> {
    let cmd = TpmPolicyGetDigestCommand {
        policy_session: session_handle.0.into(),
    };
    let (resp, _) = device.execute(&cmd, &[])?;
    let digest_resp = resp
        .PolicyGetDigest()
        .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(digest_resp.policy_digest)
}

impl DeviceCommand for Policy {
    /// Run 'policy'.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` on failure.
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let ast = parse_policy(&self.expression)?;
        let pcr_count = pcr_get_count(device)?;
        let session_handle =
            start_trial_session(device, context.cli, SessionType::Trial, TpmAlgId::Sha256)?;
        let mut executor = PolicyExecutor { pcr_count, device };
        executor.execute_policy_ast(context.cli, session_handle, &ast)?;
        let final_digest = get_policy_digest(executor.device, context.cli, session_handle)?;
        flush_session(executor.device, context.cli, session_handle)?;
        writeln!(context.writer, "{}", hex::encode(&*final_digest))?;
        Ok(())
    }
}

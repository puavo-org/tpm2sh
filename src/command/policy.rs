// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{collect_values, format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Cli, Commands, Policy},
    error::ParseError,
    pcr::{pcr_get_count, pcr_parse_selection},
    session::session_from_args,
    uri::uri_to_tpm_handle,
    CliError, Command, TpmDevice,
};
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest_derive::Parser;
use std::io::Write;
use std::sync::{Arc, Mutex, MutexGuard};
use tpm2_protocol::{
    data::{Tpm2b, Tpm2bDigest, Tpm2bNonce, TpmAlgId, TpmRh, TpmlDigest, TpmtSymDefObject},
    message::{
        TpmFlushContextCommand, TpmPolicyGetDigestCommand, TpmPolicyOrCommand, TpmPolicyPcrCommand,
        TpmPolicySecretCommand, TpmStartAuthSessionCommand,
    },
    TpmSession,
};

#[derive(Parser)]
#[grammar = "command/policy.pest"]
pub struct PolicyParser;

#[derive(Debug, PartialEq, Clone)]
enum PolicyAst {
    Pcr {
        selection: String,
        digest: Option<String>,
        count: Option<u32>,
    },
    Secret {
        auth_handle_uri: String,
    },
    Or(Vec<PolicyAst>),
}

const ABOUT: &str = "Builds a policy and prints the final digest";
const USAGE: &str = "tpm2sh policy <EXPRESSION>";
const ARGS: &[CommandLineArgument] = &[("EXPRESSION", "e.g., 'pcr(\"sha256:0\",\"...\")'")];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

fn parse_quoted_string(pair: &Pair<'_, Rule>) -> Result<String, CliError> {
    if pair.as_rule() != Rule::quoted_string {
        return Err(ParseError::Custom("expected a quoted string".to_string()).into());
    }
    let s = pair.as_str();
    Ok(s[1..s.len() - 1].to_string())
}

fn parse_policy_internal(mut pairs: Pairs<'_, Rule>) -> Result<PolicyAst, CliError> {
    let pair = pairs
        .next()
        .ok_or_else(|| ParseError::Custom("expected a policy expression".to_string()))?;
    let ast = match pair.as_rule() {
        Rule::pcr_expression => {
            let mut inner_pairs = pair.into_inner();
            let selection = parse_quoted_string(&inner_pairs.next().unwrap())?;
            let digest = inner_pairs
                .next()
                .map(|p| parse_quoted_string(&p))
                .transpose()?;
            let count = inner_pairs
                .next()
                .map(|p| {
                    p.as_str()
                        .strip_prefix("count=")
                        .unwrap_or("")
                        .parse::<u32>()
                })
                .transpose()?;
            PolicyAst::Pcr {
                selection,
                digest,
                count,
            }
        }
        Rule::secret_expression => {
            let auth_handle_uri = parse_quoted_string(&pair.into_inner().next().unwrap())?;
            PolicyAst::Secret { auth_handle_uri }
        }
        Rule::or_expression => {
            let mut or_pairs = pair.into_inner();
            let policy_list_pairs = or_pairs.next().unwrap().into_inner();
            let branches = policy_list_pairs
                .map(|p| parse_policy_internal(p.into_inner()))
                .collect::<Result<_, _>>()?;
            PolicyAst::Or(branches)
        }
        _ => {
            return Err(ParseError::Custom(format!(
                "unexpected policy expression part: {:?}",
                pair.as_rule()
            ))
            .into())
        }
    };
    if pairs.next().is_some() {
        return Err(ParseError::Custom("unexpected trailing input".to_string()).into());
    }

    Ok(ast)
}

fn parse_policy_expression(input: &str) -> Result<PolicyAst, CliError> {
    let pairs = PolicyParser::parse(Rule::policy_expression, input)
        .map_err(|e| ParseError::Custom(e.to_string()))?;
    let mut root_pairs = pairs.clone();
    parse_policy_internal(root_pairs.next().unwrap().into_inner())
}

struct PolicyExecutor<'a> {
    pcr_count: usize,
    chip: MutexGuard<'a, TpmDevice>,
}

impl PolicyExecutor<'_> {
    fn execute_pcr_policy(
        &mut self,
        session_handle: TpmSession,
        selection_str: &str,
        digest: Option<&String>,
        _count: Option<&u32>,
    ) -> Result<(), CliError> {
        let pcr_digest_bytes = hex::decode(digest.ok_or_else(|| {
            CliError::Usage("PCR digest must be provided as an argument".to_string())
        })?)?;

        let pcr_selection = pcr_parse_selection(selection_str, self.pcr_count)?;
        let pcr_digest = Tpm2bDigest::try_from(pcr_digest_bytes.as_slice())?;

        let cmd = TpmPolicyPcrCommand {
            policy_session: session_handle.0.into(),
            pcr_digest,
            pcrs: pcr_selection,
        };
        let handles = [session_handle.into()];
        let sessions = session_from_args(&cmd, &handles, &Cli::default())?;
        self.chip.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_secret_policy(
        &mut self,
        session_handle: TpmSession,
        auth_handle_uri: &str,
    ) -> Result<(), CliError> {
        let auth_handle = uri_to_tpm_handle(auth_handle_uri)?;
        let cmd = TpmPolicySecretCommand {
            auth_handle: auth_handle.into(),
            policy_session: session_handle.0.into(),
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };
        let handles = [auth_handle, session_handle.into()];
        let sessions = session_from_args(
            &cmd,
            &handles,
            &Cli {
                password: Some(String::new()),
                ..Default::default()
            },
        )?;
        self.chip.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_or_policy(
        &mut self,
        session_handle: TpmSession,
        branches: &[PolicyAst],
    ) -> Result<(), CliError> {
        let mut branch_digests = TpmlDigest::new();
        for branch_ast in branches {
            let branch_handle =
                start_trial_session(&mut self.chip, cli::SessionType::Trial, TpmAlgId::Sha256)?;
            self.execute_policy_ast(branch_handle, branch_ast)?;

            let digest = get_policy_digest(&mut self.chip, branch_handle)?;
            branch_digests.try_push(digest)?;

            flush_session(&mut self.chip, branch_handle)?;
        }

        let cmd = TpmPolicyOrCommand {
            policy_session: session_handle.0.into(),
            p_hash_list: branch_digests,
        };
        let handles = [session_handle.into()];
        let sessions = session_from_args(&cmd, &handles, &Cli::default())?;
        self.chip.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_policy_ast(
        &mut self,
        session_handle: TpmSession,
        ast: &PolicyAst,
    ) -> Result<(), CliError> {
        match ast {
            PolicyAst::Pcr {
                selection,
                digest,
                count,
            } => {
                self.execute_pcr_policy(session_handle, selection, digest.as_ref(), count.as_ref())
            }
            PolicyAst::Secret { auth_handle_uri } => {
                self.execute_secret_policy(session_handle, auth_handle_uri)
            }
            PolicyAst::Or(branches) => self.execute_or_policy(session_handle, branches),
        }
    }
}

fn start_trial_session(
    chip: &mut TpmDevice,
    session_type: cli::SessionType,
    hash_alg: TpmAlgId,
) -> Result<TpmSession, CliError> {
    let cmd = TpmStartAuthSessionCommand {
        tpm_key: (TpmRh::Null as u32).into(),
        bind: (TpmRh::Null as u32).into(),
        nonce_caller: Tpm2bNonce::default(),
        encrypted_salt: Tpm2b::default(),
        session_type: session_type.into(),
        symmetric: TpmtSymDefObject::default(),
        auth_hash: hash_alg,
    };
    let (resp, _) = chip.execute(&cmd, &[])?;
    let start_resp = resp
        .StartAuthSession()
        .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(start_resp.session_handle)
}

fn flush_session(chip: &mut TpmDevice, handle: TpmSession) -> Result<(), CliError> {
    let cmd = TpmFlushContextCommand {
        flush_handle: handle.into(),
    };
    chip.execute(&cmd, &[])?;
    Ok(())
}

fn get_policy_digest(
    chip: &mut TpmDevice,
    session_handle: TpmSession,
) -> Result<Tpm2bDigest, CliError> {
    let cmd = TpmPolicyGetDigestCommand {
        policy_session: session_handle.0.into(),
    };
    let (resp, _) = chip.execute(&cmd, &[])?;
    let digest_resp = resp
        .PolicyGetDigest()
        .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(digest_resp.policy_digest)
}

impl Command for Policy {
    fn help() {
        println!(
            "{}",
            format_subcommand_help("policy", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        arguments!(parser, arg, Self::help, {
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        let values = collect_values(parser)?;
        if values.len() != 1 {
            return Err(CliError::Usage(format!(
                "'policy' requires 1 argument, but {} were provided",
                values.len()
            )));
        }
        let expression = values
            .into_iter()
            .next()
            .ok_or_else(|| CliError::Execution("value missing".to_string()))?;
        Ok(Commands::Policy(Policy { expression }))
    }

    /// Run 'policy'.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` on failure.
    fn run<W: Write>(
        &self,
        _cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
        writer: &mut W,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let ast = parse_policy_expression(&self.expression)?;
        let pcr_count = pcr_get_count(&mut chip)?;
        let session_handle =
            start_trial_session(&mut chip, cli::SessionType::Trial, TpmAlgId::Sha256)?;

        {
            let mut executor = PolicyExecutor { pcr_count, chip };
            executor.execute_policy_ast(session_handle, &ast)?;
        }

        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let final_digest = get_policy_digest(&mut chip, session_handle)?;
        flush_session(&mut chip, session_handle)?;

        writeln!(writer, "{}", hex::encode(&*final_digest))?;

        Ok(())
    }
}

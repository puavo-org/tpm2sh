// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineArgument, CommandLineOption},
    cli::{self, Commands, Policy},
    get_pcr_count, get_tpm_device, key, parse_args, parse_pcr_selection, parse_tpm_handle_from_uri,
    Command, CommandIo, CommandType, PipelineObject, PolicySession, TpmError,
};
use lexopt::ValueExt;
use pest::iterators::{Pair, Pairs};
use pest::Parser;
use pest_derive::Parser;
use std::io::{Read, Write};
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

const ABOUT: &str = "Builds a policy using a policy expression";
const USAGE: &str = "tpm2sh policy <EXPRESSION>";
const ARGS: &[CommandLineArgument] = &[("EXPRESSION", "e.g., 'pcr(\"sha256:0\",\"...\")'")];
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

fn parse_quoted_string(pair: &Pair<'_, Rule>) -> Result<String, TpmError> {
    if pair.as_rule() != Rule::quoted_string {
        return Err(TpmError::Parse("expected a quoted string".to_string()));
    }
    let s = pair.as_str();
    Ok(s[1..s.len() - 1].to_string())
}

fn parse_policy_internal(mut pairs: Pairs<'_, Rule>) -> Result<PolicyAst, TpmError> {
    let pair = pairs
        .next()
        .ok_or_else(|| TpmError::Parse("expected a policy expression".to_string()))?;
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
                .transpose()
                .map_err(|e| TpmError::Parse(e.to_string()))?;
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
            return Err(TpmError::Parse(format!(
                "unexpected policy expression part: {:?}",
                pair.as_rule()
            )))
        }
    };
    if pairs.next().is_some() {
        return Err(TpmError::Parse("unexpected trailing input".to_string()));
    }

    Ok(ast)
}

fn parse_policy_expression(input: &str) -> Result<PolicyAst, TpmError> {
    let pairs = PolicyParser::parse(Rule::policy_expression, input)
        .map_err(|e| TpmError::Parse(e.to_string()))?;
    let mut root_pairs = pairs.clone();
    parse_policy_internal(root_pairs.next().unwrap().into_inner())
}

struct PolicyExecutor<'a> {
    chip: &'a mut crate::TpmDevice,
    pcr_count: usize,
}

impl PolicyExecutor<'_> {
    fn execute_pcr_policy<R: Read, W: Write>(
        &mut self,
        io: &mut CommandIo<R, W>,
        session_handle: TpmSession,
        selection_str: &str,
        digest: Option<&String>,
        _count: Option<&u32>,
    ) -> Result<(), TpmError> {
        let pcr_digest_bytes = hex::decode(digest.ok_or_else(|| {
            TpmError::Usage("PCR digest must be provided as an argument".to_string())
        })?)?;

        let pcr_selection = if selection_str.is_empty() {
            let pcr_values = io.pop_pcr_values()?;
            crate::pcr::pcr_values_to_selection(&pcr_values, self.pcr_count)?
        } else {
            parse_pcr_selection(selection_str, self.pcr_count)?
        };

        let pcr_digest = Tpm2bDigest::try_from(pcr_digest_bytes.as_slice())?;

        let cmd = TpmPolicyPcrCommand {
            policy_session: session_handle.0.into(),
            pcr_digest,
            pcrs: pcr_selection,
        };
        let handles = [session_handle.into()];
        let sessions = crate::get_auth_sessions(&cmd, &handles, None, None)?;
        self.chip.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_secret_policy(
        &mut self,
        session_handle: TpmSession,
        auth_handle_uri: &str,
    ) -> Result<(), TpmError> {
        let auth_handle = parse_tpm_handle_from_uri(auth_handle_uri)?;
        let cmd = TpmPolicySecretCommand {
            auth_handle: auth_handle.into(),
            policy_session: session_handle.0.into(),
            nonce_tpm: Tpm2bNonce::default(),
            cp_hash_a: Tpm2bDigest::default(),
            policy_ref: Tpm2bNonce::default(),
            expiration: 0,
        };
        let handles = [auth_handle, session_handle.into()];
        let sessions = crate::get_auth_sessions(&cmd, &handles, None, Some(""))?;
        self.chip.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_or_policy<R: Read, W: Write>(
        &mut self,
        io: &mut CommandIo<R, W>,
        session_handle: TpmSession,
        branches: &[PolicyAst],
    ) -> Result<(), TpmError> {
        let mut branch_digests = TpmlDigest::new();
        for branch_ast in branches {
            let branch_handle =
                start_trial_session(self.chip, cli::SessionType::Trial, TpmAlgId::Sha256)?;
            self.execute_policy_ast(io, branch_handle, branch_ast)?;

            let digest = get_policy_digest(self.chip, branch_handle)?;
            branch_digests.try_push(digest)?;

            flush_session(self.chip, branch_handle)?;
        }

        let cmd = TpmPolicyOrCommand {
            policy_session: session_handle.0.into(),
            p_hash_list: branch_digests,
        };
        let handles = [session_handle.into()];
        let sessions = crate::get_auth_sessions(&cmd, &handles, None, None)?;
        self.chip.execute(&cmd, &sessions)?;
        Ok(())
    }

    fn execute_policy_ast<R: Read, W: Write>(
        &mut self,
        io: &mut CommandIo<R, W>,
        session_handle: TpmSession,
        ast: &PolicyAst,
    ) -> Result<(), TpmError> {
        match ast {
            PolicyAst::Pcr {
                selection,
                digest,
                count,
            } => self.execute_pcr_policy(
                io,
                session_handle,
                selection,
                digest.as_ref(),
                count.as_ref(),
            ),
            PolicyAst::Secret { auth_handle_uri } => {
                self.execute_secret_policy(session_handle, auth_handle_uri)
            }
            PolicyAst::Or(branches) => self.execute_or_policy(io, session_handle, branches),
        }
    }
}

fn start_trial_session(
    chip: &mut crate::TpmDevice,
    session_type: cli::SessionType,
    hash_alg: TpmAlgId,
) -> Result<TpmSession, TpmError> {
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
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(start_resp.session_handle)
}

fn flush_session(chip: &mut crate::TpmDevice, handle: TpmSession) -> Result<(), TpmError> {
    let cmd = TpmFlushContextCommand {
        flush_handle: handle.into(),
    };
    chip.execute(&cmd, &[])?;
    Ok(())
}

fn get_policy_digest(
    chip: &mut crate::TpmDevice,
    session_handle: TpmSession,
) -> Result<Tpm2bDigest, TpmError> {
    let cmd = TpmPolicyGetDigestCommand {
        policy_session: session_handle.0.into(),
    };
    let (resp, _) = chip.execute(&cmd, &[])?;
    let digest_resp = resp
        .PolicyGetDigest()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok(digest_resp.policy_digest)
}

impl Command for Policy {
    fn command_type(&self) -> CommandType {
        CommandType::Pipe
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("policy", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Policy::default();
        let mut expression_arg: Option<String> = None;

        parse_args!(parser, arg, Self::help, {
            lexopt::Arg::Value(val) if expression_arg.is_none() => {
                expression_arg = Some(val.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });

        if let Some(expression) = expression_arg {
            args.expression = expression;
            Ok(Commands::Policy(args))
        } else {
            Err(TpmError::Usage(
                "Missing required argument: <EXPRESSION>".to_string(),
            ))
        }
    }

    /// Run 'policy'.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on failure.
    fn run<R: Read, W: Write>(&self, io: &mut CommandIo<R, W>) -> Result<(), TpmError> {
        let mut chip = get_tpm_device()?;

        let (mut session_obj, is_new_trial) =
            io.pop_policy_session()
                .map(|s| (s, false))
                .or_else(|_: TpmError| {
                    let hash_alg = TpmAlgId::Sha256;
                    let trial_handle =
                        start_trial_session(&mut chip, cli::SessionType::Trial, hash_alg)?;
                    let handle_uri = format!("tpm://{trial_handle:#010x}");
                    Ok::<_, TpmError>((
                        PolicySession {
                            context: handle_uri,
                            algorithm: key::tpm_alg_id_to_str(hash_alg).to_string(),
                            digest: String::new(),
                        },
                        true,
                    ))
                })?;

        let ast = parse_policy_expression(&self.expression)?;
        let pcr_count = get_pcr_count(&mut chip)?;
        let session_handle = TpmSession(parse_tpm_handle_from_uri(&session_obj.context)?);

        {
            let mut executor = PolicyExecutor {
                chip: &mut chip,
                pcr_count,
            };
            executor.execute_policy_ast(io, session_handle, &ast)?;
        }

        let final_digest = get_policy_digest(&mut chip, session_handle)?;
        session_obj.digest = hex::encode(&*final_digest);

        if is_new_trial {
            flush_session(&mut chip, session_handle)?;
            writeln!(io.writer(), "{}", session_obj.digest)?;
        } else {
            io.push_object(PipelineObject::PolicySession(session_obj));
        }

        Ok(())
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, Convert, KeyFormat},
    parse_args, resolve_uri_to_bytes, util, Command, CommandIo, CommandType, Key, PipelineObject,
    TpmDevice, TpmError, TpmKey,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::{data, TpmParse};

const ABOUT: &str = "Converts key objects between pipeline JSON and PEM/DER formats";
const USAGE: &str = "tpm2sh convert [OPTIONS] <INPUT_URI>";
const ARGS: &[(&str, &str)] = &[(
    "INPUT_URI",
    "URI of the input object (e.g., 'pipe://-1', 'file:///path/to/key.pem')",
)];
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--from",
        "<FORMAT>",
        "Input format [possible: json, pem, der]",
    ),
    (
        None,
        "--to",
        "<FORMAT>",
        "Output format [possible: json, pem, der]",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Convert {
    fn command_type(&self) -> CommandType {
        CommandType::Pipe
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("convert", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Convert::default();
        parse_args!(parser, arg, Self::help, {
            Long("from") => {
                args.from = parser.value()?.string()?.parse()?;
            }
            Long("to") => {
                args.to = parser.value()?.string()?.parse()?;
            }
            Value(val) if args.input_uri.is_none() => {
                args.input_uri = Some(val.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        if args.input_uri.is_none() {
            return Err(TpmError::Usage(
                "Missing required argument <INPUT_URI>".to_string(),
            ));
        }
        Ok(Commands::Convert(args))
    }

    fn is_local(&self) -> bool {
        true
    }

    /// Runs `convert`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        _device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), TpmError> {
        let input_bytes = resolve_uri_to_bytes(self.input_uri.as_ref().unwrap(), &[])?;

        let tpm_key = match self.from {
            KeyFormat::Json => {
                let key_obj: Key = serde_json::from_slice(&input_bytes)?;
                let public_bytes = resolve_uri_to_bytes(&key_obj.public, &[])?;
                let private_bytes = resolve_uri_to_bytes(&key_obj.private, &[])?;

                let (public, _) = data::Tpm2bPublic::parse(&public_bytes)?;
                TpmKey {
                    oid: vec![2, 23, 133, 10, 1, 3],
                    parent: "tpm://0x40000001".to_string(),
                    pub_key: util::build_to_vec(&public)?,
                    priv_key: private_bytes,
                }
            }
            KeyFormat::Pem => TpmKey::from_pem(&input_bytes)?,
            KeyFormat::Der => TpmKey::from_der(&input_bytes)?,
        };

        match self.to {
            KeyFormat::Json => {
                let key_obj = Key {
                    public: format!("data://base64,{}", base64_engine.encode(&tpm_key.pub_key)),
                    private: format!("data://base64,{}", base64_engine.encode(&tpm_key.priv_key)),
                };
                io.push_object(PipelineObject::Key(key_obj));
            }
            KeyFormat::Pem => {
                let pem_string = tpm_key.to_pem()?;
                write!(io.writer(), "{pem_string}")?;
            }
            KeyFormat::Der => {
                let der_bytes = tpm_key.to_der()?;
                io.writer().write_all(&der_bytes)?;
            }
        }

        Ok(())
    }
}

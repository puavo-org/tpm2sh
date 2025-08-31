// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineOption},
    cli::{Cli, Commands, Convert, KeyFormat},
    key::{JsonTpmKey, TpmKey},
    uri::{uri_to_bytes, uri_to_tpm_handle},
    util, CliError, Command, TpmDevice,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use pkcs8::der::asn1::OctetString;
use std::io::Write;
use std::sync::{Arc, Mutex};
use tpm2_protocol::{data, TpmParse};

const ABOUT: &str = "Converts key objects between ASN.1 and JSON format";
const USAGE: &str = "tpm2sh convert [OPTIONS] <INPUT_URI>";
const ARGS: &[(&str, &str)] = &[(
    "INPUT_URI",
    "URI of the input object (e.g., 'file:///path/to/key.pem')",
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
    fn help() {
        println!(
            "{}",
            format_subcommand_help("convert", ABOUT, USAGE, ARGS, OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = Convert::default();
        arguments!(parser, arg, Self::help, {
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
                return Err(CliError::from(arg.unexpected()));
            }
        });
        if args.input_uri.is_none() {
            return Err(CliError::Usage(
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
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        _device: Option<Arc<Mutex<TpmDevice>>>,
        writer: &mut W,
    ) -> Result<(), CliError> {
        let input_bytes = uri_to_bytes(self.input_uri.as_ref().unwrap(), &[])?;

        let tpm_key = match self.from {
            KeyFormat::Json => {
                let key_obj: JsonTpmKey = serde_json::from_slice(&input_bytes)?;
                let public_bytes = uri_to_bytes(&key_obj.public, &[])?;
                let private_bytes = uri_to_bytes(&key_obj.private, &[])?;

                let (public, _) = data::Tpm2bPublic::parse(&public_bytes)?;
                let oid = crate::crypto::ID_LOADABLE_KEY;

                let parent_handle = if let Some(uri) = &cli.parent {
                    uri_to_tpm_handle(uri)?
                } else {
                    return Err(CliError::Usage(
                        "Missing required --parent argument for JSON conversion".to_string(),
                    ));
                };

                TpmKey {
                    oid,
                    parent: parent_handle,
                    pub_key: OctetString::new(util::build_to_vec(&public)?)?,
                    priv_key: OctetString::new(private_bytes)?,
                }
            }
            KeyFormat::Pem => TpmKey::from_pem(&input_bytes)?,
            KeyFormat::Der => TpmKey::from_der(&input_bytes)?,
        };

        match self.to {
            KeyFormat::Json => {
                let key_obj = JsonTpmKey {
                    public: format!("data://base64,{}", base64_engine.encode(&tpm_key.pub_key)),
                    private: format!("data://base64,{}", base64_engine.encode(&tpm_key.priv_key)),
                };
                let json_string = serde_json::to_string_pretty(&key_obj)?;
                writeln!(writer, "{json_string}")?;
            }
            KeyFormat::Pem => {
                let pem_string = tpm_key.to_pem()?;
                write!(writer, "{pem_string}")?;
            }
            KeyFormat::Der => {
                let der_bytes = tpm_key.to_der()?;
                writer.write_all(&der_bytes)?;
            }
        }

        Ok(())
    }
}

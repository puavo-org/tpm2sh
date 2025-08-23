// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, Convert, KeyFormat, Object},
    parse_args, Command, CommandIo, CommandType, ObjectData, TpmDevice, TpmError, TpmKey,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use std::{
    fs::File,
    io::{self, Read, Write},
};

const ABOUT: &str = "Converts keys between ASN.1 and JSON format";
const USAGE: &str = "tpm2sh convert [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--from",
        "<FORMAT>",
        "Input format [default: json, possible: json, pem, der]",
    ),
    (
        None,
        "--to",
        "<FORMAT>",
        "Output format [default: pem, possible: json, pem, der]",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

/// Parses a JSON object into an intermediate `TpmKey` representation.
fn json_to_tpm_key(data: &ObjectData) -> Result<TpmKey, TpmError> {
    Ok(TpmKey {
        oid: data
            .oid
            .split('.')
            .map(|s| {
                s.parse::<u32>()
                    .map_err(|_| TpmError::Parse("invalid OID arc".to_string()))
            })
            .collect::<Result<_, _>>()?,
        parent: data.parent.clone(),
        pub_key: base64_engine.decode(&data.public)?,
        priv_key: base64_engine.decode(&data.private)?,
    })
}

/// Converts an intermediate `TpmKey` into a final `ObjectData` struct.
fn tpm_key_to_object_data(key: TpmKey) -> ObjectData {
    ObjectData {
        oid: key
            .oid
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("."),
        empty_auth: false,
        parent: key.parent,
        public: base64_engine.encode(key.pub_key),
        private: base64_engine.encode(key.priv_key),
    }
}

fn read_all(path: Option<&str>) -> Result<Vec<u8>, TpmError> {
    let mut buf = Vec::new();
    match path {
        Some("-") | None => {
            io::stdin()
                .read_to_end(&mut buf)
                .map_err(|e| TpmError::File("stdin".to_string(), e))?;
        }
        Some(file_path) => {
            File::open(file_path)
                .and_then(|mut f| f.read_to_end(&mut buf))
                .map_err(|e| TpmError::File(file_path.to_string(), e))?;
        }
    }
    Ok(buf)
}

impl Command for Convert {
    fn command_type(&self) -> CommandType {
        CommandType::Pipe
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("convert", ABOUT, USAGE, &[], OPTIONS)
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
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
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
    fn run(
        &self,
        _device: &mut Option<TpmDevice>,
        log_format: cli::LogFormat,
    ) -> Result<(), TpmError> {
        let mut io = CommandIo::new(std::io::stdout(), log_format)?;

        let input_key = match self.from {
            KeyFormat::Json => {
                let obj = io.consume_object(|obj| matches!(obj, Object::Key(_)))?;
                let Object::Key(data) = obj else {
                    unreachable!();
                };
                json_to_tpm_key(&data)?
            }
            KeyFormat::Pem => TpmKey::from_pem(&read_all(None)?)?,
            KeyFormat::Der => TpmKey::from_der(&read_all(None)?)?,
        };

        match self.to {
            KeyFormat::Json => {
                let data = tpm_key_to_object_data(input_key);
                io.push_object(Object::Key(data));
            }
            KeyFormat::Pem => println!("{}", input_key.to_pem()?),
            KeyFormat::Der => std::io::stdout().write_all(&input_key.to_der()?)?,
        }

        io.finalize()
    }
}

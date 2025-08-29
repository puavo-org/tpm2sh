// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, PrintStack},
    parse_args,
    schema::{Key, PipelineObject, PublicArea},
    Command, CommandIo, CommandType, TpmDevice, TpmError,
};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::TpmParse;

const ABOUT: &str = "Prints a human-readable summary of the object stack to stdout";
const USAGE: &str = "tpm2sh print-stack";
const OPTIONS: &[CommandLineOption] = &[(Some("-h"), "--help", "", "Print help information")];

impl Command for PrintStack {
    fn command_type(&self) -> CommandType {
        CommandType::Sink
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("print-stack", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        parse_args!(parser, arg, Self::help, {
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::PrintStack(PrintStack))
    }

    fn is_local(&self) -> bool {
        true
    }

    /// Runs `print-stack`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails.
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        _device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), TpmError> {
        let mut objects = Vec::new();

        while let Ok(obj) = io.pop_active_object() {
            objects.push(obj);
        }

        if objects.is_empty() {
            writeln!(io.writer(), "Pipeline is empty.")?;
            return Ok(());
        }

        for (i, obj) in objects.iter().rev().enumerate() {
            writeln!(io.writer(), "--- Object {i} (Top of Stack) ---")?;
            pretty_print_object(obj, io.writer())?;
        }

        Ok(())
    }
}

/// Helper function to print a detailed summary of a pipeline object.
fn pretty_print_object<W: Write>(obj: &PipelineObject, writer: &mut W) -> Result<(), TpmError> {
    let json_val = serde_json::to_value(obj)?;
    let pretty_json = serde_json::to_string_pretty(&json_val)?;
    writeln!(writer, "{pretty_json}")?;

    if let PipelineObject::Key(key) = obj {
        writeln!(writer, "  Decoded Public Area:")?;
        print_decoded_public_area(key, writer)?;
    }

    Ok(())
}

/// Decodes and prints the public area of a key object.
fn print_decoded_public_area<W: Write>(key: &Key, writer: &mut W) -> Result<(), TpmError> {
    let pub_bytes = crate::resolve_uri_to_bytes(&key.public, &[])?;
    let (tpm_pub, _) = tpm2_protocol::data::Tpm2bPublic::parse(&pub_bytes)?;

    let public_area = PublicArea::try_from(&tpm_pub.inner)?;
    let pa_json = serde_json::to_string_pretty(&public_area)?;

    for line in pa_json.lines() {
        writeln!(writer, "    {line}")?;
    }
    Ok(())
}

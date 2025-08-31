// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineOption},
    cli::{Cli, Commands, PrintStack},
    pipeline::{
        CommandIo, Entry as PipelineEntry, Key as PipelineKey, PublicArea as PipelinePublicArea,
    },
    CliError, Command, CommandType, TpmDevice,
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

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        arguments!(parser, arg, Self::help, {
            _ => {
                return Err(CliError::from(arg.unexpected()));
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
    /// Returns a `CliError` if the execution fails.
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        _cli: &Cli,
        _device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        let mut objects = Vec::new();

        while let Ok(obj) = io.pop_object() {
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
fn pretty_print_object<W: Write>(obj: &PipelineEntry, writer: &mut W) -> Result<(), CliError> {
    let json_val = serde_json::to_value(obj)?;
    let pretty_json = serde_json::to_string_pretty(&json_val)?;
    writeln!(writer, "{pretty_json}")?;

    if let PipelineEntry::Key(key) = obj {
        writeln!(writer, "  Decoded Public Area:")?;
        print_decoded_public_area(key, writer)?;
    }

    Ok(())
}

/// Decodes and prints the public area of a key object.
fn print_decoded_public_area<W: Write>(key: &PipelineKey, writer: &mut W) -> Result<(), CliError> {
    let pub_bytes = crate::resolve_uri_to_bytes(&key.public, &[])?;
    let (tpm_pub, _) = tpm2_protocol::data::Tpm2bPublic::parse(&pub_bytes)?;

    let public_area = PipelinePublicArea::try_from(&tpm_pub.inner)?;
    let pa_json = serde_json::to_string_pretty(&public_area)?;

    for line in pa_json.lines() {
        writeln!(writer, "    {line}")?;
    }
    Ok(())
}

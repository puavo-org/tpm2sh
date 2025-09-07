// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, LocalCommand, Subcommand},
    command::context::Context,
    error::CliError,
    util::parse_tpm_rc,
};
use lexopt::{Arg, Parser};
use tpm2_protocol::data::TpmRc;

#[derive(Debug)]
pub struct PrintError {
    pub rc: TpmRc,
}

impl Subcommand for PrintError {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut rc = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if rc.is_none() => {
                    let rc_str = val.to_string_lossy();
                    let rc_val =
                        parse_tpm_rc(&rc_str).map_err(|e| lexopt::Error::from(e.to_string()))?;
                    rc = Some(rc_val);
                }
                _ => return handle_help(arg),
            }
        }
        Ok(PrintError {
            rc: required(rc, "<RC>")?,
        })
    }
}

impl LocalCommand for PrintError {
    fn run(&self, context: &mut Context) -> Result<(), CliError> {
        writeln!(context.writer, "{}", self.rc)?;
        Ok(())
    }
}

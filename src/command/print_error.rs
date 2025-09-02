// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, LocalCommand, PrintError},
    CliError,
};
use std::io::Write;

impl LocalCommand for PrintError {
    fn run<W: Write>(&self, _cli: &Cli, writer: &mut W) -> Result<crate::Resources, CliError> {
        writeln!(writer, "{}", self.rc)?;
        Ok(crate::Resources::new(Vec::new()))
    }
}

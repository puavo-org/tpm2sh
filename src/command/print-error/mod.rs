// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{LocalCommand, PrintError},
    CliError, Context,
};
use std::io::Write;

impl LocalCommand for PrintError {
    fn run<W: Write>(&self, context: &mut Context<W>) -> Result<(), CliError> {
        writeln!(context.writer, "{}", self.rc)?;
        Ok(())
    }
}

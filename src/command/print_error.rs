// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, PrintError},
    CliError, Command, TpmDevice,
};
use std::io::Write;
use std::sync::{Arc, Mutex};

impl Command for PrintError {
    fn is_local(&self) -> bool {
        true
    }

    fn run<W: Write>(
        &self,
        _cli: &Cli,
        _device: Option<Arc<Mutex<TpmDevice>>>,
        writer: &mut W,
    ) -> Result<(), CliError> {
        writeln!(writer, "{}", self.rc)?;
        Ok(())
    }
}

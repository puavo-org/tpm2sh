// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use cli::execute_cli;
use log::error;
use std::io::Write;

/// CTRL-C exits with 130 as exit codes larger than 128 commonly refer to an
/// external signal indexed by the signal number.
fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

    if ctrlc::set_handler(move || {
        let mut stderr = std::io::stderr();
        let _ = write!(stderr, "\x1B[?25h");
        let _ = stderr.flush();
        std::process::exit(130);
    })
    .is_err()
    {
        eprintln!("CTRL-C handler failed");
        std::process::exit(1);
    }

    if let Err(err) = execute_cli() {
        if err.is_usage_error() {
            eprintln!("{err}");
            std::process::exit(2);
        } else {
            error!("{err}");
            std::process::exit(1);
        }
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use cli::{error::CliError, execute_cli};
use log::error;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

    let result = execute_cli();

    match result {
        Ok(()) => {}
        Err(CliError::Help) | Err(CliError::HelpHandled) => std::process::exit(0),
        Err(CliError::UsageHandled) => std::process::exit(2),
        Err(err) => {
            if err.is_usage_error() {
                eprintln!("{err}");
                std::process::exit(2);
            } else {
                error!("{err}");
                std::process::exit(1);
            }
        }
    }
}

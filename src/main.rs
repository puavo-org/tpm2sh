// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use cli::{execute_cli, TpmError};
use log::error;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

    match execute_cli() {
        Ok(()) => {}
        Err(TpmError::Help) => std::process::exit(0),
        Err(TpmError::UsageHandled) => std::process::exit(2),
        Err(err) => {
            if err.is_interactive() {
                eprintln!("{err}");
                std::process::exit(2);
            } else {
                error!("{err}");
                std::process::exit(1);
            }
        }
    }
}

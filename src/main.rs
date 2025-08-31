// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use cli::execute_cli;
use log::error;

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

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

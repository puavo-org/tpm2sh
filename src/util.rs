// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::CliError;
use tpm2_protocol::{data::TpmRc, TpmBuild, TpmPersistent, TpmWriter, TPM_MAX_COMMAND_SIZE};

/// Parses a hex string (with or without a "0x" prefix) into a u32.
///
/// # Errors
///
/// Returns a `CliError::Parse` if the string is not a valid hex integer.
pub fn parse_hex_u32(s: &str) -> Result<u32, CliError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(CliError::from)
}

/// Parses a PCR index string (decimal or hex with "0x" prefix) into a u32.
///
/// # Errors
///
/// Returns a `CliError::Parse` if the string is not a valid integer.
pub fn parse_pcr_index(s: &str) -> Result<u32, CliError> {
    if let Some(hex_val) = s.strip_prefix("0x") {
        u32::from_str_radix(hex_val, 16).map_err(CliError::from)
    } else {
        s.parse::<u32>().map_err(CliError::from)
    }
}

/// Parses a hex string into a `TpmPersistent` handle.
///
/// # Errors
///
/// Returns a `CliError::Parse` if the string is not a valid hex integer.
pub fn parse_persistent_handle(s: &str) -> Result<TpmPersistent, CliError> {
    parse_hex_u32(s).map(TpmPersistent)
}

/// Parses a hex string into a `TpmRc` (TPM Return Code).
///
/// # Errors
///
/// Returns a `CliError::Parse` if the string is not a valid hex integer
/// or the value is not a valid `TpmRc`.
pub fn parse_tpm_rc(s: &str) -> Result<TpmRc, CliError> {
    let raw_rc: u32 = parse_hex_u32(s)?;
    Ok(TpmRc::try_from(raw_rc)?)
}

/// A clap value parser for `TpmRc`.
///
/// # Errors
///
/// Returns an error string if the input is not a valid hex u32 or not a valid `TpmRc`.
pub fn parse_tpm_rc_str(s: &str) -> Result<TpmRc, String> {
    parse_tpm_rc(s).map_err(|e| e.to_string())
}

/// A helper to build a `TpmBuild` type into a `Vec<u8>`.
///
/// # Errors
///
/// Returns a `CliError::Build` if the object cannot be serialized into the buffer.
pub fn build_to_vec<T: TpmBuild>(obj: &T) -> Result<Vec<u8>, CliError> {
    let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.build(&mut writer)?;
        writer.len()
    };
    Ok(buf[..len].to_vec())
}

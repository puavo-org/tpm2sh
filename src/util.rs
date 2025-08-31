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

/// Parses a PCR URI string (e.g., `pcr://sha256,7`) into a bank name and index.
///
/// # Errors
///
/// Returns a `CliError::Parse` if the URI is malformed.
pub fn parse_pcr_uri(uri_str: &str) -> Result<(String, u32), CliError> {
    let Some(path) = uri_str.strip_prefix("pcr://") else {
        return Err(crate::error::ParseError::Custom(format!(
            "Invalid PCR URI scheme: '{uri_str}'"
        ))
        .into());
    };

    let Some((bank, index_str)) = path.split_once(',') else {
        return Err(crate::error::ParseError::Custom(format!(
            "Invalid PCR URI format, expected 'pcr://bank,index': '{uri_str}'"
        ))
        .into());
    };

    let index = parse_pcr_index(index_str)?;
    Ok((bank.to_string(), index))
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

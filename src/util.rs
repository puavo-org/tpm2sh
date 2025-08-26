// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmError;
use tpm2_protocol::{data::TpmRc, TpmBuild, TpmPersistent, TpmWriter, TPM_MAX_COMMAND_SIZE};

/// Parses a hex string (with or without a "0x" prefix) into a u32.
///
/// # Errors
///
/// Returns a `TpmError::Parse` if the string is not a valid hex integer.
pub fn parse_hex_u32(s: &str) -> Result<u32, TpmError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(TpmError::from)
}

/// Parses a hex string into a `TpmPersistent` handle.
///
/// # Errors
///
/// Returns a `TpmError::Parse` if the string is not a valid hex integer.
pub fn parse_persistent_handle(s: &str) -> Result<TpmPersistent, TpmError> {
    parse_hex_u32(s).map(TpmPersistent)
}

/// Parses a hex string into a `TpmRc` (TPM Return Code).
///
/// # Errors
///
/// Returns a `TpmError::Parse` if the string is not a valid hex integer
/// or the value is not a valid `TpmRc`.
pub fn parse_tpm_rc(s: &str) -> Result<TpmRc, TpmError> {
    let raw_rc: u32 = parse_hex_u32(s)?;
    Ok(TpmRc::try_from(raw_rc)?)
}

/// A helper to build a `TpmBuild` type into a `Vec<u8>`.
///
/// # Errors
///
/// Returns a `TpmError::Build` if the object cannot be serialized into the buffer.
pub fn build_to_vec<T: TpmBuild>(obj: &T) -> Result<Vec<u8>, TpmError> {
    let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.build(&mut writer)?;
        writer.len()
    };
    Ok(buf[..len].to_vec())
}

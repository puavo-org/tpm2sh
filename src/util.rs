// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::error::ProtocolError;
use anyhow::{Context, Result};
use tpm2_protocol::{
    constant::TPM_MAX_COMMAND_SIZE,
    data::{TpmRc, TpmRcBase},
    TpmBuild, TpmErrorKind, TpmPersistent, TpmWriter,
};

/// Parses a hex string (with or without a "0x" prefix) into a u32.
///
/// # Errors
///
/// Returns a `ParseError` if the string is not a valid hex integer.
pub fn parse_hex_u32(s: &str) -> Result<u32> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).context("Failed to parse hex u32")
}

/// Parses a PCR index string (decimal or hex with "0x" prefix) into a u32.
///
/// # Errors
///
/// Returns a `ParseError` if the string is not a valid integer.
pub fn parse_pcr_index(s: &str) -> Result<u32> {
    if let Some(hex_val) = s.strip_prefix("0x") {
        u32::from_str_radix(hex_val, 16).context("Failed to parse hex pcr index")
    } else {
        s.parse::<u32>()
            .context("Failed to parse decimal pcr index")
    }
}

/// Parses a hex string into a `TpmPersistent` handle.
///
/// # Errors
///
/// Returns a `ParseError` if the string is not a valid hex integer.
pub fn parse_persistent_handle(s: &str) -> Result<TpmPersistent> {
    parse_hex_u32(s).map(TpmPersistent)
}

/// Parses a hex string into a `TpmRc` (TPM Return Code).
///
/// # Errors
///
/// Returns a `ParseError` if the string is not a valid hex integer
/// or the value is not a valid `TpmRc`.
pub fn parse_tpm_rc(s: &str) -> Result<TpmRc> {
    let raw_rc: u32 = parse_hex_u32(s)?;
    Ok(TpmRc::try_from(raw_rc).map_err(ProtocolError)?)
}

/// A helper to build a `TpmBuild` type into a `Vec<u8>`.
///
/// # Errors
///
/// Returns a `TpmErrorKind` if the object cannot be serialized into the buffer.
pub fn build_to_vec<T: TpmBuild>(obj: &T) -> Result<Vec<u8>, TpmErrorKind> {
    let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.build(&mut writer)?;
        writer.len()
    };
    Ok(buf[..len].to_vec())
}

/// Converts `TpmErrorKind` to `TpmRc`.
pub trait TpmErrorKindExt {
    fn to_tpm_rc(self) -> TpmRc;
}

impl TpmErrorKindExt for TpmErrorKind {
    fn to_tpm_rc(self) -> TpmRc {
        let base = match self {
            TpmErrorKind::Capacity(..)
            | TpmErrorKind::InvalidValue
            | TpmErrorKind::NotDiscriminant(..) => TpmRcBase::Value,
            TpmErrorKind::Underflow | TpmErrorKind::TrailingData => TpmRcBase::Size,
            TpmErrorKind::Unreachable => TpmRcBase::Failure,
        };
        TpmRc::from(base)
    }
}

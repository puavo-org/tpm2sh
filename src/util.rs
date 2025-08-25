// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli, CommandIo, ObjectData, TpmError};
use std::io::Write;
use tpm2_protocol::{data::TpmRc, TpmBuild, TpmPersistent, TpmWriter, TPM_MAX_COMMAND_SIZE};

pub(crate) fn parse_hex_u32(s: &str) -> Result<u32, TpmError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u32::from_str_radix(s, 16).map_err(TpmError::from)
}

pub(crate) fn parse_persistent_handle(s: &str) -> Result<TpmPersistent, TpmError> {
    parse_hex_u32(s).map(TpmPersistent)
}

pub(crate) fn parse_tpm_rc(s: &str) -> Result<TpmRc, TpmError> {
    let raw_rc: u32 = parse_hex_u32(s)?;
    Ok(TpmRc::try_from(raw_rc)?)
}

/// Pops an object from the stack and deserializes it into `ObjectData`.
///
/// # Errors
///
/// Returns a `TpmError` if the stack is empty, the object is not a context,
/// or the data cannot be parsed.
pub fn pop_object_data<W: Write>(io: &mut CommandIo<W>) -> Result<ObjectData, TpmError> {
    let obj = io.consume_object(|obj| matches!(obj, cli::Object::Key(_)))?;
    if let cli::Object::Key(data) = obj {
        Ok(data)
    } else {
        Err(TpmError::Execution(
            "Expected a Key object from the pipeline".to_string(),
        ))
    }
}

/// Resolves an input string with "data:" or "path:" prefixes into raw bytes.
///
/// # Errors
///
/// Returns a `TpmError` if the prefix is invalid or I/O fails.
pub fn input_to_bytes(s: &str) -> Result<Vec<u8>, TpmError> {
    if let Some(data_str) = s.strip_prefix("hex:") {
        hex::decode(data_str).map_err(TpmError::from)
    } else if let Some(path_str) = s.strip_prefix("file:") {
        std::fs::read(path_str).map_err(|e| TpmError::File(path_str.to_string(), e))
    } else if let Some(str_data) = s.strip_prefix("str:") {
        Ok(str_data.as_bytes().to_vec())
    } else {
        Err(TpmError::Usage(
            "Data input must be prefixed with 'str:', 'hex:', or 'file:'".to_string(),
        ))
    }
}

/// A helper to build a `TpmBuild` type into a `Vec<u8>`.
pub(crate) fn build_to_vec<T: TpmBuild>(obj: &T) -> Result<Vec<u8>, TpmError> {
    let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.build(&mut writer)?;
        writer.len()
    };
    Ok(buf[..len].to_vec())
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{error::ParseError, CliError};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::path::Path;

/// Resolves a URI string into bytes.
///
/// # Errors
///
/// Returns a `CliError` if the URI is malformed or a file cannot be read.
pub fn uri_to_bytes(uri_str: &str, _pipeline_objects: &[u8]) -> Result<Vec<u8>, CliError> {
    if let Some(path) = uri_str.strip_prefix("file://") {
        std::fs::read(Path::new(path)).map_err(|e| CliError::File(path.to_string(), e))
    } else if let Some(data) = uri_str.strip_prefix("data://") {
        let (encoding, value) = data
            .split_once(',')
            .ok_or_else(|| ParseError::Custom(format!("Invalid data URI format: '{uri_str}'")))?;
        match encoding {
            "utf8" => Ok(value.as_bytes().to_vec()),
            "hex" => Ok(hex::decode(value)?),
            "base64" => Ok(base64_engine.decode(value)?),
            _ => Err(
                ParseError::Custom(format!("Unsupported data URI encoding: '{encoding}'")).into(),
            ),
        }
    } else {
        Err(ParseError::Custom(format!("Unsupported or malformed URI scheme: '{uri_str}'")).into())
    }
}

/// Parses a TPM handle from a `tpm://` URI string.
///
/// # Errors
///
/// Returns a `CliError` if the URI is malformed or the handle is not a valid hex u32.
pub fn uri_to_tpm_handle(uri_str: &str) -> Result<u32, CliError> {
    if let Some(handle_str) = uri_str.strip_prefix("tpm://") {
        crate::util::parse_hex_u32(handle_str)
    } else {
        Err(ParseError::Custom("Expected a tpm:// URI to parse a handle".to_string()).into())
    }
}

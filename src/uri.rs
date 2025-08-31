// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{error::ParseError, pipeline::Entry as PipelineEntry, CliError};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::path::Path;

/// Resolves a URI string into bytes. `pipe://` URIs contain an index that point
/// to a `PipelineEntry` to be consumed.
///
/// # Errors
///
/// Returns a `CliError` if the URI is malformed, file cannot be read, or a
/// pipeline index is out of bounds.
pub fn uri_to_bytes(
    uri_str: &str,
    pipeline_objects: &[PipelineEntry],
) -> Result<Vec<u8>, CliError> {
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
    } else if let Some(data) = uri_str.strip_prefix("pipe://") {
        let index: isize = data.parse()?;
        let len = pipeline_objects.len();

        let actual_index = if index < 0 {
            let offset = usize::try_from(index.abs())
                .map_err(|_| ParseError::Custom("Invalid negative index".to_string()))?;
            len.checked_sub(offset)
        } else {
            usize::try_from(index).ok()
        };

        let Some(idx) = actual_index else {
            return Err(
                ParseError::Custom(format!("Pipeline index out of bounds: {index}")).into(),
            );
        };

        let obj = pipeline_objects
            .get(idx)
            .ok_or_else(|| ParseError::Custom(format!("Pipeline index out of bounds: {index}")))?;
        Ok(serde_json::to_string(obj)?.into_bytes())
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

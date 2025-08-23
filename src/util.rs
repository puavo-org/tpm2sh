// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli, CommandIo, ObjectData, TpmDevice, TpmError};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use json::JsonValue;
use log::warn;
use std::{fs, io::Write};
use tpm2_protocol::{
    self,
    data::{self, TpmRc},
    message::{TpmContextLoadCommand, TpmFlushContextCommand},
    TpmBuild, TpmParse, TpmPersistent, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

/// Executes an operation with a transient handle, and flushes the handle
/// afterwards.
///
/// # Errors
///
/// Returns the error from the primary operation (`op`). If `op` succeeds but
/// the subsequent flush fails, the flush error is returned instead.
pub fn with_transient_handle<F, R>(
    device: &mut TpmDevice,
    handle: TpmTransient,
    log_format: cli::LogFormat,
    op: F,
) -> Result<R, TpmError>
where
    F: FnOnce(&mut TpmDevice) -> Result<R, TpmError>,
{
    let op_result = op(device);
    let cmd = TpmFlushContextCommand {
        flush_handle: handle.into(),
    };
    let result = device.execute(&cmd, &[], log_format).err();
    if let Some(err) = result {
        warn!(
            target: "cli::util",
            "Operation succeeded, but failed to flush transient handle {handle:#010x}: {err}"
        );
        if op_result.is_ok() {
            return Err(err);
        }
    }
    op_result
}

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

/// Deserializes an `Envelope`-wrapped JSON object from a string.
///
/// # Errors
///
/// Returns a `TpmError::Json` if deserialization fails or if the object type
/// in the envelope does not match `expected_type`.
pub fn from_json_str(json_str: &str, expected_type: &str) -> Result<JsonValue, TpmError> {
    let parsed = json::parse(json_str)?;
    let obj_type = parsed["type"]
        .as_str()
        .ok_or_else(|| TpmError::Parse("'type' field is not a string".to_string()))?;
    if obj_type != expected_type {
        return Err(TpmError::Execution(format!(
            "invalid object type: expected '{expected_type}', got '{obj_type}'"
        )));
    }
    Ok(parsed["data"].clone())
}

/// Serializes a TPM data data and writes it to a file.
///
/// # Errors
///
/// Returns a `TpmError` if serialization fails or the file cannot be written.
pub fn write_to_file<T: TpmBuild>(path: &str, obj: &T) -> Result<(), TpmError> {
    let mut buffer = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buffer);
        obj.build(&mut writer)?;
        writer.len()
    };
    fs::write(path, &buffer[..len]).map_err(|e| TpmError::File(path.to_string(), e))
}

/// Reads from a file and deserializes it into a TPM data data.
///
/// # Errors
///
/// Returns a `TpmError` if the file cannot be read, or if the file content
/// cannot be parsed into the target type `T`, including if there is trailing data.
pub fn read_from_file<T>(path: &str) -> Result<T, TpmError>
where
    T: TpmParse,
{
    let bytes = fs::read(path).map_err(|e| TpmError::File(path.to_string(), e))?;
    let (obj, remainder) = T::parse(&bytes)?;
    if !remainder.is_empty() {
        return Err(TpmError::Parse(
            "file contained trailing data after the expected object".to_string(),
        ));
    }
    Ok(obj)
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
        unreachable!();
    }
}

/// Parses a parent handle from a hex string in the loaded object data.
///
/// # Errors
///
/// Returns a `TpmError::Parse` if the hex string is invalid.
pub fn parse_parent_handle_from_json(object_data: &ObjectData) -> Result<TpmTransient, TpmError> {
    u32::from_str_radix(object_data.parent.trim_start_matches("0x"), 16)
        .map_err(TpmError::from)
        .map(TpmTransient)
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
        fs::read(path_str).map_err(|e| TpmError::File(path_str.to_string(), e))
    } else if let Some(str_data) = s.strip_prefix("str:") {
        Ok(str_data.as_bytes().to_vec())
    } else {
        Err(TpmError::Usage(
            "Data input must be prefixed with 'str:', 'hex:', or 'file:'".to_string(),
        ))
    }
}

/// Resolves an input string with "data:" or "path:" prefixes into a UTF-8 string.
///
/// # Errors
///
/// Returns a `TpmError` if the prefix is invalid, I/O fails, or the data is not valid UTF-8.
pub fn input_to_utf8(s: &str) -> Result<String, TpmError> {
    if let Some(str_data) = s.strip_prefix("str:") {
        Ok(str_data.to_string())
    } else if let Some(hex_str) = s.strip_prefix("hex:") {
        let bytes = hex::decode(hex_str)?;
        String::from_utf8(bytes).map_err(|e| TpmError::Parse(e.to_string()))
    } else if let Some(path_str) = s.strip_prefix("file:") {
        fs::read_to_string(path_str).map_err(|e| TpmError::File(path_str.to_string(), e))
    } else {
        Err(TpmError::Usage(
            "Data input must be prefixed with 'str:', 'hex:', or 'file:'".to_string(),
        ))
    }
}

/// Resolves an object from the input stack into a transient handle.
///
/// If the object is a context file, it is loaded into the TPM and its handle is
/// returned along with a flag indicating it needs to be flushed.
///
/// # Errors
///
/// Returns a `TpmError` if the object is of an invalid type or cannot be loaded.
pub fn object_to_handle(
    chip: &mut TpmDevice,
    obj: &cli::Object,
    log_format: cli::LogFormat,
) -> Result<(TpmTransient, bool), TpmError> {
    match obj {
        cli::Object::Handle(handle) => Ok((TpmTransient(*handle), false)),
        cli::Object::Context(context_data) => {
            let context_blob = base64_engine.decode(context_data.context_blob.clone())?;
            let (context, remainder) = data::TpmsContext::parse(&context_blob)?;
            if !remainder.is_empty() {
                return Err(TpmError::Parse(
                    "Context object contains trailing data".to_string(),
                ));
            }
            let load_cmd = TpmContextLoadCommand { context };
            let (resp, _) = chip.execute(&load_cmd, &[], log_format)?;
            let load_resp = resp
                .ContextLoad()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            Ok((load_resp.loaded_handle, true))
        }
        _ => Err(TpmError::Parse(
            "pipeline object is not a valid handle or context".to_string(),
        )),
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

/// Helper to consume the parent object from the pipeline and return its handle.
///
/// It looks for a `Handle` or `Context` object in the input stream,
/// loads it if necessary, and returns the transient handle and a flag indicating
/// whether it needs to be flushed.
///
/// # Errors
///
/// Returns an error if a suitable parent object cannot be found or if there's an issue loading it.
pub fn consume_and_get_parent_handle<W: Write>(
    io: &mut CommandIo<W>,
    chip: &mut TpmDevice,
    log_format: cli::LogFormat,
) -> Result<(TpmTransient, bool), TpmError> {
    let parent_obj =
        io.consume_object(|obj| matches!(obj, cli::Object::Handle(_) | cli::Object::Context(_)))?;
    object_to_handle(chip, &parent_obj, log_format)
}

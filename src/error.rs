// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{io::Error as IoError, num::ParseIntError, str::Utf8Error};
use thiserror::Error;
use tpm2_protocol::{data::TpmRc, TpmErrorKind};

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("TPM protocol error: {0}")]
    Build(TpmErrorKind),

    #[error("Help message was requested.")]
    Help,

    #[error("Execution failed: {0}")]
    Execution(String),

    #[error("File operation on '{0}': {1}")]
    File(String, #[source] IoError),

    #[error("Invalid handle: {0}")]
    InvalidHandle(String),

    #[error("I/O error: {0}")]
    Io(#[from] IoError),

    #[error("JSON operation failed: {0}")]
    Json(#[from] json::Error),

    #[error("Argument parsing failed: {0}")]
    Lexopt(#[from] lexopt::Error),

    #[error("Parsing failed: {0}")]
    Parse(String),

    #[error("Invalid PCR selection: {0}")]
    PcrSelection(String),

    #[error("TPM returned an error: {0}")]
    TpmRc(TpmRc),

    #[error("Unexpected response type from TPM: {0}")]
    UnexpectedResponse(String),

    #[error("{0}")]
    Usage(String),

    #[error("Usage error already handled.")]
    UsageHandled,
}

impl TpmError {
    #[must_use]
    pub fn is_interactive(&self) -> bool {
        matches!(
            self,
            TpmError::Usage(_)
                | TpmError::UsageHandled
                | TpmError::Lexopt(_)
                | TpmError::Parse(_)
                | TpmError::PcrSelection(_)
                | TpmError::InvalidHandle(_)
                | TpmError::File(_, _)
        )
    }
}

impl From<base64::DecodeError> for TpmError {
    fn from(err: base64::DecodeError) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<hex::FromHexError> for TpmError {
    fn from(err: hex::FromHexError) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<ParseIntError> for TpmError {
    fn from(err: ParseIntError) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<pkcs8::der::Error> for TpmError {
    fn from(err: pkcs8::der::Error) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<pkcs8::Error> for TpmError {
    fn from(err: pkcs8::Error) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<pem::PemError> for TpmError {
    fn from(err: pem::PemError) -> Self {
        TpmError::Parse(err.to_string())
    }
}

impl From<TpmErrorKind> for TpmError {
    fn from(err: TpmErrorKind) -> Self {
        TpmError::Build(err)
    }
}

impl From<Utf8Error> for TpmError {
    fn from(err: Utf8Error) -> Self {
        TpmError::Parse(err.to_string())
    }
}

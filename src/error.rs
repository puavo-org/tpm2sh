// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{io::Error as IoError, num::ParseIntError, str::Utf8Error};
use thiserror::Error;
use tpm2_protocol::{data::TpmRc, TpmErrorKind};

#[derive(Debug, Error)]
pub enum TpmError {
    #[error("TPM protocol: {0}")]
    Build(TpmErrorKind),

    #[error("")]
    Help,

    #[error("Execution: {0}")]
    Execution(String),

    #[error("'{0}': {1}")]
    File(String, #[source] IoError),

    #[error("Handle: {0}")]
    InvalidHandle(String),

    #[error("I/O: {0}")]
    Io(#[from] IoError),

    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Lexopt: {0}")]
    Lexopt(#[from] lexopt::Error),

    #[error("Parser: {0}")]
    Parse(String),

    #[error("PCR: {0}")]
    PcrSelection(String),

    #[error("TPM RC: {0}")]
    TpmRc(TpmRc),

    #[error("TPM unexpected: {0}")]
    UnexpectedResponse(String),

    #[error("{0}")]
    Usage(String),

    #[error("")]
    UsageHandled,
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
        TpmError::Parse(format!("invalid PEM data: {err}"))
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

impl From<url::ParseError> for TpmError {
    fn from(err: url::ParseError) -> Self {
        TpmError::Parse(format!("Invalid URI: {err}"))
    }
}

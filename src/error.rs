// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{io::Error as IoError, num::ParseIntError, str::Utf8Error};
use thiserror::Error;
use tpm2_protocol::{data::TpmRc, TpmErrorKind};

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("{0}")]
    Custom(String),
    #[error("DER parsing failed: {0}")]
    Der(#[from] pkcs8::der::Error),
    #[error("hex decoding failed: {0}")]
    Hex(#[from] hex::FromHexError),
    #[error("integer parsing failed: {0}")]
    Int(#[from] ParseIntError),
    #[error("invalid PEM data: {0}")]
    Pem(#[from] pem::PemError),
    #[error("PKCS#8 parsing failed: {0}")]
    Pkcs8(#[from] pkcs8::Error),
    #[error("invalid URI: {0}")]
    Uri(#[from] url::ParseError),
    #[error("UTF-8 decoding failed: {0}")]
    Utf8(#[from] Utf8Error),
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("TPM protocol: {0}")]
    Build(TpmErrorKind),

    #[error("Execution: {0}")]
    Execution(String),

    #[error("'{0}': {1}")]
    File(String, #[source] IoError),

    #[error("Handle: {0}")]
    InvalidHandle(String),

    #[error("I/O: {0}")]
    Io(#[from] IoError),

    #[error("Parser: {0}")]
    Parse(#[from] ParseError),

    #[error("PCR: {0}")]
    PcrSelection(String),

    #[error("TPM RC: {0}")]
    TpmRc(TpmRc),

    #[error("TPM unexpected: {0}")]
    UnexpectedResponse(String),

    #[error("{0}")]
    Usage(String),
}

impl CliError {
    /// Checks if the error is related to user input or usage.
    #[must_use]
    pub fn is_usage_error(&self) -> bool {
        matches!(
            self,
            Self::Usage(_)
                | Self::Parse(_)
                | Self::PcrSelection(_)
                | Self::InvalidHandle(_)
                | Self::File(_, _)
        )
    }
}

impl From<base64::DecodeError> for CliError {
    fn from(err: base64::DecodeError) -> Self {
        ParseError::from(err).into()
    }
}

impl From<hex::FromHexError> for CliError {
    fn from(err: hex::FromHexError) -> Self {
        ParseError::from(err).into()
    }
}

impl From<ParseIntError> for CliError {
    fn from(err: ParseIntError) -> Self {
        ParseError::from(err).into()
    }
}

impl From<pkcs8::der::Error> for CliError {
    fn from(err: pkcs8::der::Error) -> Self {
        ParseError::from(err).into()
    }
}

impl From<pkcs8::Error> for CliError {
    fn from(err: pkcs8::Error) -> Self {
        ParseError::from(err).into()
    }
}

impl From<pem::PemError> for CliError {
    fn from(err: pem::PemError) -> Self {
        ParseError::from(err).into()
    }
}

impl From<TpmErrorKind> for CliError {
    fn from(err: TpmErrorKind) -> Self {
        CliError::Build(err)
    }
}

impl From<Utf8Error> for CliError {
    fn from(err: Utf8Error) -> Self {
        ParseError::from(err).into()
    }
}

impl From<url::ParseError> for CliError {
    fn from(err: url::ParseError) -> Self {
        ParseError::from(err).into()
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{command::CommandError, device::TpmDeviceError};
use std::io::Error as IoError;
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
    Int(#[from] std::num::ParseIntError),
    #[error("invalid PEM data: {0}")]
    Pem(#[from] pem::PemError),
    #[error("PKCS#8 parsing failed: {0}")]
    Pkcs8(#[from] pkcs8::Error),
    #[error("TPM protocol: {0}")]
    TpmProtocol(TpmErrorKind),
    #[error("UTF-8 decoding failed: {0}")]
    Utf8(#[from] std::str::Utf8Error),
}

impl From<TpmErrorKind> for ParseError {
    fn from(err: TpmErrorKind) -> Self {
        ParseError::TpmProtocol(err)
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Command error: {0}")]
    Command(#[from] CommandError),

    #[error("Device error: {0}")]
    Device(#[from] TpmDeviceError),

    #[error("'{0}': {1}")]
    File(String, #[source] IoError),

    #[error("I/O error: {0}")]
    Io(#[from] IoError),

    #[error("Parsing error: {0}")]
    Parse(#[from] ParseError),

    #[error("TPM returned an error code: {0}")]
    Tpm(TpmRc),
}

impl From<TpmRc> for CliError {
    fn from(rc: TpmRc) -> Self {
        Self::Tpm(rc)
    }
}

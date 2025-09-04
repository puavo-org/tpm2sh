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
    #[error("TPM protocol: {0}")]
    TpmProtocol(TpmErrorKind),
    #[error("UTF-8 decoding failed: {0}")]
    Utf8(#[from] Utf8Error),
}

impl From<TpmErrorKind> for ParseError {
    fn from(err: TpmErrorKind) -> Self {
        ParseError::TpmProtocol(err)
    }
}

#[derive(Debug, Error)]
pub enum CliError {
    #[error("{0}")]
    Build(TpmErrorKind),

    #[error("{0}")]
    Execution(String),

    #[error("'{0}': {1}")]
    File(String, #[source] IoError),

    #[error("{handle:#010x}")]
    InvalidHandleType { handle: u32 },

    #[error("The arguments '--{0}' and '--{1}' are mutually exclusive")]
    MutualExclusionArgs(&'static str, &'static str),

    #[error("{0}")]
    UnsupportedUriForDelete(String),

    #[error("I/O: {0}")]
    Io(#[from] IoError),

    #[error("Parser: {0}")]
    Parse(#[from] ParseError),

    #[error("PCR: {0}")]
    PcrSelection(String),

    #[error("{0}")]
    TpmRc(TpmRc),

    #[error("TPM device lock poisoned")]
    DeviceLockPoisoned,

    #[error("TPM device not provided for a device command")]
    DeviceNotProvided,

    #[error("unexpected TPM response: {0}")]
    Unexpected(String),
}

impl From<TpmErrorKind> for CliError {
    fn from(err: TpmErrorKind) -> Self {
        CliError::Build(err)
    }
}

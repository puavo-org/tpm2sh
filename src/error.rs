// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use std::{error::Error, fmt};
use tpm2_protocol::{data::TpmRc, TpmErrorKind};

/// A newtype wrapper for `TpmErrorKind` to implement `std::error::Error`.
#[derive(Debug)]
pub struct ProtocolError(pub TpmErrorKind);

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for ProtocolError {}

/// A newtype wrapper for `TpmRc` to implement `std::error::Error`.
#[derive(Debug)]
pub struct ReturnCode(pub TpmRc);

impl fmt::Display for ReturnCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for ReturnCode {}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::key::Tpm2shAlgId;
use thiserror::Error;
use tpm2_protocol::{TpmErrorKind, TpmTransient};

pub mod context;
pub mod convert;
#[path = "create-primary/mod.rs"]
pub mod create_primary;
pub mod delete;
pub mod list;
pub mod load;
#[path = "pcr-event/mod.rs"]
pub mod pcr_event;
pub mod policy;
#[path = "print-error/mod.rs"]
pub mod print_error;
#[path = "reset-lock/mod.rs"]
pub mod reset_lock;
pub mod seal;
#[path = "start-session/mod.rs"]
pub mod start_session;

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("help requested")]
    HelpRequested,

    #[error("Handle capacity ({capacity}) exceeded")]
    HandleCapacityExceeded { capacity: usize },

    #[error("Handle is not tracked: tpm://{handle:#010x}")]
    HandleNotTracked { handle: TpmTransient },

    #[error("Handle is already tracked: tpm://{handle:#010x}")]
    HandleAlreadyTracked { handle: TpmTransient },

    #[error("Input and output formats cannot be the same")]
    SameConversionFormat,

    #[error("Parent key is not a valid type: {reason}")]
    InvalidParentKeyType { reason: &'static str },

    #[error("Invalid algorithm: {alg}")]
    InvalidAlgorithm { alg: Tpm2shAlgId },

    #[error("Invalid algorithm name: '{0}'")]
    InvalidAlgorithmName(String),

    #[error("Invalid URI scheme: expected '{expected}', found '{actual}'")]
    InvalidUriScheme { expected: String, actual: String },

    #[error("Invalid handle type for this operation: {handle:#010x}")]
    InvalidHandleType { handle: u32 },

    #[error("The arguments '--{arg1}' and '--{arg2}' are mutually exclusive")]
    MutualExclusionArgs {
        arg1: &'static str,
        arg2: &'static str,
    },

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Invalid PCR selection: {0}")]
    InvalidPcrSelection(String),

    #[error("TPM protocol error")]
    Build(TpmErrorKind),

    #[error("{0}")]
    Custom(String),
}

impl From<TpmErrorKind> for CommandError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Build(err)
    }
}

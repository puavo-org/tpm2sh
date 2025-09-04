// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    error::{CliError, ParseError},
    parser::{parse_policy, PolicyExpr},
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::{fmt, ops::Deref, path::Path, str::FromStr};
use tpm2_protocol::{
    data::{TpmAlgId, TpmlPcrSelection, TpmsPcrSelection, TPM_PCR_SELECT_MAX},
    TpmBuffer,
};

/// Parses a PCR selection string (e.g., "sha256:0,7+sha1:1") into a TPM list.
pub(crate) fn pcr_selection_to_list(
    selection_str: &str,
    pcr_count: usize,
) -> Result<TpmlPcrSelection, CliError> {
    let mut list = TpmlPcrSelection::new();
    let pcr_select_size = pcr_count.div_ceil(8);
    if pcr_select_size > TPM_PCR_SELECT_MAX {
        return Err(CliError::PcrSelection(format!(
            "required pcr select size {pcr_select_size} exceeds maximum {TPM_PCR_SELECT_MAX}"
        )));
    }

    for bank_str in selection_str.split('+') {
        let (alg_str, indices_str) = bank_str
            .split_once(':')
            .ok_or_else(|| CliError::PcrSelection(format!("invalid bank format: '{bank_str}'")))?;
        let alg = PcrAlgId::from_str(alg_str)
            .map_err(|()| CliError::PcrSelection(format!("invalid algorithm: {alg_str}")))?
            .0;

        let mut pcr_select_bytes = vec![0u8; pcr_select_size];
        for index_str in indices_str.split(',') {
            let pcr_index: usize = index_str.parse().map_err(ParseError::from)?;

            if pcr_index >= pcr_count {
                return Err(CliError::PcrSelection(format!(
                    "pcr index {pcr_index} is out of range for a TPM with {pcr_count} PCRs"
                )));
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }
        list.try_push(TpmsPcrSelection {
            hash: alg,
            pcr_select: TpmBuffer::try_from(pcr_select_bytes.as_slice())?,
        })?;
    }
    Ok(list)
}

struct PcrAlgId(TpmAlgId);

impl FromStr for PcrAlgId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha1" => Ok(Self(TpmAlgId::Sha1)),
            "sha256" => Ok(Self(TpmAlgId::Sha256)),
            "sha384" => Ok(Self(TpmAlgId::Sha384)),
            "sha512" => Ok(Self(TpmAlgId::Sha512)),
            _ => Err(()),
        }
    }
}

/// URI data type used for the input data. The input is fully validated,
/// and only legit URIs get passed to the subcommands.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Uri(String, PolicyExpr);

impl Deref for Uri {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for Uri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for Uri {
    type Err = ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ast = parse_policy(s)?;
        Ok(Self(s.to_string(), ast))
    }
}

impl Uri {
    /// Returns the parsed AST of the URI
    #[must_use]
    pub fn ast(&self) -> &PolicyExpr {
        &self.1
    }

    /// Resolves a URI string into bytes.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the URI is malformed or a file cannot be read.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CliError> {
        match &self.1 {
            PolicyExpr::FilePath(path) => {
                std::fs::read(Path::new(path)).map_err(|e| CliError::File(path.clone(), e))
            }
            PolicyExpr::Data { encoding, value } => match encoding.as_str() {
                "utf8" => Ok(value.as_bytes().to_vec()),
                "hex" => Ok(hex::decode(value).map_err(ParseError::from)?),
                "base64" => Ok(base64_engine.decode(value).map_err(ParseError::from)?),
                _ => Err(ParseError::Custom(format!(
                    "Unsupported data URI encoding: '{encoding}'"
                ))
                .into()),
            },
            _ => Err(ParseError::Custom(format!("Not a data-like URI: '{}'", self.0)).into()),
        }
    }

    /// Parses a TPM handle from a `tpm://` URI string.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the URI is not a `tpm://` URI.
    pub fn to_tpm_handle(&self) -> Result<u32, CliError> {
        match self.1 {
            PolicyExpr::TpmHandle(handle) => Ok(handle),
            _ => Err(ParseError::Custom(format!("Not a TPM handle URI: '{}'", self.0)).into()),
        }
    }

    /// Parses a PCR selection from a `pcr://` URI string.
    ///
    /// # Errors
    ///
    /// Returns a `CliError::Parse` if the URI is not a `pcr://` URI.
    pub fn to_pcr_selection(&self, pcr_count: usize) -> Result<TpmlPcrSelection, CliError> {
        match &self.1 {
            PolicyExpr::Pcr { selection, .. } => pcr_selection_to_list(selection, pcr_count),
            _ => Err(ParseError::Custom(format!("Not a PCR URI: '{}'", self.0)).into()),
        }
    }
}

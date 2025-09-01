// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{error::ParseError, util, CliError};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use pest::Parser;
use pest_derive::Parser;
use std::{fmt, ops::Deref, path::Path, str::FromStr};
use tpm2_protocol::{
    data::{TpmAlgId, TpmlPcrSelection, TpmsPcrSelection, TPM_PCR_SELECT_MAX},
    TpmBuffer,
};

#[derive(Parser)]
#[grammar = "uri.pest"]
pub struct UriParser;

/// Parses a PCR selection string (e.g., "sha256:0,7+sha1:1") into a TPM list.
pub(crate) fn pcr_parse_selection(
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

    let pairs = UriParser::parse(Rule::selection_body, selection_str)
        .map_err(|e| CliError::PcrSelection(e.to_string()))?;

    for pair in pairs.flatten().filter(|p| p.as_rule() == Rule::bank) {
        let mut inner_pairs = pair.into_inner();

        let alg_str = inner_pairs.next().unwrap().as_str();
        let alg = PcrAlgId::from_str(alg_str)
            .map_err(|()| CliError::PcrSelection(format!("invalid algorithm: {alg_str}")))?
            .0;

        let colon_and_list_pair = inner_pairs.next().unwrap();
        let pcr_list_pair = colon_and_list_pair.into_inner().next().unwrap();
        let mut pcr_select_bytes = vec![0u8; pcr_select_size];

        for pcr_index_pair in pcr_list_pair.into_inner() {
            let pcr_index: usize = pcr_index_pair.as_str().parse()?;

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
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Uri(String);

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
        UriParser::parse(Rule::uri, s)
            .map(|_| Self(s.to_string()))
            .map_err(|e| ParseError::Custom(e.to_string()))
    }
}

impl Uri {
    /// Resolves a URI string into bytes.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the URI is malformed or a file cannot be read.
    pub fn to_bytes(&self) -> Result<Vec<u8>, CliError> {
        if let Some(path) = self.strip_prefix("file://") {
            std::fs::read(Path::new(path)).map_err(|e| CliError::File(path.to_string(), e))
        } else if let Some(data) = self.strip_prefix("data://") {
            let (encoding, value) = data
                .split_once(',')
                .ok_or_else(|| ParseError::Custom(format!("Corrupted URI: '{self}'")))?;
            match encoding {
                "utf8" => Ok(value.as_bytes().to_vec()),
                "hex" => Ok(hex::decode(value)?),
                "base64" => Ok(base64_engine.decode(value)?),
                _ => Err(ParseError::Custom(format!(
                    "Unsupported data URI encoding: '{encoding}'"
                ))
                .into()),
            }
        } else {
            Err(ParseError::Custom(format!("Corrupted URI: '{self}'")).into())
        }
    }

    /// Parses a TPM handle from a `tpm://` URI string.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the URI is malformed or the handle is not a valid hex u32.
    pub fn to_tpm_handle(&self) -> Result<u32, CliError> {
        if let Some(handle_str) = self.strip_prefix("tpm://") {
            util::parse_hex_u32(handle_str)
        } else {
            Err(ParseError::Custom(format!("Not TPM URI: '{self}'")).into())
        }
    }

    /// Parses a PCR selection from a `pcr://` URI string.
    ///
    /// # Errors
    ///
    /// Returns a `CliError::Parse` if the URI is malformed.
    pub fn to_pcr_selection(&self, pcr_count: usize) -> Result<TpmlPcrSelection, CliError> {
        if let Some(selection_str) = self.strip_prefix("pcr://") {
            pcr_parse_selection(selection_str, pcr_count)
        } else {
            Err(ParseError::Custom(format!("Not a PCR URI: '{self}'")).into())
        }
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{error::ParseError, util, CliError};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use pest::Parser;
use pest_derive::Parser;
use std::{fmt, ops::Deref, path::Path, str::FromStr};

#[derive(Parser)]
#[grammar = "uri.pest"]
struct UriParser;

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

    /// Parses a PCR URI string (e.g., `pcr://sha256,7`) into a bank name and index.
    ///
    /// # Errors
    ///
    /// Returns a `CliError::Parse` if the URI is malformed.
    pub fn to_pcr_spec(&self) -> Result<(String, u32), CliError> {
        let Some(path) = self.strip_prefix("pcr://") else {
            return Err(ParseError::Custom(format!("Not PCR URI: '{self}'")).into());
        };

        let Some((bank, index_str)) = path.split_once(',') else {
            return Err(ParseError::Custom(format!("Corrupted URI: '{self}'")).into());
        };

        let index = util::parse_pcr_index(index_str)?;
        Ok((bank.to_string(), index))
    }
}

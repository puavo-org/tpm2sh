// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{Cli, Convert, KeyFormat, LocalCommand},
    key::{JsonTpmKey, TpmKey},
    uri::{uri_to_bytes, uri_to_tpm_handle},
    util, CliError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use pkcs8::der::asn1::OctetString;
use std::io::Write;
use tpm2_protocol::{data, TpmParse};

impl LocalCommand for Convert {
    /// Runs `convert`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(&self, cli: &Cli, writer: &mut W) -> Result<(), CliError> {
        let input_bytes = uri_to_bytes(&self.input_uri, &[])?;

        let tpm_key = match self.from {
            KeyFormat::Json => {
                let key_obj: JsonTpmKey = serde_json::from_slice(&input_bytes)?;
                let public_bytes = uri_to_bytes(&key_obj.public, &[])?;
                let private_bytes = uri_to_bytes(&key_obj.private, &[])?;

                let (public, _) = data::Tpm2bPublic::parse(&public_bytes)?;
                let oid = crate::crypto::ID_LOADABLE_KEY;

                let parent_handle = if let Some(uri) = &cli.parent {
                    uri_to_tpm_handle(uri)?
                } else {
                    return Err(CliError::Usage(
                        "Missing required --parent argument for JSON conversion".to_string(),
                    ));
                };

                TpmKey {
                    oid,
                    parent: parent_handle,
                    pub_key: OctetString::new(util::build_to_vec(&public)?)?,
                    priv_key: OctetString::new(private_bytes)?,
                }
            }
            KeyFormat::Pem => TpmKey::from_pem(&input_bytes)?,
            KeyFormat::Der => TpmKey::from_der(&input_bytes)?,
        };

        match self.to {
            KeyFormat::Json => {
                let key_obj = JsonTpmKey {
                    public: format!("data://base64,{}", base64_engine.encode(&tpm_key.pub_key)),
                    private: format!("data://base64,{}", base64_engine.encode(&tpm_key.priv_key)),
                };
                let json_string = serde_json::to_string_pretty(&key_obj)?;
                writeln!(writer, "{json_string}")?;
            }
            KeyFormat::Pem => {
                let pem_string = tpm_key.to_pem()?;
                write!(writer, "{pem_string}")?;
            }
            KeyFormat::Der => {
                let der_bytes = tpm_key.to_der()?;
                writer.write_all(&der_bytes)?;
            }
        }

        Ok(())
    }
}

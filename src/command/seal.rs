// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, Seal},
    key::JsonTpmKey,
    session::session_from_args,
    uri::uri_to_bytes,
    util::build_to_vec,
    CliError, TpmDevice,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::io::Write;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmaObject, TpmlPcrSelection, TpmsKeyedhashParms, TpmsSensitiveCreate,
        TpmtPublic, TpmtScheme, TpmuPublicId, TpmuPublicParms,
    },
    message::TpmCreateCommand,
    TpmTransient,
};

impl DeviceCommand for Seal {
    /// Runs `seal`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: &mut TpmDevice,
        writer: &mut W,
    ) -> Result<Vec<TpmTransient>, CliError> {
        let parent_uri = cli
            .parent
            .as_ref()
            .ok_or_else(|| CliError::Usage("Missing required --parent argument".to_string()))?;
        let (parent_handle, needs_flush) = device.load_context(parent_uri)?;
        let mut handles_to_flush = Vec::new();
        if needs_flush {
            handles_to_flush.push(parent_handle);
        }

        let data_to_seal = uri_to_bytes(&self.data_uri, &[])?;

        let mut object_attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;
        if self.object_password.is_some() {
            object_attributes |= TpmaObject::USER_WITH_AUTH;
        }
        let public_template = TpmtPublic {
            object_type: TpmAlgId::KeyedHash,
            name_alg: TpmAlgId::Sha256,
            object_attributes,
            auth_policy: Tpm2bDigest::default(),
            parameters: TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                scheme: TpmtScheme {
                    scheme: TpmAlgId::Null,
                },
            }),
            unique: TpmuPublicId::KeyedHash(tpm2_protocol::TpmBuffer::default()),
        };

        let sealed_obj_password = self.object_password.as_deref().unwrap_or("").as_bytes();
        let cmd = TpmCreateCommand {
            parent_handle: parent_handle.0.into(),
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth: Tpm2bAuth::try_from(sealed_obj_password)?,
                    data: Tpm2bSensitiveData::try_from(data_to_seal.as_slice())?,
                },
            },
            in_public: Tpm2bPublic {
                inner: public_template,
            },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let handles = [parent_handle.into()];
        let sessions = session_from_args(&cmd, &handles, cli)?;
        let (resp, _) = device.execute(&cmd, &sessions)?;

        let create_resp = resp.Create().map_err(|e| {
            CliError::Execution(format!("unexpected response type for Create: {e:?}"))
        })?;

        let pub_bytes = build_to_vec(&create_resp.out_public)?;
        let priv_bytes = build_to_vec(&create_resp.out_private)?;

        let key = JsonTpmKey {
            public: format!("data://base64,{}", base64_engine.encode(pub_bytes)),
            private: format!("data://base64,{}", base64_engine.encode(priv_bytes)),
        };

        let json_string = serde_json::to_string_pretty(&key)?;
        writeln!(writer, "{json_string}")?;

        Ok(handles_to_flush)
    }
}

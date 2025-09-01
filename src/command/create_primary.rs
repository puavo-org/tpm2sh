// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{Cli, CreatePrimary, DeviceCommand},
    error::CliError,
    key::{Alg, AlgInfo},
    session::session_from_args,
    TpmDevice,
};
use std::io::Write;

use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmRh, TpmaObject, TpmlPcrSelection, TpmsEccParms, TpmsEccPoint,
        TpmsKeyedhashParms, TpmsRsaParms, TpmsSensitiveCreate, TpmtKdfScheme, TpmtPublic,
        TpmtScheme, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{TpmCreatePrimaryCommand, TpmEvictControlCommand},
    TpmPersistent, TpmTransient,
};

fn build_public_template(alg_desc: &Alg) -> TpmtPublic {
    let mut object_attributes = TpmaObject::USER_WITH_AUTH
        | TpmaObject::FIXED_TPM
        | TpmaObject::FIXED_PARENT
        | TpmaObject::SENSITIVE_DATA_ORIGIN;
    let (parameters, unique) = match alg_desc.params {
        AlgInfo::Rsa { key_bits } => {
            object_attributes |= TpmaObject::DECRYPT | TpmaObject::RESTRICTED;
            (
                TpmuPublicParms::Rsa(TpmsRsaParms {
                    symmetric: TpmtSymDefObject {
                        algorithm: TpmAlgId::Aes,
                        key_bits: TpmuSymKeyBits::Aes(128),
                        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
                    },
                    scheme: TpmtScheme::default(),
                    key_bits,
                    exponent: 0,
                }),
                TpmuPublicId::Rsa(tpm2_protocol::TpmBuffer::default()),
            )
        }
        AlgInfo::Ecc { curve_id } => {
            object_attributes |= TpmaObject::DECRYPT | TpmaObject::RESTRICTED;
            (
                TpmuPublicParms::Ecc(TpmsEccParms {
                    symmetric: TpmtSymDefObject {
                        algorithm: TpmAlgId::Aes,
                        key_bits: TpmuSymKeyBits::Aes(128),
                        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
                    },
                    scheme: TpmtScheme::default(),
                    curve_id,
                    kdf: TpmtKdfScheme::default(),
                }),
                TpmuPublicId::Ecc(TpmsEccPoint::default()),
            )
        }
        AlgInfo::KeyedHash => (
            TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                scheme: TpmtScheme {
                    scheme: TpmAlgId::Null,
                },
            }),
            TpmuPublicId::KeyedHash(tpm2_protocol::TpmBuffer::default()),
        ),
    };
    TpmtPublic {
        object_type: alg_desc.object_type,
        name_alg: alg_desc.name_alg,
        object_attributes,
        auth_policy: Tpm2bDigest::default(),
        parameters,
        unique,
    }
}

impl DeviceCommand for CreatePrimary {
    /// Runs `create-primary`.
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
        let primary_handle: TpmRh = self.hierarchy.into();
        let handles = [primary_handle as u32];
        let public_template = build_public_template(&self.algorithm);
        let cmd = TpmCreatePrimaryCommand {
            primary_handle: (primary_handle as u32).into(),
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth: Tpm2bAuth::default(),
                    data: Tpm2bSensitiveData::default(),
                },
            },
            in_public: Tpm2bPublic {
                inner: public_template,
            },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let sessions = session_from_args(&cmd, &handles, cli)?;
        let (resp, _) = device.execute(&cmd, &sessions)?;
        let create_primary_resp = resp
            .CreatePrimary()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let object_handle = create_primary_resp.object_handle;

        if let Some(uri) = &self.handle {
            let persistent_handle = TpmPersistent(uri.to_tpm_handle()?);
            let evict_cmd = TpmEvictControlCommand {
                auth: (TpmRh::Owner as u32).into(),
                object_handle: object_handle.0.into(),
                persistent_handle,
            };
            let evict_handles = [TpmRh::Owner as u32, object_handle.into()];
            let evict_sessions = session_from_args(&evict_cmd, &evict_handles, cli)?;
            let (resp, _) = device.execute(&evict_cmd, &evict_sessions)?;
            resp.EvictControl()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

            writeln!(writer, "tpm://{persistent_handle:#010x}")?;
            Ok(Vec::new())
        } else {
            device.context_save(object_handle, writer)?;
            Ok(vec![object_handle])
        }
    }
}

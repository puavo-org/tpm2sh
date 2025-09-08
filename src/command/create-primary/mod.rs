// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{DeviceCommand, Hierarchy},
    command::context::Context,
    device::{TpmDevice, TpmDeviceError},
    error::CliError,
    key::{Alg, AlgInfo},
    policy::{session_from_uri, Uri},
};
use argh::FromArgs;
use tpm2_protocol::{
    self,
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmCc, TpmRh, TpmaObject, TpmlPcrSelection, TpmsEccParms, TpmsEccPoint,
        TpmsKeyedhashParms, TpmsRsaParms, TpmsSensitiveCreate, TpmtKdfScheme, TpmtPublic,
        TpmtScheme, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    },
    message::TpmCreatePrimaryCommand,
};

/// Creates a primary key.
///
/// Creates a primary key from a chosen hierarchy and algorithm. The command creates
/// and loads the object, then returns its saved context. The output can be an
/// output file URI for the saved context. If omitted, the saved context is printed
/// to standard output as a 'data://' URI.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "create-primary")]
pub struct CreatePrimary {
    /// hierarchy to create the key in (owner, platform, or endorsement)
    #[argh(option, short = 'H', default = "Default::default()")]
    pub hierarchy: Hierarchy,

    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,

    /// output destination: 'tpm://' or 'file://'
    #[argh(option)]
    pub output: Option<Uri>,

    /// algorithm descriptor string
    #[argh(positional)]
    pub algorithm: Alg,
}

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
        AlgInfo::KeyedHash => {
            object_attributes |= TpmaObject::SIGN_ENCRYPT;
            (
                TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                    scheme: TpmtScheme {
                        scheme: TpmAlgId::Null,
                    },
                }),
                TpmuPublicId::KeyedHash(tpm2_protocol::TpmBuffer::default()),
            )
        }
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
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
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
        let sessions = session_from_uri(&cmd, &handles, self.session.as_ref())?;
        let (resp, _) = device.execute(&cmd, &sessions)?;
        let resp = resp
            .CreatePrimary()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::CreatePrimary,
            })?;
        let object_handle = resp.object_handle;

        context.track(object_handle)?;
        context.finalize_object_output(
            device,
            object_handle,
            self.output.as_ref(),
            self.session.as_ref(),
        )
    }
}

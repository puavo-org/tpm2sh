// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{handle_help, required, DeviceCommand, Hierarchy, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    key::{Alg, AlgInfo},
    session::session_from_args,
    uri::Uri,
};
use lexopt::{Arg, Parser, ValueExt};

use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmRh, TpmaObject, TpmlPcrSelection, TpmsEccParms, TpmsEccPoint,
        TpmsKeyedhashParms, TpmsRsaParms, TpmsSensitiveCreate, TpmtKdfScheme, TpmtPublic,
        TpmtScheme, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    },
    message::TpmCreatePrimaryCommand,
    TpmPersistent,
};

#[derive(Debug, Default)]
pub struct CreatePrimary {
    pub hierarchy: Hierarchy,
    pub algorithm: Alg,
    pub handle: Option<Uri>,
}

impl Subcommand for CreatePrimary {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut hierarchy = Hierarchy::default();
        let mut algorithm = None;
        let mut handle = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("hierarchy") | Arg::Short('H') => hierarchy = parser.value()?.parse()?,
                Arg::Long("algorithm") => algorithm = Some(parser.value()?.parse()?),
                Arg::Long("handle") => handle = Some(parser.value()?.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(CreatePrimary {
            hierarchy,
            algorithm: required(algorithm, "--algorithm")?,
            handle,
        })
    }
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
        let sessions = session_from_args(&cmd, &handles, context.cli)?;
        let (resp, _) = device.execute(&cmd, &sessions)?;
        let resp = resp
            .CreatePrimary()
            .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
        let object_handle = resp.object_handle;
        if let Some(uri) = &self.handle {
            let persistent_handle = TpmPersistent(uri.to_tpm_handle()?);
            context.evict(device, object_handle, persistent_handle)?;
            writeln!(context.writer, "tpm://{persistent_handle:#010x}")?;
            Ok(())
        } else {
            context.track(device, object_handle)?;
            context.save(device, object_handle)
        }
    }
}

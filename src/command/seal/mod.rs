// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::{context::Context, CommandError},
    device::{TpmDevice, TpmDeviceError},
    error::{CliError, ParseError},
    session::session_from_args,
    uri::Uri,
    util::build_to_vec,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::{Arg, Parser, ValueExt};

use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmCc, TpmaObject, TpmlPcrSelection, TpmsKeyedhashParms, TpmsSensitiveCreate,
        TpmtPublic, TpmtScheme, TpmuPublicId, TpmuPublicParms,
    },
    message::TpmCreateCommand,
};

#[derive(Debug, Default)]
pub struct Seal {
    pub parent: Uri,
    pub data: Uri,
    pub object_password: Option<String>,
    pub policy: Option<String>,
}

impl Subcommand for Seal {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut parent = None;
        let mut data = None;
        let mut object_password = None;
        let mut policy = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("parent") | Arg::Short('P') => parent = Some(parser.value()?.parse()?),
                Arg::Long("data") => data = Some(parser.value()?.parse()?),
                Arg::Long("object-password") => object_password = Some(parser.value()?.string()?),
                Arg::Long("policy") => policy = Some(parser.value()?.string()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Seal {
            parent: required(parent, "--parent")?,
            data: required(data, "--data")?,
            object_password,
            policy,
        })
    }
}

impl DeviceCommand for Seal {
    /// Runs `seal`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let parent_handle = context.load(device, &self.parent)?;
        let data_to_seal = self.data.to_bytes()?;
        let mut object_attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;
        if self.object_password.is_some() {
            object_attributes |= TpmaObject::USER_WITH_AUTH;
        }
        let auth_policy = if let Some(policy_hex) = &self.policy {
            object_attributes |= TpmaObject::USER_WITH_AUTH;
            let digest_bytes = hex::decode(policy_hex).map_err(ParseError::from)?;
            Tpm2bDigest::try_from(digest_bytes.as_slice()).map_err(CommandError::from)?
        } else {
            Tpm2bDigest::default()
        };
        let public_template = TpmtPublic {
            object_type: TpmAlgId::KeyedHash,
            name_alg: TpmAlgId::Sha256,
            object_attributes,
            auth_policy,
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
                    user_auth: Tpm2bAuth::try_from(sealed_obj_password)
                        .map_err(CommandError::from)?,
                    data: Tpm2bSensitiveData::try_from(data_to_seal.as_slice())
                        .map_err(CommandError::from)?,
                },
            },
            in_public: Tpm2bPublic {
                inner: public_template,
            },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let handles = [parent_handle.into()];
        let sessions = session_from_args(&cmd, &handles, context.cli)?;
        let (_rc, resp, _) = device.execute(&cmd, &sessions)?;

        let create_resp = resp
            .Create()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::Create,
            })?;
        let pub_bytes = build_to_vec(&create_resp.out_public)?;
        let priv_bytes = build_to_vec(&create_resp.out_private)?;
        writeln!(
            context.writer,
            "data://base64,{}",
            base64_engine.encode(pub_bytes)
        )?;
        writeln!(
            context.writer,
            "data://base64,{}",
            base64_engine.encode(priv_bytes)
        )?;
        Ok(())
    }
}

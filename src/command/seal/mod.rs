// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, parse_session_option, required, DeviceCommand, Subcommand},
    command::{context::Context, CommandError},
    crypto,
    device::{TpmDevice, TpmDeviceError},
    error::{CliError, ParseError},
    key::TpmKey,
    policy::Expression,
    session::session_from_uri,
    uri::Uri,
    util::build_to_vec,
};
use lexopt::{Arg, Parser, ValueExt};
use pkcs8::der::asn1::OctetString;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmCc, TpmaObject, TpmlPcrSelection, TpmsKeyedhashParms, TpmsSensitiveCreate,
        TpmtPublic, TpmtScheme, TpmuPublicId, TpmuPublicParms,
    },
    message::TpmCreateCommand,
};

#[derive(Debug, Default, Clone)]
pub struct Seal {
    pub parent: Uri,
    pub data: Uri,
    pub password: Option<String>,
    pub policy: Option<String>,
    pub output: Option<Uri>,
    pub session: Option<Uri>,
}

impl Subcommand for Seal {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");
    const OPTION_SESSION: bool = true;

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut parent = None;
        let mut data = None;
        let mut password = None;
        let mut policy = None;
        let mut output = None;
        let mut session = None;
        let mut positional_args = Vec::new();

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("password") => password = Some(parser.value()?.string()?),
                Arg::Long("policy") => policy = Some(parser.value()?.string()?),
                Arg::Long("output") => output = Some(parser.value()?.parse()?),
                Arg::Long("session") => parse_session_option(parser, &mut session)?,
                Arg::Value(val) => positional_args.push(val.parse()?),
                _ => return handle_help(arg),
            }
        }

        if positional_args.len() == 2 {
            let mut iter = positional_args.into_iter();
            parent = iter.next();
            data = iter.next();
        }

        Ok(Seal {
            parent: required(parent, "<PARENT>")?,
            data: required(data, "<DATA>")?,
            password,
            policy,
            output,
            session,
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
        if self.password.is_some() {
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
        let sealed_obj_password = self.password.as_deref().unwrap_or("").as_bytes();
        let create_cmd = TpmCreateCommand {
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
        let sessions = session_from_uri(&create_cmd, &handles, self.session.as_ref())?;
        let (_rc, resp, _) = device.execute(&create_cmd, &sessions)?;

        let create_resp = resp
            .Create()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::Create,
            })?;

        let tpm_key = TpmKey {
            oid: crypto::ID_SEALED_DATA,
            parent: parent_handle.0,
            pub_key: OctetString::new(build_to_vec(&create_resp.out_public)?)
                .map_err(|e| ParseError::Custom(format!("DER encode error: {e}")))?,
            priv_key: OctetString::new(build_to_vec(&create_resp.out_private)?)
                .map_err(|e| ParseError::Custom(format!("DER encode error: {e}")))?,
        };

        let pem_output = tpm_key.to_pem()?;
        if let Some(uri) = &self.output {
            if let Expression::FilePath(path) = uri.ast() {
                std::fs::write(path, pem_output.as_bytes())
                    .map_err(|e| CliError::File(path.clone(), e))?;
            } else {
                return Err(CliError::Command(CommandError::InvalidUriScheme {
                    expected: "file://".to_string(),
                    actual: uri.to_string(),
                }));
            }
        } else {
            writeln!(context.writer, "{pem_output}")?;
        }

        Ok(())
    }
}

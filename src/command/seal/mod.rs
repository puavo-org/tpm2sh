// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::DeviceCommand,
    command::{context::Context, CommandError},
    crypto,
    device::{TpmDevice, TpmDeviceError},
    error::{CliError, ParseError},
    key::TpmKey,
    policy::session_from_uri,
    policy::Uri,
    util::build_to_vec,
};
use argh::FromArgs;
use pkcs8::der::asn1::OctetString;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmCc, TpmaObject, TpmlPcrSelection, TpmsKeyedhashParms, TpmsSensitiveCreate,
        TpmtPublic, TpmtScheme, TpmuPublicId, TpmuPublicParms,
    },
    message::TpmCreateCommand,
};

/// Seals a keyedhash object. The object is returned in the ASN.1 format.
#[derive(FromArgs, Debug, Clone, Default)]
#[argh(subcommand, name = "seal")]
pub struct Seal {
    /// password for the new sealed object
    #[argh(option)]
    pub password: Option<String>,

    /// authorization policy digest
    #[argh(option)]
    pub policy: Option<String>,

    /// output destination ('file://')
    #[argh(option)]
    pub output: Option<Uri>,

    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,

    /// parent object URI ('tpm://', 'file://', or 'data://')
    #[argh(positional)]
    pub parent: Uri,

    /// data URI to seal ('file://' or 'data://')
    #[argh(positional)]
    pub data: Uri,
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
        let (resp, _) = device.execute(&create_cmd, &sessions)?;

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
        context.handle_data_output(self.output.as_ref(), pem_output.as_bytes())
    }
}

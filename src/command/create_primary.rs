// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineOption},
    cli::{Commands, CreatePrimary},
    get_auth_sessions, parse_tpm_handle_from_uri,
    pipeline::{CommandIo, Entry as PipelineEntry, ScopedHandle, Tpm as PipelineTpm},
    util, Alg, AlgInfo, CliError, Command, CommandType, TpmDevice,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmRh, TpmaObject, TpmlPcrSelection, TpmsEccParms, TpmsEccPoint,
        TpmsKeyedhashParms, TpmsRsaParms, TpmsSensitiveCreate, TpmtKdfScheme, TpmtPublic,
        TpmtScheme, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{TpmContextSaveCommand, TpmCreatePrimaryCommand, TpmEvictControlCommand},
    TpmPersistent,
};

const ABOUT: &str = "Creates a primary key";
const USAGE: &str = "tpm2sh create-primary [OPTIONS] --algorithm <ALGORITHM>";
const OPTIONS: &[CommandLineOption] = &[
    (
        Some("-H"),
        "--hierarchy",
        "<HIERARCHY>",
        "[default: owner, possible: owner, platform, endorsement]",
    ),
    (
        None,
        "--algorithm",
        "<ALGORITHM>",
        "Public key algorithm. Run 'algorithms' for options",
    ),
    (
        None,
        "--handle",
        "<HANDLE_URI>",
        "Store object to non-volatile memory (e.g., 'tpm://0x81000001')",
    ),
    (
        None,
        "--password",
        "<PASSWORD>",
        "Authorization value for the hierarchy",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

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

impl Command for CreatePrimary {
    fn command_type(&self) -> CommandType {
        CommandType::Source
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("create-primary", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = CreatePrimary::default();
        let mut alg_set = false;
        arguments!(parser, arg, Self::help, {
            Short('H') | Long("hierarchy") => {
                args.hierarchy = parser.value()?.string()?.parse()?;
            }
            Long("algorithm") => {
                args.algorithm = parser.value()?.string()?.parse()?;
                alg_set = true;
            }
            Long("handle") => {
                args.handle_uri = Some(parser.value()?.string()?);
            }
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });

        if !alg_set {
            return Err(CliError::Usage(
                "Missing required argument: --algorithm <ALGORITHM>".to_string(),
            ));
        }
        Ok(Commands::CreatePrimary(args))
    }

    /// Runs `create-primary`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        io.clear_input()?;
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let primary_handle: TpmRh = self.hierarchy.into();
        let handles = [primary_handle as u32];
        let public_template = build_public_template(&self.algorithm);
        let user_password = self.password.password.as_deref().unwrap_or("").as_bytes();
        let cmd = TpmCreatePrimaryCommand {
            primary_handle: (primary_handle as u32).into(),
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth: Tpm2bAuth::try_from(user_password)?,
                    data: Tpm2bSensitiveData::default(),
                },
            },
            in_public: Tpm2bPublic {
                inner: public_template,
            },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let sessions = get_auth_sessions(&cmd, &handles, None, self.password.password.as_deref())?;
        let (resp, _) = chip.execute(&cmd, &sessions)?;

        let create_primary_resp = resp
            .CreatePrimary()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let object_handle = create_primary_resp.object_handle;

        let final_object = if let Some(uri) = &self.handle_uri {
            let object_handle_guard = ScopedHandle::new(object_handle, device_arc.clone());
            let persistent_handle = TpmPersistent(parse_tpm_handle_from_uri(uri)?);
            let evict_cmd = TpmEvictControlCommand {
                auth: (TpmRh::Owner as u32).into(),
                object_handle: object_handle_guard.handle().0.into(),
                persistent_handle,
            };
            let evict_handles = [TpmRh::Owner as u32, object_handle_guard.handle().into()];
            let evict_sessions = get_auth_sessions(&evict_cmd, &evict_handles, None, None)?;
            let (resp, _) = chip.execute(&evict_cmd, &evict_sessions)?;
            resp.EvictControl()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

            std::mem::forget(object_handle_guard);

            PipelineTpm {
                context: format!("tpm://{persistent_handle:#010x}"),
                parent: None,
            }
        } else {
            let _ = ScopedHandle::new(object_handle, device_arc.clone());
            let save_command = TpmContextSaveCommand {
                save_handle: object_handle,
            };
            let (resp, _) = chip.execute(&save_command, &[])?;
            let save_resp = resp
                .ContextSave()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            let context_bytes = util::build_to_vec(&save_resp.context)?;

            PipelineTpm {
                context: format!("data://base64,{}", base64_engine.encode(context_bytes)),
                parent: None,
            }
        };

        io.push_object(PipelineEntry::Tpm(final_object));
        Ok(())
    }
}

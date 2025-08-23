// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{self, Commands, CreatePrimary, Object},
    get_auth_sessions, parse_args, parse_persistent_handle,
    util::{build_to_vec, with_transient_handle},
    Alg, AlgInfo, Command, CommandIo, CommandType, ContextData, TpmDevice, TpmError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmRh, TpmaObject, TpmlPcrSelection, TpmsEccParms, TpmsEccPoint,
        TpmsKeyedhashParms, TpmsRsaParms, TpmsSensitiveCreate, TpmtKdfScheme, TpmtPublic,
        TpmtScheme, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{TpmContextSaveCommand, TpmCreatePrimaryCommand, TpmEvictControlCommand},
    TpmBuffer, TpmTransient,
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
        "<HANDLE>",
        "Store object to non-volatile memory",
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
                TpmuPublicId::Rsa(TpmBuffer::default()),
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
            TpmuPublicId::KeyedHash(TpmBuffer::default()),
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

/// Saves a transient key's context.
///
/// # Errors
///
/// Returns a `TpmError` if the context cannot be saved.
pub fn save_key_context(
    chip: &mut TpmDevice,
    handle: TpmTransient,
    log_format: cli::LogFormat,
) -> Result<ContextData, TpmError> {
    let save_command = TpmContextSaveCommand {
        save_handle: handle,
    };
    let (resp, _) = chip.execute(&save_command, &[], log_format)?;

    let save_resp = resp
        .ContextSave()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    let context_bytes = build_to_vec(&save_resp.context)?;

    Ok(ContextData {
        context_blob: base64_engine.encode(context_bytes),
    })
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

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = CreatePrimary::default();
        let mut alg_set = false;
        parse_args!(parser, arg, Self::help, {
            Short('H') | Long("hierarchy") => {
                args.hierarchy = parser.value()?.string()?.parse()?;
            }
            Long("algorithm") => {
                args.algorithm = parser.value()?.string()?.parse()?;
                alg_set = true;
            }
            Long("handle") => {
                args.handle = Some(parse_persistent_handle(&parser.value()?.string()?)?);
            }
            Long("password") => {
                args.password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });

        if !alg_set {
            return Err(TpmError::Usage(
                "Missing required argument: --algorithm <ALGORITHM>".to_string(),
            ));
        }
        Ok(Commands::CreatePrimary(args))
    }

    /// Runs `create-primary`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(
        &self,
        device: &mut Option<TpmDevice>,
        log_format: cli::LogFormat,
    ) -> Result<(), TpmError> {
        let chip = device.as_mut().unwrap();
        let mut io = CommandIo::new(std::io::stdout(), log_format)?;
        let session = io.take_session()?;

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
        let sessions = get_auth_sessions(
            &cmd,
            &handles,
            session.as_ref(),
            self.password.password.as_deref(),
        )?;
        let (resp, _) = chip.execute(&cmd, &sessions, log_format)?;

        let create_primary_resp = resp
            .CreatePrimary()
            .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
        let object_handle = create_primary_resp.object_handle;

        let final_object = if let Some(persistent_handle) = self.handle {
            let evict_cmd = TpmEvictControlCommand {
                auth: (TpmRh::Owner as u32).into(),
                object_handle: object_handle.0.into(),
                persistent_handle,
            };
            let evict_handles = [TpmRh::Owner as u32, object_handle.into()];
            let evict_sessions =
                get_auth_sessions(&evict_cmd, &evict_handles, session.as_ref(), None)?;
            let (resp, _) = chip.execute(&evict_cmd, &evict_sessions, log_format)?;
            resp.EvictControl()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

            Object::Handle(persistent_handle.into())
        } else {
            let mut final_context = None;
            with_transient_handle(chip, object_handle, log_format, |chip_inner| {
                final_context = Some(save_key_context(chip_inner, object_handle, log_format)?);
                Ok(())
            })?;
            Object::Context(final_context.unwrap())
        };

        io.push_object(final_object);
        io.finalize()
    }
}

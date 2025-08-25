// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, Object, Seal},
    get_auth_sessions, get_tpm_device, input_to_bytes, parse_args,
    util::build_to_vec,
    Command, CommandIo, CommandType, ObjectData, TpmError, ID_SEALED_DATA,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use std::io;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData,
        TpmAlgId, TpmaObject, TpmlPcrSelection, TpmsKeyedhashParms, TpmsSensitiveCreate,
        TpmtPublic, TpmtScheme, TpmuPublicId, TpmuPublicParms,
    },
    message::TpmCreateCommand,
};

const ABOUT: &str = "Seals a keyedhash object";
const USAGE: &str = "tpm2sh seal [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--parent-password",
        "<PASSWORD>",
        "Authorization for the parent object",
    ),
    (
        None,
        "--object-password",
        "<PASSWORD>",
        "Authorization for the new sealed object",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

impl Command for Seal {
    fn command_type(&self) -> CommandType {
        CommandType::Pipe
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("seal", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Seal::default();
        parse_args!(parser, arg, Self::help, {
            Long("parent-password") => {
                args.parent_password.password = Some(parser.value()?.string()?);
            }
            Long("object-password") => {
                args.object_password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Seal(args))
    }

    /// Runs `seal`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(&self) -> Result<(), TpmError> {
        let mut chip = get_tpm_device()?;
        let mut io = CommandIo::new(io::stdout())?;
        let session = io.take_session()?;

        let parent_handle_guard = io.consume_handle()?;
        let parent_handle = parent_handle_guard.handle();

        let data_to_seal_obj = io.consume_object(|obj| matches!(obj, Object::KeyData(_)))?;
        let Object::KeyData(data_str) = data_to_seal_obj else {
            return Err(TpmError::Execution(
                "Expected a KeyData object from the pipeline".to_string(),
            ));
        };
        let data_to_seal = input_to_bytes(&data_str)?;

        let mut object_attributes = TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT;
        if self.object_password.password.is_some() {
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

        let sealed_obj_password = self
            .object_password
            .password
            .as_deref()
            .unwrap_or("")
            .as_bytes();
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
        let sessions = get_auth_sessions(
            &cmd,
            &handles,
            session.as_ref(),
            self.parent_password.password.as_deref(),
        )?;
        let (resp, _) = chip.execute(&cmd, &sessions)?;

        let create_resp = resp.Create().map_err(|e| {
            TpmError::Execution(format!("unexpected response type for Create: {e:?}"))
        })?;
        let pub_bytes = build_to_vec(&create_resp.out_public)?;
        let priv_bytes = build_to_vec(&create_resp.out_private)?;

        let data = ObjectData {
            oid: ID_SEALED_DATA.to_string(),
            empty_auth: sealed_obj_password.is_empty(),
            parent: format!("{parent_handle:#010x}"),
            public: base64_engine.encode(pub_bytes),
            private: base64_engine.encode(priv_bytes),
        };
        let new_object = Object::Key(data);
        io.push_object(new_object);
        io.finalize()
    }
}

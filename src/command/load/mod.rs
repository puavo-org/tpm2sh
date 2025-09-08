// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{
        handle_help, parse_parent_option, parse_session_option, required, DeviceCommand, Subcommand,
    },
    command::{context::Context, CommandError},
    crypto::{self, crypto_hmac, crypto_kdfa, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE},
    device::{TpmDevice, TpmDeviceError},
    error::{CliError, ParseError},
    key::{private_key_from_bytes, Tpm2shAlgId, TpmKey},
    session::session_from_uri,
    uri::Uri,
    util::build_to_vec,
};
use aes::Aes128;
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use lexopt::{Arg, Parser, ValueExt};
use rand::{thread_rng, RngCore};
use tpm2_protocol::{
    self,
    data::{
        Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc, TpmtPublic,
        TpmtSymDef, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{TpmImportCommand, TpmLoadCommand, TpmReadPublicCommand, TpmUnsealCommand},
    TpmBuild, TpmParse, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

#[derive(Debug)]
pub struct Load {
    pub parent: Uri,
    pub input: Uri,
    pub output: Option<Uri>,
    pub session: Option<Uri>,
    pub unseal: bool,
}

impl Subcommand for Load {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");
    const OPTION_PARENT: bool = true;
    const OPTION_OUTPUT: bool = true;
    const OPTION_SESSION: bool = true;

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut parent = None;
        let mut output = None;
        let mut session = None;
        let mut unseal = false;
        let mut positional_args = Vec::new();

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("parent") => parse_parent_option(parser, &mut parent)?,
                Arg::Long("output") => output = Some(parser.value()?.parse()?),
                Arg::Long("session") => parse_session_option(parser, &mut session)?,
                Arg::Long("unseal") => unseal = true,
                Arg::Value(val) => positional_args.push(val.parse()?),
                _ => return handle_help(arg),
            }
        }

        if positional_args.len() != 1 {
            return Err(CliError::Parse(ParseError::Custom(format!(
                "expected 1 positional argument, found {}",
                positional_args.len()
            ))));
        }

        Ok(Load {
            parent: required(parent, "--parent")?,
            input: positional_args.remove(0),
            output,
            session,
            unseal,
        })
    }
}

/// Creates the encrypted blobs needed for `TPM2_Import`.
///
/// This function protects the sensitive private key material for import under a
/// parent key. It secures the seed used for symmetric encryption using the
/// parent's public key (RSA-OAEP for RSA parents, ECDH for ECC parents).
///
/// # Errors
///
/// Returns a `CliError` for cryptographic failures or invalid input.
fn create_import_blob(
    parent_public: &TpmtPublic,
    object_public: &TpmtPublic,
    private_bytes: &[u8],
    parent_name: &[u8],
) -> Result<(Tpm2bPrivate, Tpm2bEncryptedSecret, Tpm2bData), CliError> {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    let parent_name_alg = parent_public.name_alg;

    let (in_sym_seed, encryption_key) = match parent_public.object_type {
        TpmAlgId::Rsa => crypto::protect_seed_with_rsa(parent_public, &seed)?,
        TpmAlgId::Ecc => crypto::protect_seed_with_ecc(parent_public, &seed)?,
        _ => {
            return Err(CommandError::InvalidParentKeyType {
                reason: "parent key must be RSA or ECC",
            }
            .into())
        }
    };

    let object_name = crypto::crypto_make_name(object_public).map_err(CliError::from)?;

    let sym_key = crypto_kdfa(
        parent_name_alg,
        &seed,
        KDF_LABEL_STORAGE,
        &object_name,
        parent_name,
        128,
    )
    .map_err(CliError::from)?;

    let integrity_key_bits = u16::try_from(
        tpm2_protocol::tpm_hash_size(&parent_name_alg).ok_or({
            CommandError::InvalidAlgorithm {
                alg: Tpm2shAlgId(parent_name_alg),
            }
        })? * 8,
    )
    .map_err(|_| CommandError::InvalidKey("hash size conversion error".to_string()))?;

    let hmac_key = crypto_kdfa(
        parent_name_alg,
        &seed,
        KDF_LABEL_INTEGRITY,
        &[],
        &[],
        integrity_key_bits,
    )
    .map_err(CliError::from)?;

    let sensitive = tpm2_protocol::data::TpmtSensitive::from_private_bytes(
        object_public.object_type,
        private_bytes,
    )
    .map_err(CommandError::from)?;
    let sensitive_data_vec = build_to_vec(&sensitive)?;

    let mut enc_data = sensitive_data_vec;
    let iv = [0u8; 16];

    let cipher = Encryptor::<Aes128>::new(sym_key.as_slice().into(), &iv.into());
    cipher.encrypt(&mut enc_data);

    let final_mac = crypto_hmac(parent_name_alg, &hmac_key, &[&enc_data, parent_name])
        .map_err(CliError::from)?;

    let duplicate_blob = {
        let mut duplicate_blob_buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut duplicate_blob_buf);
            tpm2_protocol::data::Tpm2bDigest::try_from(final_mac.as_slice())
                .map_err(CommandError::from)?
                .build(&mut writer)
                .map_err(CommandError::from)?;
            writer.write_bytes(&enc_data).map_err(CommandError::from)?;
            writer.len()
        };
        duplicate_blob_buf[..len].to_vec()
    };

    Ok((
        Tpm2bPrivate::try_from(duplicate_blob.as_slice()).map_err(CommandError::from)?,
        in_sym_seed,
        encryption_key,
    ))
}

/// Parses an external key from a URI and prepares it for TPM import.
fn prepare_key_for_import(
    key: &Uri,
    parent_name_alg: TpmAlgId,
) -> Result<(crypto::PrivateKey, TpmtPublic, Vec<u8>), CliError> {
    let key_bytes = key.to_bytes()?;
    let private_key = private_key_from_bytes(&key_bytes)?;

    let public = private_key
        .to_public(parent_name_alg)
        .map_err(CliError::from)?;
    let sensitive_blob = private_key.sensitive_blob();

    Ok((private_key, public, sensitive_blob))
}

/// Checks if a byte slice contains valid, printable UTF-8.
///
/// "Printable" is defined as not containing any control characters except for
/// common whitespace (newline, carriage return, tab).
fn is_printable_utf8(data: &[u8]) -> bool {
    if let Ok(s) = std::str::from_utf8(data) {
        !s.chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    } else {
        false
    }
}

impl Load {
    /// Finishes the command by loading the object and optionally unsealing.
    #[allow(clippy::too_many_lines, clippy::large_types_passed_by_value)]
    fn run_load(
        &self,
        device: &mut TpmDevice,
        context: &mut Context,
        parent_handle: TpmTransient,
        in_public: Tpm2bPublic,
        in_private: Tpm2bPrivate,
    ) -> Result<(), CliError> {
        let load_cmd = TpmLoadCommand {
            parent_handle: parent_handle.0.into(),
            in_private,
            in_public,
        };
        let handles = [parent_handle.into()];
        let sessions = session_from_uri(&load_cmd, &handles, self.session.as_ref())?;
        let (_rc, resp, _) = device.execute(&load_cmd, &sessions)?;
        let resp = resp
            .Load()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::Load,
            })?;

        context.track(resp.object_handle)?;

        if self.unseal {
            let read_public_cmd = TpmReadPublicCommand {
                object_handle: resp.object_handle.0.into(),
            };
            let (_rc, read_public_resp, _) = device.execute(&read_public_cmd, &[])?;
            let public_area = read_public_resp
                .ReadPublic()
                .map_err(|_| TpmDeviceError::MismatchedResponse {
                    command: TpmCc::ReadPublic,
                })?
                .out_public;

            if public_area.inner.object_type == TpmAlgId::KeyedHash {
                let unseal_cmd = TpmUnsealCommand {
                    item_handle: resp.object_handle.0.into(),
                };
                let handles = [unseal_cmd.item_handle.into()];
                let unseal_sessions =
                    session_from_uri(&unseal_cmd, &handles, self.session.as_ref())?;
                let (_rc, unseal_resp, _) = device.execute(&unseal_cmd, &unseal_sessions)?;
                let unseal_resp = unseal_resp
                    .Unseal()
                    .map_err(|_| TpmDeviceError::MismatchedResponse {
                        command: TpmCc::Unseal,
                    })?
                    .out_data;

                if is_printable_utf8(&unseal_resp) {
                    let s = std::str::from_utf8(&unseal_resp).expect("already checked for utf-8");
                    writeln!(context.writer, "data://utf8,{s}")?;
                } else {
                    writeln!(context.writer, "data://hex,{}", hex::encode(unseal_resp))?;
                }
            } else {
                return Err(CommandError::InvalidAlgorithm {
                    alg: Tpm2shAlgId(public_area.inner.object_type),
                }
                .into());
            }
        } else {
            context.finalize_object_output(
                device,
                resp.object_handle,
                self.output.as_ref(),
                self.session.as_ref(),
            )?;
        }

        Ok(())
    }

    /// Finishes the command by importing an external key.
    fn run_import(
        &self,
        device: &mut TpmDevice,
        context: &mut Context,
        parent_handle: TpmTransient,
    ) -> Result<(), CliError> {
        let (_rc, parent_public, parent_name) = device.read_public(parent_handle)?;
        let parent_name_alg = parent_public.name_alg;
        let (_, public, sensitive_blob) = prepare_key_for_import(&self.input, parent_name_alg)?;
        let in_public = Tpm2bPublic {
            inner: public.clone(),
        };
        let (duplicate, in_sym_seed, encryption_key) =
            create_import_blob(&parent_public, &public, &sensitive_blob, &parent_name)?;
        let symmetric_alg = if parent_public.object_type == TpmAlgId::Rsa {
            TpmtSymDef::default()
        } else {
            TpmtSymDef {
                algorithm: TpmAlgId::Aes,
                key_bits: TpmuSymKeyBits::Aes(128),
                mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
            }
        };
        let import_cmd = TpmImportCommand {
            parent_handle: parent_handle.0.into(),
            encryption_key,
            object_public: in_public.clone(),
            duplicate,
            in_sym_seed,
            symmetric_alg,
        };
        let handles = [parent_handle.into()];
        let sessions = session_from_uri(&import_cmd, &handles, self.session.as_ref())?;
        let (_rc, resp, _) = device.execute(&import_cmd, &sessions)?;
        let import_resp = resp
            .Import()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::Import,
            })?;

        self.run_load(
            device,
            context,
            parent_handle,
            in_public,
            import_resp.out_private,
        )
    }
}

impl DeviceCommand for Load {
    /// Runs `load`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let parent_handle = context.load(device, &self.parent)?;
        let input_bytes = self.input.to_bytes()?;

        if let Ok(tpm_key) =
            TpmKey::from_pem(&input_bytes).or_else(|_| TpmKey::from_der(&input_bytes))
        {
            let (in_public, _) =
                Tpm2bPublic::parse(tpm_key.pub_key.as_bytes()).map_err(ParseError::from)?;
            let (in_private, _) =
                Tpm2bPrivate::parse(tpm_key.priv_key.as_bytes()).map_err(ParseError::from)?;
            self.run_load(device, context, parent_handle, in_public, in_private)
        } else {
            self.run_import(device, context, parent_handle)
        }
    }
}

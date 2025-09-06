// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::{context::Context, CommandError},
    crypto::{self, crypto_hmac, crypto_kdfa, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE},
    device::{TpmDevice, TpmDeviceError},
    error::{CliError, ParseError},
    key::{private_key_from_pem_bytes, TpmKey},
    session::session_from_args,
    uri::Uri,
    util::build_to_vec,
};
use aes::Aes128;
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use lexopt::{Arg, Parser, ValueExt};
use rand::{thread_rng, RngCore};
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc, TpmtPublic,
        TpmtSymDef, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{TpmImportCommand, TpmLoadCommand},
    TpmBuild, TpmParse, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

#[derive(Debug)]
pub struct Load {
    pub parent: Uri,
    pub input: Uri,
    pub output: Option<Uri>,
}

impl Subcommand for Load {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut parent = None;
        let mut output = None;
        let mut positional_args = Vec::new();

        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("parent") => parent = Some(parser.value()?.parse()?),
                Arg::Long("output") => output = Some(parser.value()?.parse()?),
                Arg::Value(val) => positional_args.push(val.parse()?),
                _ => return handle_help(arg),
            }
        }

        if positional_args.len() != 1 {
            return Err(format!(
                "expected 1 positional argument, found {}",
                positional_args.len()
            )
            .into());
        }

        Ok(Load {
            parent: required(parent, "--parent")?,
            input: positional_args.remove(0),
            output,
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
        tpm2_protocol::tpm_hash_size(&parent_name_alg).ok_or_else(|| {
            CommandError::UnsupportedAlgorithm("parent nameAlg is not a supported hash".to_string())
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
    let pem_bytes = key.to_bytes()?;
    let private_key = private_key_from_pem_bytes(&pem_bytes)?;

    let public = private_key
        .to_public(parent_name_alg)
        .map_err(CliError::from)?;
    let sensitive_blob = private_key.sensitive_blob();

    Ok((private_key, public, sensitive_blob))
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

        let (in_public, in_private) = if let Ok(tpm_key) =
            TpmKey::from_pem(&input_bytes).or_else(|_| TpmKey::from_der(&input_bytes))
        {
            let (public, _) =
                Tpm2bPublic::parse(tpm_key.pub_key.as_bytes()).map_err(ParseError::from)?;
            let (private, _) =
                Tpm2bPrivate::parse(tpm_key.priv_key.as_bytes()).map_err(ParseError::from)?;
            (public, private)
        } else {
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
            let sessions = session_from_args(&import_cmd, &handles, context.cli)?;
            let (_rc, resp, _) = device.execute(&import_cmd, &sessions)?;
            let import_resp = resp
                .Import()
                .map_err(|_| TpmDeviceError::MismatchedResponse {
                    command: TpmCc::Import,
                })?;
            (in_public, import_resp.out_private)
        };

        let load_cmd = TpmLoadCommand {
            parent_handle: parent_handle.0.into(),
            in_private,
            in_public,
        };
        let handles = [parent_handle.into()];
        let sessions = session_from_args(&load_cmd, &handles, context.cli)?;
        let (_rc, resp, _) = device.execute(&load_cmd, &sessions)?;
        let resp = resp
            .Load()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::Load,
            })?;

        context.track(resp.object_handle)?;
        context.save_or_persist(device, resp.object_handle, self.output.as_ref())?;
        Ok(())
    }
}

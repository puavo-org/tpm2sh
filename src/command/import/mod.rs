// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::{context::Context, CommandError},
    crypto::{self, crypto_hmac, crypto_kdfa, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE},
    device::TpmDevice,
    error::CliError,
    key::private_key_from_pem_bytes,
    session::session_from_args,
    uri::Uri,
    util::build_to_vec,
};
use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use lexopt::{Arg, Parser, ValueExt};
use rand::{thread_rng, RngCore};
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmtPublic,
        TpmtSymDef, TpmuSymKeyBits, TpmuSymMode,
    },
    message::TpmImportCommand,
    TpmBuild, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

#[derive(Debug, Default)]
pub struct Import {
    pub parent: Uri,
    pub key: Uri,
}

impl Subcommand for Import {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut parent = None;
        let mut key = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Long("parent") | Arg::Short('P') => parent = Some(parser.value()?.parse()?),
                Arg::Long("key") => key = Some(parser.value()?.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(Import {
            parent: required(parent, "--parent")?,
            key: required(key, "--key")?,
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

impl DeviceCommand for Import {
    /// Runs `import`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError`.
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let parent_handle = context.load(device, &self.parent)?;
        let (_rc, parent_public, parent_name) = device.read_public(parent_handle)?;
        let parent_name_alg = parent_public.name_alg;
        let (_, public, sensitive_blob) = prepare_key_for_import(&self.key, parent_name_alg)?;
        let public_bytes_struct = Tpm2bPublic {
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
            object_public: public_bytes_struct,
            duplicate,
            in_sym_seed,
            symmetric_alg,
        };
        let handles = [parent_handle.into()];
        let sessions = session_from_args(&import_cmd, &handles, context.cli)?;
        let (_rc, resp, _) = device.execute(&import_cmd, &sessions)?;
        let import_resp = resp.Import().map_err(|e| {
            CliError::Unexpected(format!("unexpected response type for Import: {e:?}"))
        })?;
        let pub_key_bytes = build_to_vec(&Tpm2bPublic { inner: public })?;
        let priv_key_bytes = build_to_vec(&import_resp.out_private)?;
        writeln!(
            context.writer,
            "data://base64,{}",
            base64_engine.encode(pub_key_bytes)
        )?;
        writeln!(
            context.writer,
            "data://base64,{}",
            base64_engine.encode(priv_key_bytes)
        )?;
        Ok(())
    }
}

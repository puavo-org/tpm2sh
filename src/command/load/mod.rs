// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::DeviceCommand,
    command::{context::Context, CommandError},
    crypto::{
        crypto_hmac, crypto_kdfa, crypto_make_name, protect_seed_with_ecc, protect_seed_with_rsa,
        PrivateKey, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE,
    },
    device::{TpmDevice, TpmDeviceError},
    error::{CliError, ParseError},
    key::{private_key_from_der_bytes, Tpm2shAlgId, TpmKey},
    policy::{session_from_uri, Uri},
    util::build_to_vec,
};
use aes::Aes128;
use argh::FromArgs;
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use rand::{thread_rng, RngCore};
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bEncryptedSecret, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmCc,
        TpmtPublic, TpmtSymDef, TpmuSymKeyBits, TpmuSymMode,
    },
    message::{TpmImportCommand, TpmLoadCommand, TpmReadPublicCommand, TpmUnsealCommand},
    tpm_hash_size, TpmBuild, TpmParse, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

/// Loads a TPM object or imports an external key.
///
/// Loads a TPM-native key or imports an external key under a parent object.
/// The command auto-detects the key type from the <`KEY_URI`> argument.
/// - If the input is a PEM/DER external key, it is imported using `TPM2_Import`.
/// - If the input is a TSS2 PRIVATE KEY, it is loaded using `TPM2_Load`.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "load")]
pub struct Load {
    /// parent object URI ('data://', 'file://' or 'tpm://')
    #[argh(option)]
    pub parent: Uri,

    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,

    /// output destination ('tpm://' or 'file://')
    #[argh(option)]
    pub output: Option<Uri>,

    /// unseal the object after loading and print the secret data
    #[argh(switch)]
    pub unseal: bool,

    /// key URI ('file://' or 'data://')
    #[argh(positional)]
    pub input: Uri,
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
        TpmAlgId::Rsa => protect_seed_with_rsa(parent_public, &seed)?,
        TpmAlgId::Ecc => protect_seed_with_ecc(parent_public, &seed)?,
        _ => {
            return Err(CommandError::InvalidParentKeyType {
                reason: "parent key must be RSA or ECC",
            }
            .into())
        }
    };

    let object_name = crypto_make_name(object_public).map_err(CliError::from)?;

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
        tpm_hash_size(&parent_name_alg).ok_or(CommandError::InvalidAlgorithm {
            alg: Tpm2shAlgId(parent_name_alg),
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

/// Checks if a byte slice contains valid, printable UTF-8.
///
/// \"Printable\" is defined as not containing any control characters except for
/// common whitespace (newline, carriage return, tab).
fn is_printable_utf8(data: &[u8]) -> bool {
    if let Ok(s) = std::str::from_utf8(data) {
        !s.chars()
            .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    } else {
        false
    }
}

fn read_public(
    device: &mut TpmDevice,
    handle: TpmTransient,
) -> Result<(TpmtPublic, Tpm2bName), TpmDeviceError> {
    let cmd = TpmReadPublicCommand {
        object_handle: handle.0.into(),
    };
    let (resp, _) = device.execute(&cmd, &[])?;
    let read_public_resp = resp
        .ReadPublic()
        .map_err(|_| TpmDeviceError::MismatchedResponse {
            command: TpmCc::ReadPublic,
        })?;
    Ok((read_public_resp.out_public.inner, read_public_resp.name))
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
        let (resp, _) = device.execute(&load_cmd, &sessions)?;
        let resp = resp
            .Load()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::Load,
            })?;

        context.track(resp.object_handle)?;

        if self.unseal {
            let (public_area, _) = read_public(device, resp.object_handle)?;

            if public_area.object_type == TpmAlgId::KeyedHash {
                let unseal_cmd = TpmUnsealCommand {
                    item_handle: resp.object_handle.0.into(),
                };
                let handles = [unseal_cmd.item_handle.into()];
                let unseal_sessions =
                    session_from_uri(&unseal_cmd, &handles, self.session.as_ref())?;
                let (unseal_resp, _) = device.execute(&unseal_cmd, &unseal_sessions)?;
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
                    alg: Tpm2shAlgId(public_area.object_type),
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
        private_key: &PrivateKey,
    ) -> Result<(), CliError> {
        let (parent_public, parent_name) = read_public(device, parent_handle)?;
        let parent_name_alg = parent_public.name_alg;

        let public = private_key
            .to_public(parent_name_alg)
            .map_err(CliError::from)?;
        let sensitive_blob = private_key.sensitive_blob();

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
        let (resp, _) = device.execute(&import_cmd, &sessions)?;
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

        if let Ok(pem) = pem::parse(&input_bytes) {
            if pem.tag() == "TSS2 PRIVATE KEY" {
                let tpm_key = TpmKey::from_der(pem.contents())?;
                let (in_public, _) =
                    Tpm2bPublic::parse(tpm_key.pub_key.as_bytes()).map_err(ParseError::from)?;
                let (in_private, _) =
                    Tpm2bPrivate::parse(tpm_key.priv_key.as_bytes()).map_err(ParseError::from)?;
                return self.run_load(device, context, parent_handle, in_public, in_private);
            } else if pem.tag() == "PRIVATE KEY" {
                let private_key = private_key_from_der_bytes(pem.contents())?;
                return self.run_import(device, context, parent_handle, &private_key);
            }
            return Err(CliError::Parse(ParseError::Custom(format!(
                "unsupported PEM tag '{}', expected 'TSS2 PRIVATE KEY' or 'PRIVATE KEY'",
                pem.tag()
            ))));
        }

        if let Ok(tpm_key) = TpmKey::from_der(&input_bytes) {
            let (in_public, _) =
                Tpm2bPublic::parse(tpm_key.pub_key.as_bytes()).map_err(ParseError::from)?;
            let (in_private, _) =
                Tpm2bPrivate::parse(tpm_key.priv_key.as_bytes()).map_err(ParseError::from)?;
            return self.run_load(device, context, parent_handle, in_public, in_private);
        }

        if let Ok(private_key) = private_key_from_der_bytes(&input_bytes) {
            return self.run_import(device, context, parent_handle, &private_key);
        }

        Err(CliError::Parse(ParseError::Custom(
            "failed to parse input key. Expected a PEM-encoded 'TSS2 PRIVATE KEY' or 'PRIVATE KEY', or a corresponding DER blob.".to_string(),
        )))
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{DeviceCommand, Hierarchy, LocalCommand},
    context::Context,
    crypto::{
        crypto_hmac, crypto_kdfa, crypto_make_name, protect_seed_with_ecc, protect_seed_with_rsa,
        PrivateKey, ID_SEALED_DATA, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE,
    },
    device::{TpmDevice, TpmDeviceError},
    error::{CliError, ParseError},
    key::{private_key_from_der_bytes, Alg, AlgInfo, Tpm2shAlgId, TpmKey},
    policy::{
        fill_pcr_digests, flush_session, get_policy_digest, parse as policy_parse, pcr_get_count,
        pcr_selection_to_list, session_from_uri, start_trial_session, AuthSession, Parsing,
        PolicyExecutor, SessionType, Uri,
    },
    util::{build_to_vec, parse_tpm_rc},
};

use aes::Aes128;
use argh::FromArgs;
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use pkcs8::der::asn1::OctetString;
use rand::{thread_rng, RngCore};
use thiserror::Error;
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bEvent, Tpm2bName, Tpm2bNonce,
        Tpm2bPrivate, Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmAlgId, TpmCc,
        TpmRc, TpmRh, TpmaObject, TpmlPcrSelection, TpmsEccParms, TpmsEccPoint, TpmsKeyedhashParms,
        TpmsRsaParms, TpmsSensitiveCreate, TpmtKdfScheme, TpmtPublic, TpmtScheme, TpmtSymDef,
        TpmtSymDefObject, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
        TPM_RH_PERSISTENT_FIRST, TPM_RH_TRANSIENT_FIRST,
    },
    message::{
        TpmCreateCommand, TpmCreatePrimaryCommand, TpmDictionaryAttackLockResetCommand,
        TpmImportCommand, TpmLoadCommand, TpmPcrEventCommand, TpmReadPublicCommand,
        TpmStartAuthSessionCommand, TpmUnsealCommand,
    },
    tpm_hash_size, TpmBuild, TpmErrorKind, TpmParse, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

#[derive(Debug, Error)]
pub enum CommandError {
    #[error("lock poisoned")]
    LockPoisoned,

    #[error("invalid parent key")]
    InvalidParentKey,

    #[error("invalid algorithm: {0}")]
    InvalidAlgorithm(Tpm2shAlgId),

    #[error("invalid key format")]
    InvalidKeyFormat,

    #[error("invalid PCR selection")]
    InvalidPcrSelection,

    #[error("lock poisoned")]
    NotProvided,

    #[error("same conversion format")]
    SameConversionFormat,

    #[error("TPM: {0}")]
    Tpm(TpmErrorKind),
}

impl From<TpmErrorKind> for CommandError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Tpm(err)
    }
}

/// Converts keys between ASN.1 formats.
/// Detects the format (PEM or DER) from the file extensions, and converts the key.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "convert")]
pub struct Convert {
    /// input file path
    #[argh(positional)]
    pub input: std::path::PathBuf,

    /// output file path
    #[argh(positional)]
    pub output: std::path::PathBuf,
}

impl LocalCommand for Convert {
    /// Runs `convert`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, _context: &mut Context) -> Result<(), CliError> {
        let input_ext = self
            .input
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();

        let output_ext = self
            .output
            .extension()
            .and_then(std::ffi::OsStr::to_str)
            .unwrap_or_default();

        if !input_ext.is_empty() && input_ext == output_ext {
            return Err(CommandError::SameConversionFormat.into());
        }

        let input_bytes = std::fs::read(&self.input)
            .map_err(|e| CliError::File(self.input.display().to_string(), e))?;

        let tpm_key = TpmKey::from_pem(&input_bytes)
            .or_else(|_| TpmKey::from_der(&input_bytes))
            .map_err(|_| CommandError::InvalidKeyFormat)?;

        let output_bytes = match output_ext {
            "pem" => tpm_key.to_pem()?.into_bytes(),
            "der" => tpm_key.to_der()?,
            _ => return Err(CommandError::InvalidKeyFormat.into()),
        };

        std::fs::write(&self.output, output_bytes)
            .map_err(|e| CliError::File(self.output.display().to_string(), e))?;

        Ok(())
    }
}

/// Creates a primary key.
///
/// Creates a primary key from a chosen hierarchy and algorithm. The command creates
/// and loads the object, then returns its saved context. The output can be an
/// output file URI for the saved context. If omitted, the saved context is printed
/// to standard output as a 'data://' URI.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "create-primary")]
pub struct CreatePrimary {
    /// hierarchy to create the key in (owner, platform, or endorsement)
    #[argh(option, short = 'H', default = "Default::default()")]
    pub hierarchy: Hierarchy,

    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,

    /// output destination: 'tpm://' or 'file://'
    #[argh(option)]
    pub output: Option<Uri>,

    /// algorithm descriptor string
    #[argh(positional)]
    pub algorithm: Alg,
}

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
        AlgInfo::KeyedHash => {
            object_attributes |= TpmaObject::SIGN_ENCRYPT;
            (
                TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                    scheme: TpmtScheme {
                        scheme: TpmAlgId::Null,
                    },
                }),
                TpmuPublicId::KeyedHash(tpm2_protocol::TpmBuffer::default()),
            )
        }
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

impl DeviceCommand for CreatePrimary {
    /// Runs `create-primary`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let primary_handle: TpmRh = self.hierarchy.into();
        let handles = [primary_handle as u32];
        let public_template = build_public_template(&self.algorithm);
        let cmd = TpmCreatePrimaryCommand {
            primary_handle: (primary_handle as u32).into(),
            in_sensitive: Tpm2bSensitiveCreate {
                inner: TpmsSensitiveCreate {
                    user_auth: Tpm2bAuth::default(),
                    data: Tpm2bSensitiveData::default(),
                },
            },
            in_public: Tpm2bPublic {
                inner: public_template,
            },
            outside_info: Tpm2bData::default(),
            creation_pcr: TpmlPcrSelection::default(),
        };
        let sessions = session_from_uri(&cmd, &handles, self.session.as_ref())?;
        let (resp, _) = device.execute(&cmd, &sessions)?;
        let resp = resp
            .CreatePrimary()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::CreatePrimary))?;
        let object_handle = resp.object_handle;

        context.track(object_handle)?;
        Ok(context.finalize_object_output(
            device,
            object_handle,
            self.output.as_ref(),
            self.session.as_ref(),
        )?)
    }
}

/// Deletes a transient or persistent object.
///
/// If a 'tpm://' URI is provided for a persistent handle, the object is evicted
/// from NV memory. If the URI points to a transient handle (either 'tpm://',
/// 'file://', or 'data://'), the object's context is flushed from the TPM.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "delete")]
pub struct Delete {
    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,

    /// URI of the object to delete ('tpm://', 'file://', or 'data://')
    #[argh(positional)]
    pub handle: Uri,
}

impl DeviceCommand for Delete {
    /// Runs `delete`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let handle = context.delete(device, &self.handle, self.session.as_ref())?;
        writeln!(context.writer, "tpm://{handle:#010x}")?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListType {
    Algorithm,
    Persistent,
    Transient,
}

impl std::str::FromStr for ListType {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "algorithm" | "algorithms" => Ok(Self::Algorithm),
            "persistent" => Ok(Self::Persistent),
            "transient" => Ok(Self::Transient),
            _ => Err(format!("invalid list type: '{s}'")),
        }
    }
}

/// Lists TPM capabilities and objects.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "list")]
pub struct List {
    /// type of items to list (algorithm, persistent, or transient)
    #[argh(positional)]
    pub list_type: ListType,
}

impl DeviceCommand for List {
    /// Runs `list`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        match self.list_type {
            ListType::Algorithm => {
                let mut algorithms = device.get_all_algorithms()?;
                algorithms.sort_by(|a, b| a.1.cmp(&b.1));
                for (_, name) in algorithms {
                    writeln!(context.writer, "{name}")?;
                }
            }
            ListType::Persistent => {
                let handles = device.get_all_handles(TPM_RH_PERSISTENT_FIRST)?;
                for handle in handles {
                    writeln!(context.writer, "tpm://{handle:#010x}")?;
                }
            }
            ListType::Transient => {
                let handles = device.get_all_handles(TPM_RH_TRANSIENT_FIRST)?;
                for handle in handles {
                    writeln!(context.writer, "tpm://{handle:#010x}")?;
                }
            }
        }
        Ok(())
    }
}

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
        _ => return Err(CommandError::InvalidParentKey.into()),
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
        tpm_hash_size(&parent_name_alg)
            .ok_or(CommandError::InvalidAlgorithm(Tpm2shAlgId(parent_name_alg)))?
            * 8,
    )
    .map_err(|_| CommandError::InvalidKeyFormat)?;

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
        .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::ReadPublic))?;
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
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::Load))?;

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
                    .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::Unseal))?
                    .out_data;

                if is_printable_utf8(&unseal_resp) {
                    let s = std::str::from_utf8(&unseal_resp).expect("already checked for utf-8");
                    writeln!(context.writer, "data://utf8,{s}")?;
                } else {
                    writeln!(context.writer, "data://hex,{}", hex::encode(unseal_resp))?;
                }
            } else {
                return Err(
                    CommandError::InvalidAlgorithm(Tpm2shAlgId(public_area.object_type)).into(),
                );
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
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::Import))?;

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

/// Extends a PCR with an event.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "pcr-event")]
pub struct PcrEvent {
    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,

    /// PCR selection to extend (e.g., "sha256:7")
    #[argh(positional)]
    pub pcr_selection: String,

    /// data URI for the event ('file://' or 'data://')
    #[argh(positional)]
    pub data: Uri,
}

impl DeviceCommand for PcrEvent {
    /// Runs `pcr-event`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, _context: &mut Context) -> Result<(), CliError> {
        let pcr_count = pcr_get_count(device)?;
        let selection = pcr_selection_to_list(&self.pcr_selection, pcr_count)?;

        if selection.len() != 1 {
            return Err(CommandError::InvalidPcrSelection.into());
        }
        let pcr_selection = &selection[0];

        let set_bits_count: u32 = pcr_selection
            .pcr_select
            .iter()
            .map(|b| b.count_ones())
            .sum();
        if set_bits_count != 1 {
            return Err(CommandError::InvalidPcrSelection.into());
        }

        let pcr_index = pcr_selection
            .pcr_select
            .iter()
            .enumerate()
            .find_map(|(byte_idx, &byte)| {
                if byte != 0 {
                    let base =
                        u32::try_from(byte_idx * 8).expect("PCR index calculation overflowed");
                    Some(base + byte.trailing_zeros())
                } else {
                    None
                }
            })
            .ok_or(CommandError::InvalidPcrSelection)?;

        let handles = [pcr_index];
        let data_bytes = self.data.to_bytes()?;
        let event_data = Tpm2bEvent::try_from(data_bytes.as_slice()).map_err(CommandError::from)?;
        let command = TpmPcrEventCommand {
            pcr_handle: handles[0],
            event_data,
        };
        let sessions = session_from_uri(&command, &handles, self.session.as_ref())?;
        let (resp, _) = device.execute(&command, &sessions)?;
        resp.PcrEvent()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::PcrEvent))?;
        Ok(())
    }
}

/// Builds authorization policies.
///
/// A policy expression defines a condition that must be met, for example,
/// 'pcr(sha256:0,...)' or 'secret(tpm://...)'.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "policy")]
pub struct Policy {
    /// compose the policy and output only the final digest
    #[argh(switch)]
    pub compose: bool,

    /// policy expression
    #[argh(positional)]
    pub expression: String,
}

impl DeviceCommand for Policy {
    /// Run 'policy'.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` on failure.
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let mut ast = policy_parse(&self.expression, Parsing::AuthorizationPolicy)?;

        fill_pcr_digests(&mut ast, device)?;

        if self.compose {
            let pcr_count = pcr_get_count(device)?;
            let session_hash_alg = TpmAlgId::Sha256;
            let session_handle = start_trial_session(device, SessionType::Trial, session_hash_alg)?;
            let mut executor = PolicyExecutor::new(pcr_count, device, session_hash_alg);
            executor.execute_policy_ast(session_handle, &ast)?;
            let final_digest = get_policy_digest(executor.device(), session_handle)?;
            flush_session(executor.device(), session_handle)?;
            writeln!(context.writer, "{}", hex::encode(&*final_digest))?;
        } else {
            writeln!(context.writer, "{ast}")?;
        }
        Ok(())
    }
}

fn parse_rc_from_str(value: &str) -> Result<TpmRc, String> {
    parse_tpm_rc(value).map_err(|e| e.to_string())
}

/// Prints a human-readable description of a TPM error code.
#[derive(FromArgs, Debug)]
#[argh(subcommand, name = "print-error")]
pub struct PrintError {
    /// TPM error code in decimal or hex format
    #[argh(positional, from_str_fn(parse_rc_from_str))]
    pub rc: TpmRc,
}

impl LocalCommand for PrintError {
    fn run(&self, context: &mut Context) -> Result<(), CliError> {
        writeln!(context.writer, "{}", self.rc)?;
        Ok(())
    }
}

/// Resets the dictionary attack lockout timer.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "reset-lock")]
pub struct ResetLock {
    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,
}

impl DeviceCommand for ResetLock {
    /// Runs `reset-lock`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, _context: &mut Context) -> Result<(), CliError> {
        let command = TpmDictionaryAttackLockResetCommand {
            lock_handle: (TpmRh::Lockout as u32).into(),
        };
        let handles = [TpmRh::Lockout as u32];
        let sessions = session_from_uri(&command, &handles, self.session.as_ref())?;
        let (resp, _) = device.execute(&command, &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::DictionaryAttackLockReset))?;
        Ok(())
    }
}

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
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::Create))?;

        let tpm_key = TpmKey {
            oid: ID_SEALED_DATA,
            parent: parent_handle.0,
            pub_key: OctetString::new(build_to_vec(&create_resp.out_public)?)
                .map_err(|e| ParseError::Custom(format!("DER encode error: {e}")))?,
            priv_key: OctetString::new(build_to_vec(&create_resp.out_private)?)
                .map_err(|e| ParseError::Custom(format!("DER encode error: {e}")))?,
        };

        let pem_output = tpm_key.to_pem()?;
        Ok(context.handle_data_output(self.output.as_ref(), pem_output.as_bytes())?)
    }
}

/// Starts an authorization session.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "start-session")]
pub struct StartSession {
    /// session type (hmac, policy, or trial)
    #[argh(option, short = 's', default = "Default::default()")]
    pub session_type: SessionType,
}

impl DeviceCommand for StartSession {
    /// Runs `start-session`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let auth_hash = TpmAlgId::Sha256;
        let digest_len = tpm_hash_size(&auth_hash)
            .ok_or(CommandError::InvalidAlgorithm(Tpm2shAlgId(auth_hash)))?;
        let mut nonce_bytes = vec![0; digest_len];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let cmd = TpmStartAuthSessionCommand {
            tpm_key: (TpmRh::Null as u32).into(),
            bind: (TpmRh::Null as u32).into(),
            nonce_caller: Tpm2bNonce::try_from(nonce_bytes.as_slice())
                .map_err(CommandError::from)?,
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: self.session_type.into(),
            symmetric: TpmtSymDefObject {
                algorithm: TpmAlgId::Null,
                key_bits: TpmuSymKeyBits::Null,
                mode: TpmuSymMode::Null,
            },
            auth_hash,
        };
        let (response, _) = device.execute(&cmd, &[])?;
        let start_auth_session_resp = response
            .StartAuthSession()
            .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::StartAuthSession))?;
        let session = AuthSession {
            handle: start_auth_session_resp.session_handle,
            nonce_tpm: start_auth_session_resp.nonce_tpm,
            attributes: tpm2_protocol::data::TpmaSession::empty(),
            hmac_key: Tpm2bAuth::default(),
            auth_hash,
        };
        writeln!(context.writer, "session://{session}")?;
        Ok(())
    }
}

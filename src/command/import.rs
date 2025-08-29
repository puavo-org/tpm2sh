// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arg_parser::{format_subcommand_help, CommandLineOption},
    cli::{Commands, Import},
    get_auth_sessions, parse_args,
    util::build_to_vec,
    Command, CommandIo, CommandType, Key, PipelineObject, PrivateKey, TpmDevice, TpmError,
};
use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use hmac::{Hmac, Mac};
use lexopt::prelude::*;
use num_traits::FromPrimitive;
use p256::{ecdh::diffie_hellman, elliptic_curve::sec1::FromEncodedPoint, AffinePoint, SecretKey};
use p384::{
    ecdh::diffie_hellman as p384_ecdh, elliptic_curve::sec1::ToEncodedPoint as ToEncodedPoint384,
    AffinePoint as AffinePoint384, PublicKey as PublicKey384, SecretKey as SecretKey384,
};
use p521::{
    ecdh::diffie_hellman as p521_ecdh, AffinePoint as AffinePoint521, PublicKey as PublicKey521,
    SecretKey as SecretKey521,
};
use rand::{thread_rng, RngCore};
use rsa::{Oaep, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::{
        self, Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmEccCurve,
        TpmsEccPoint, TpmtPublic, TpmtSymDef, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits,
        TpmuSymMode,
    },
    message::{TpmImportCommand, TpmReadPublicCommand},
    TpmBuild, TpmErrorKind, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};
use url::Url;

const ABOUT: &str = "Imports an external key";
const USAGE: &str = "tpm2sh import --key <KEY_URI> [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[
    (
        None,
        "--key",
        "<KEY_URI>",
        "URI of the external private key to import (e.g., 'file:///path/to/key.pem')",
    ),
    (
        None,
        "--parent-password",
        "<PASSWORD>",
        "Authorization for the parent object",
    ),
    (Some("-h"), "--help", "", "Print help information"),
];

const KDF_DUPLICATE: &str = "DUPLICATE";
const KDF_INTEGRITY: &str = "INTEGRITY";
const KDF_STORAGE: &str = "STORAGE";

/// Reads the public area and name of a TPM object.
///
/// # Errors
///
/// Returns `TpmError` if the `ReadPublic` command fails.
fn read_public(
    device: Option<Arc<Mutex<TpmDevice>>>,
    handle: TpmTransient,
) -> Result<(TpmtPublic, data::Tpm2bName), TpmError> {
    let cmd = TpmReadPublicCommand {
        object_handle: handle.0.into(),
    };
    let device_arc =
        device.ok_or_else(|| TpmError::Execution("TPM device not provided".to_string()))?;
    let mut locked_device = device_arc
        .lock()
        .map_err(|_| TpmError::Execution("TPM device lock poisoned".to_string()))?;

    let (resp, _) = locked_device.execute(&cmd, &[])?;
    let read_public_resp = resp
        .ReadPublic()
        .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
    Ok((read_public_resp.out_public.inner, read_public_resp.name))
}

fn kdfa(
    auth_hash: TpmAlgId,
    hmac_key: &[u8],
    label: &str,
    context_a: &[u8],
    context_b: &[u8],
    key_bits: u16,
) -> Result<Vec<u8>, TpmError> {
    let mut key_stream = Vec::new();
    let key_bytes = key_bits as usize / 8;
    let label_bytes = {
        let mut bytes = label.as_bytes().to_vec();
        bytes.push(0);
        bytes
    };

    macro_rules! kdfa_hmac {
        ($digest:ty) => {{
            let mut counter: u32 = 1;
            while key_stream.len() < key_bytes {
                let mut hmac = <Hmac<$digest> as Mac>::new_from_slice(hmac_key)
                    .map_err(|e| TpmError::Execution(format!("HMAC init error: {e}")))?;

                hmac.update(&counter.to_be_bytes());
                hmac.update(&label_bytes);
                hmac.update(context_a);
                hmac.update(context_b);
                hmac.update(&u32::from(key_bits).to_be_bytes());

                let result = hmac.finalize().into_bytes();
                let remaining = key_bytes - key_stream.len();
                let to_take = remaining.min(result.len());
                key_stream.extend_from_slice(&result[..to_take]);

                counter += 1;
            }
        }};
    }

    match auth_hash {
        TpmAlgId::Sha256 => kdfa_hmac!(Sha256),
        TpmAlgId::Sha384 => kdfa_hmac!(Sha384),
        TpmAlgId::Sha512 => kdfa_hmac!(Sha512),
        _ => {
            return Err(TpmError::Execution(format!(
                "unsupported hash algorithm for KDFa: {auth_hash}"
            )))
        }
    }

    Ok(key_stream)
}

/// Encrypts the import seed using the parent's RSA public key.
///
/// See Table 27 in TCG TPM 2.0 Architectures specification for more information.
fn protect_seed_with_rsa(
    parent_public: &TpmtPublic,
    seed: &[u8; 32],
) -> Result<(Tpm2bEncryptedSecret, Tpm2bData), TpmError> {
    let n = match &parent_public.unique {
        TpmuPublicId::Rsa(data) => Ok(data.as_ref()),
        _ => Err(TpmError::Execution("RSA: invalid unique".to_string())),
    }?;
    let e_raw = match &parent_public.parameters {
        TpmuPublicParms::Rsa(params) => Ok(params.exponent),
        _ => Err(TpmError::Execution("RSA: invalid parameters".to_string())),
    }?;
    let e = if e_raw == 0 { 65537 } else { e_raw };
    let rsa_pub_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_u32(e)
            .ok_or_else(|| TpmError::Execution("RSA: invalid integer conversion".to_string()))?,
    )
    .map_err(|e| TpmError::Execution(format!("RSA: invalid public key: {e}")))?;

    let mut rng = thread_rng();
    let parent_name_alg = parent_public.name_alg;

    let encrypted_seed_result = match parent_name_alg {
        TpmAlgId::Sha1 => rsa_pub_key.encrypt(
            &mut rng,
            Oaep::new_with_label::<Sha1, _>(KDF_DUPLICATE),
            seed,
        ),
        TpmAlgId::Sha256 => rsa_pub_key.encrypt(
            &mut rng,
            Oaep::new_with_label::<Sha256, _>(KDF_DUPLICATE),
            seed,
        ),
        TpmAlgId::Sha384 => rsa_pub_key.encrypt(
            &mut rng,
            Oaep::new_with_label::<Sha384, _>(KDF_DUPLICATE),
            seed,
        ),
        TpmAlgId::Sha512 => rsa_pub_key.encrypt(
            &mut rng,
            Oaep::new_with_label::<Sha512, _>(KDF_DUPLICATE),
            seed,
        ),
        _ => {
            return Err(TpmError::Execution(format!(
                "RSA-OAEP: unsupported nameAlg: {parent_name_alg:?}"
            )));
        }
    };
    let encrypted_seed = encrypted_seed_result
        .map_err(|e| TpmError::Execution(format!("RSA-OAEP: encryption failed: {e}")))?;

    Ok((
        Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice())?,
        Tpm2bData::default(),
    ))
}

macro_rules! ecdh_protect_seed {
    (
		$parent_point:expr, $name_alg:expr, $seed:expr,
		$pk_ty:ty, $sk_ty:ty, $affine_ty:ty, $dh_fn:ident, $encoded_point_ty:ty
	) => {{
        let encoded_point = <$encoded_point_ty>::from_affine_coordinates(
            $parent_point.x.as_ref().into(),
            $parent_point.y.as_ref().into(),
            false,
        );
        let affine_point_opt: Option<$affine_ty> =
            <$affine_ty>::from_encoded_point(&encoded_point).into();
        let affine_point = affine_point_opt.ok_or_else(|| {
            TpmError::Execution("Invalid parent public key: not on curve".to_string())
        })?;

        if affine_point.is_identity().into() {
            return Err(TpmError::Execution(
                "Invalid parent public key: point at infinity".to_string(),
            ));
        }

        let parent_pk = <$pk_ty>::from_affine(affine_point)
            .map_err(|e| TpmError::Execution(format!("failed to construct public key: {e}")))?;

        let context_b: Vec<u8> = [$parent_point.x.as_ref(), $parent_point.y.as_ref()].concat();

        let ephemeral_sk = <$sk_ty>::random(&mut thread_rng());
        let ephemeral_pk_bytes_encoded = ephemeral_sk.public_key().to_encoded_point(false);
        let ephemeral_pk_bytes = ephemeral_pk_bytes_encoded.as_bytes();
        if ephemeral_pk_bytes.is_empty()
            || ephemeral_pk_bytes[0] != crate::crypto::UNCOMPRESSED_POINT_TAG
        {
            return Err(TpmError::Execution(
                "invalid ephemeral ECC public key format".to_string(),
            ));
        }
        let context_a = &ephemeral_pk_bytes[1..];

        let shared_secret = $dh_fn(ephemeral_sk.to_nonzero_scalar(), parent_pk.as_affine());
        let z = shared_secret.raw_secret_bytes();
        let sym_material = kdfa($name_alg, z, KDF_STORAGE, context_a, &context_b, 256)?;
        let (aes_key, iv) = sym_material.split_at(16);
        let mut encrypted_seed_buf = *$seed;
        let cipher = Encryptor::<Aes128>::new(aes_key.into(), iv.into());
        cipher.encrypt(&mut encrypted_seed_buf);

        (encrypted_seed_buf, ephemeral_pk_bytes.to_vec())
    }};
}

/// Encrypts the import seed using an ECDH shared secret derived from the parent's ECC public key.
fn protect_seed_with_ecc(
    parent_public: &TpmtPublic,
    seed: &[u8; 32],
) -> Result<(Tpm2bEncryptedSecret, Tpm2bData), TpmError> {
    let (parent_point, curve_id) = match (&parent_public.unique, &parent_public.parameters) {
        (TpmuPublicId::Ecc(point), TpmuPublicParms::Ecc(params)) => Ok((point, params.curve_id)),
        _ => Err(TpmError::Execution(
            "parent is not a valid ECC key".to_string(),
        )),
    }?;

    let (encrypted_seed, ephemeral_point_bytes) = match curve_id {
        TpmEccCurve::NistP256 => ecdh_protect_seed!(
            parent_point,
            parent_public.name_alg,
            seed,
            p256::PublicKey,
            SecretKey,
            AffinePoint,
            diffie_hellman,
            p256::EncodedPoint
        ),
        TpmEccCurve::NistP384 => ecdh_protect_seed!(
            parent_point,
            parent_public.name_alg,
            seed,
            PublicKey384,
            SecretKey384,
            AffinePoint384,
            p384_ecdh,
            p384::EncodedPoint
        ),
        TpmEccCurve::NistP521 => ecdh_protect_seed!(
            parent_point,
            parent_public.name_alg,
            seed,
            PublicKey521,
            SecretKey521,
            AffinePoint521,
            p521_ecdh,
            p521::EncodedPoint
        ),
        _ => {
            return Err(TpmError::Execution(format!(
                "unsupported parent ECC curve for import: {curve_id:?}"
            )))
        }
    };

    if ephemeral_point_bytes.is_empty()
        || ephemeral_point_bytes[0] != crate::crypto::UNCOMPRESSED_POINT_TAG
    {
        return Err(TpmError::Execution(
            "invalid ephemeral ECC public key format".to_string(),
        ));
    }
    let coord_len = (ephemeral_point_bytes.len() - 1) / 2;
    let x = &ephemeral_point_bytes[1..=coord_len];
    let y = &ephemeral_point_bytes[1 + coord_len..];

    Ok((
        Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice())?,
        Tpm2bData::try_from(
            build_to_vec(&TpmsEccPoint {
                x: tpm2_protocol::data::Tpm2bEccParameter::try_from(x)?,
                y: tpm2_protocol::data::Tpm2bEccParameter::try_from(y)?,
            })?
            .as_slice(),
        )?,
    ))
}

/// Creates the encrypted blobs needed for `TPM2_Import`.
///
/// This function protects the sensitive private key material for import under a
/// parent key. It secures the seed used for symmetric encryption using the
/// parent's public key (RSA-OAEP for RSA parents, ECDH for ECC parents).
///
/// # Errors
///
/// Returns a `TpmError` for cryptographic failures or invalid input.
fn create_import_blob(
    parent_public: &TpmtPublic,
    object_alg: TpmAlgId,
    private_bytes: &[u8],
    parent_name: &[u8],
) -> Result<(Tpm2bPrivate, Tpm2bEncryptedSecret, Tpm2bData), TpmError> {
    let mut seed = [0u8; 32];
    thread_rng().fill_bytes(&mut seed);
    let parent_name_alg = parent_public.name_alg;

    let (in_sym_seed, encryption_key) = match parent_public.object_type {
        TpmAlgId::Rsa => protect_seed_with_rsa(parent_public, &seed)?,
        TpmAlgId::Ecc => protect_seed_with_ecc(parent_public, &seed)?,
        _ => {
            return Err(TpmError::Execution(
                "parent key must be RSA or ECC".to_string(),
            ))
        }
    };

    let parent_name_len_bytes = u16::try_from(parent_name.len())
        .map_err(|_| TpmErrorKind::InvalidValue)?
        .to_be_bytes();

    let sym_key = kdfa(
        parent_name_alg,
        &seed,
        KDF_STORAGE,
        &parent_name_len_bytes,
        parent_name,
        128,
    )?;

    let integrity_key_bits = u16::try_from(
        tpm2_protocol::tpm_hash_size(&parent_name_alg).ok_or_else(|| {
            TpmError::Execution("parent nameAlg is not a supported hash".to_string())
        })? * 8,
    )
    .map_err(|_| TpmError::Execution("hash size conversion error".to_string()))?;

    let hmac_key = kdfa(
        parent_name_alg,
        &seed,
        KDF_INTEGRITY,
        &parent_name_len_bytes,
        parent_name,
        integrity_key_bits,
    )?;

    let sensitive =
        tpm2_protocol::data::TpmtSensitive::from_private_bytes(object_alg, private_bytes)?;
    let sensitive_data_vec = build_to_vec(&sensitive)?;

    let mut enc_data = sensitive_data_vec;
    let iv = [0u8; 16];

    let cipher = Encryptor::<Aes128>::new(sym_key.as_slice().into(), &iv.into());
    cipher.encrypt(&mut enc_data);

    macro_rules! do_integrity_hmac {
        ($digest:ty) => {{
            let mut integrity_mac =
                <hmac::Hmac<$digest> as hmac::Mac>::new_from_slice(&hmac_key)
                    .map_err(|e| TpmError::Execution(format!("HMAC init error: {e}")))?;
            integrity_mac.update(&enc_data);
            integrity_mac.update(parent_name);
            integrity_mac.finalize().into_bytes().to_vec()
        }};
    }

    let final_mac = match parent_name_alg {
        TpmAlgId::Sha256 => do_integrity_hmac!(Sha256),
        TpmAlgId::Sha384 => do_integrity_hmac!(Sha384),
        TpmAlgId::Sha512 => do_integrity_hmac!(Sha512),
        _ => {
            return Err(TpmError::Execution(format!(
                "unsupported hash algorithm for integrity HMAC: {parent_name_alg}"
            )))
        }
    };

    let duplicate_blob = {
        let mut duplicate_blob_buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut duplicate_blob_buf);
            tpm2_protocol::data::Tpm2bDigest::try_from(final_mac.as_slice())?.build(&mut writer)?;
            writer.write_bytes(&enc_data)?;
            writer.len()
        };
        duplicate_blob_buf[..len].to_vec()
    };

    Ok((
        Tpm2bPrivate::try_from(duplicate_blob.as_slice())?,
        in_sym_seed,
        encryption_key,
    ))
}

impl Command for Import {
    fn command_type(&self) -> CommandType {
        CommandType::Pipe
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("import", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, TpmError> {
        let mut args = Import::default();
        parse_args!(parser, arg, Self::help, {
            Long("key") => {
                args.key_uri = Some(parser.value()?.string()?);
            }
            Long("parent-password") => {
                args.parent_password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(TpmError::from(arg.unexpected()));
            }
        });
        if args.key_uri.is_none() {
            return Err(TpmError::Usage(
                "Missing required argument: --key <KEY_URI>".to_string(),
            ));
        }
        Ok(Commands::Import(args))
    }

    /// Runs `import`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError`.
    #[allow(clippy::too_many_lines)]
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), TpmError> {
        let device_arc =
            device.ok_or_else(|| TpmError::Execution("TPM device not provided".to_string()))?;

        let parent_obj = io
            .get_active_object()?
            .as_tpm()
            .ok_or_else(|| TpmError::Execution("Pipeline missing parent 'tpm' object".to_string()))?
            .clone();
        let parent_handle_guard = io.resolve_tpm_context(device_arc.clone(), &parent_obj)?;
        let parent_handle = parent_handle_guard.handle();

        let (parent_public, parent_name) = read_public(Some(device_arc.clone()), parent_handle)?;
        let parent_name_alg = parent_public.name_alg;

        let key_uri_str = self.key_uri.as_ref().unwrap();
        let key_url = Url::parse(key_uri_str)?;
        if key_url.scheme() != "file" {
            return Err(TpmError::Usage(
                "Key URI must use the 'file://' scheme".to_string(),
            ));
        }
        let private_key_path = key_url
            .to_file_path()
            .map_err(|()| TpmError::Parse("Invalid file path in URI".to_string()))?;

        let private_key = PrivateKey::from_pem_file(&private_key_path)?;
        let public = private_key.to_tpmt_public(parent_name_alg)?;
        let public_bytes_struct = Tpm2bPublic {
            inner: public.clone(),
        };
        let private_bytes_blob = private_key.get_sensitive_blob()?;

        let (duplicate, in_sym_seed, encryption_key) = create_import_blob(
            &parent_public,
            public.object_type,
            &private_bytes_blob,
            &parent_name,
        )?;

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
        let sessions = get_auth_sessions(
            &import_cmd,
            &handles,
            None,
            self.parent_password.password.as_deref(),
        )?;

        let (resp, _) = {
            let mut chip = device_arc
                .lock()
                .map_err(|_| TpmError::Execution("TPM device lock poisoned".to_string()))?;
            chip.execute(&import_cmd, &sessions)?
        };
        let import_resp = resp.Import().map_err(|e| {
            TpmError::Execution(format!("unexpected response type for Import: {e:?}"))
        })?;

        let pub_key_bytes = build_to_vec(&Tpm2bPublic { inner: public })?;
        let priv_key_bytes = build_to_vec(&import_resp.out_private)?;

        let new_key = Key {
            public: format!("data://base64,{}", base64_engine.encode(pub_key_bytes)),
            private: format!("data://base64,{}", base64_engine.encode(priv_key_bytes)),
        };

        io.push_object(PipelineObject::Key(new_key));
        Ok(())
    }
}

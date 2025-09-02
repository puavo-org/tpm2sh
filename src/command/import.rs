// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, Import},
    crypto::{
        crypto_ecdh_p256, crypto_ecdh_p384, crypto_ecdh_p521, crypto_hmac, crypto_kdfa,
        crypto_make_name, PrivateKey, KDF_LABEL_DUPLICATE, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE,
        UNCOMPRESSED_POINT_TAG,
    },
    key::private_key_from_pem_bytes,
    session::session_from_args,
    uri::Uri,
    util::build_to_vec,
    CliError, TpmDevice,
};
use aes::Aes128;
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use num_traits::FromPrimitive;
use rand::{thread_rng, RngCore};
use rsa::{Oaep, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use std::io::Write;
use tpm2_protocol::{
    data::{
        Tpm2bData, Tpm2bEncryptedSecret, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmEccCurve,
        TpmsEccPoint, TpmtPublic, TpmtSymDef, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits,
        TpmuSymMode,
    },
    message::TpmImportCommand,
    TpmBuild, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

/// Encrypts the import seed using the parent's RSA public key.
///
/// See Table 27 in TCG TPM 2.0 Architectures specification for more information.
fn protect_seed_with_rsa(
    parent_public: &TpmtPublic,
    seed: &[u8; 32],
) -> Result<(Tpm2bEncryptedSecret, Tpm2bData), CliError> {
    let n = match &parent_public.unique {
        TpmuPublicId::Rsa(data) => Ok(data.as_ref()),
        _ => Err(CliError::Execution("RSA: invalid unique".to_string())),
    }?;
    let e_raw = match &parent_public.parameters {
        TpmuPublicParms::Rsa(params) => Ok(params.exponent),
        _ => Err(CliError::Execution("RSA: invalid parameters".to_string())),
    }?;
    let e = if e_raw == 0 { 65537 } else { e_raw };
    let rsa_pub_key = RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_u32(e)
            .ok_or_else(|| CliError::Execution("RSA: invalid integer conversion".to_string()))?,
    )
    .map_err(|e| CliError::Execution(format!("RSA: invalid public key: {e}")))?;

    let mut rng = thread_rng();
    let parent_name_alg = parent_public.name_alg;

    let encrypted_seed_result = match parent_name_alg {
        TpmAlgId::Sha1 => rsa_pub_key.encrypt(
            &mut rng,
            Oaep::new_with_label::<Sha1, _>(KDF_LABEL_DUPLICATE),
            seed,
        ),
        TpmAlgId::Sha256 => rsa_pub_key.encrypt(
            &mut rng,
            Oaep::new_with_label::<Sha256, _>(KDF_LABEL_DUPLICATE),
            seed,
        ),
        TpmAlgId::Sha384 => rsa_pub_key.encrypt(
            &mut rng,
            Oaep::new_with_label::<Sha384, _>(KDF_LABEL_DUPLICATE),
            seed,
        ),
        TpmAlgId::Sha512 => rsa_pub_key.encrypt(
            &mut rng,
            Oaep::new_with_label::<Sha512, _>(KDF_LABEL_DUPLICATE),
            seed,
        ),
        _ => {
            return Err(CliError::Execution(format!(
                "RSA-OAEP: unsupported nameAlg: {parent_name_alg:?}"
            )));
        }
    };
    let encrypted_seed = encrypted_seed_result
        .map_err(|e| CliError::Execution(format!("RSA-OAEP: encryption failed: {e}")))?;

    Ok((
        Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice())?,
        Tpm2bData::default(),
    ))
}

/// Encrypts the import seed using an ECDH shared secret derived from the parent's ECC public key.
fn protect_seed_with_ecc(
    parent_public: &TpmtPublic,
    seed: &[u8; 32],
) -> Result<(Tpm2bEncryptedSecret, Tpm2bData), CliError> {
    let (parent_point, curve_id) = match (&parent_public.unique, &parent_public.parameters) {
        (TpmuPublicId::Ecc(point), TpmuPublicParms::Ecc(params)) => Ok((point, params.curve_id)),
        _ => Err(CliError::Execution(
            "parent is not a valid ECC key".to_string(),
        )),
    }?;

    let (encrypted_seed, ephemeral_point_bytes) =
        match curve_id {
            TpmEccCurve::NistP256 => crypto_ecdh_p256(parent_point, parent_public.name_alg, seed)
                .map_err(CliError::TpmRc)?,
            TpmEccCurve::NistP384 => crypto_ecdh_p384(parent_point, parent_public.name_alg, seed)
                .map_err(CliError::TpmRc)?,
            TpmEccCurve::NistP521 => crypto_ecdh_p521(parent_point, parent_public.name_alg, seed)
                .map_err(CliError::TpmRc)?,
            _ => {
                return Err(CliError::Execution(format!(
                    "unsupported parent ECC curve for import: {curve_id:?}"
                )))
            }
        };

    if ephemeral_point_bytes.is_empty() || ephemeral_point_bytes[0] != UNCOMPRESSED_POINT_TAG {
        return Err(CliError::Execution(
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
            return Err(CliError::Execution(
                "parent key must be RSA or ECC".to_string(),
            ))
        }
    };

    let object_name = crypto_make_name(object_public).map_err(CliError::TpmRc)?;

    let sym_key = crypto_kdfa(
        parent_name_alg,
        &seed,
        KDF_LABEL_STORAGE,
        &object_name,
        parent_name,
        128,
    )
    .map_err(CliError::TpmRc)?;

    let integrity_key_bits = u16::try_from(
        tpm2_protocol::tpm_hash_size(&parent_name_alg).ok_or_else(|| {
            CliError::Execution("parent nameAlg is not a supported hash".to_string())
        })? * 8,
    )
    .map_err(|_| CliError::Execution("hash size conversion error".to_string()))?;

    let hmac_key = crypto_kdfa(
        parent_name_alg,
        &seed,
        KDF_LABEL_INTEGRITY,
        parent_name,
        &[],
        integrity_key_bits,
    )
    .map_err(CliError::TpmRc)?;

    let sensitive = tpm2_protocol::data::TpmtSensitive::from_private_bytes(
        object_public.object_type,
        private_bytes,
    )?;
    let sensitive_data_vec = build_to_vec(&sensitive)?;

    let mut enc_data = sensitive_data_vec;
    let iv = [0u8; 16];

    let cipher = Encryptor::<Aes128>::new(sym_key.as_slice().into(), &iv.into());
    cipher.encrypt(&mut enc_data);

    let final_mac = crypto_hmac(parent_name_alg, &hmac_key, &[&enc_data, parent_name])
        .map_err(CliError::TpmRc)?;

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

/// Parses an external key from a URI and prepares it for TPM import.
fn prepare_key_for_import(
    key: &Uri,
    parent_name_alg: TpmAlgId,
) -> Result<(PrivateKey, TpmtPublic, Vec<u8>), CliError> {
    let pem_bytes = key.to_bytes()?;
    let private_key = private_key_from_pem_bytes(&pem_bytes)?;

    let public = private_key
        .to_public(parent_name_alg)
        .map_err(CliError::TpmRc)?;
    let sensitive_blob = private_key.sensitive_blob();

    Ok((private_key, public, sensitive_blob))
}

impl DeviceCommand for Import {
    /// Runs `import`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError`.
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: &mut TpmDevice,
        writer: &mut W,
    ) -> Result<crate::Resources, CliError> {
        let (parent_handle, needs_flush) = device.context_load(&self.parent.parent)?;
        let handles_to_flush = if needs_flush {
            vec![parent_handle]
        } else {
            Vec::new()
        };
        let (parent_public, parent_name) = device.read_public(parent_handle)?;
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
        let sessions = session_from_args(&import_cmd, &handles, cli)?;
        let (resp, _) = device.execute(&import_cmd, &sessions)?;
        let import_resp = resp.Import().map_err(|e| {
            CliError::Execution(format!("unexpected response type for Import: {e:?}"))
        })?;
        let pub_key_bytes = build_to_vec(&Tpm2bPublic { inner: public })?;
        let priv_key_bytes = build_to_vec(&import_resp.out_private)?;
        writeln!(
            writer,
            "data://base64,{}",
            base64_engine.encode(pub_key_bytes)
        )?;
        writeln!(
            writer,
            "data://base64,{}",
            base64_engine.encode(priv_key_bytes)
        )?;
        let handles = handles_to_flush.into_iter().map(|h| (h, true)).collect();
        Ok(crate::Resources::new(handles))
    }
}

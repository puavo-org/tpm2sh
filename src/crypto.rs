// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This file contains cryptographic algorithms shared by tpm2sh and `MockTPM`.

use crate::util::{self, TpmErrorKindExt};
use aes::Aes128;
use cfb_mode::Encryptor;
use cipher::{AsyncStreamCipher, KeyIvInit};
use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
use hmac::{Hmac, Mac};
use num_traits::FromPrimitive;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::SecretKey;
use pkcs8::{
    der::{self, asn1::AnyRef, Decode, Encode},
    EncodePrivateKey, ObjectIdentifier, PrivateKeyInfo,
};
use rand::{thread_rng, CryptoRng, RngCore};
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    Oaep, RsaPrivateKey,
};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use tpm2_protocol::data::{
    Tpm2bData, Tpm2bDigest, Tpm2bEccParameter, Tpm2bEncryptedSecret, Tpm2bPublicKeyRsa, TpmAlgId,
    TpmEccCurve, TpmRc, TpmRcBase, TpmaObject, TpmsEccParms, TpmsEccPoint, TpmsRsaParms,
    TpmtKdfScheme, TpmtPublic, TpmtScheme, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms,
};

pub const ID_LOADABLE_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.10.1.3");
pub const ID_IMPORTABLE_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.10.1.4");
pub const ID_SEALED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.10.1.5");
pub const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

pub const KDF_LABEL_DUPLICATE: &str = "DUPLICATE";
pub const KDF_LABEL_INTEGRITY: &str = "INTEGRITY";
pub const KDF_LABEL_STORAGE: &str = "STORAGE";

/// Computes an HMAC digest over a series of data chunks.
///
/// # Errors
///
/// Returns a `TpmRc` error if the key is invalid or the algorithm is unsupported.
pub fn crypto_hmac(alg: TpmAlgId, key: &[u8], data_chunks: &[&[u8]]) -> Result<Vec<u8>, TpmRc> {
    macro_rules! hmac {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(key)
                .map_err(|_| TpmRc::from(TpmRcBase::Value))?;
            for chunk in data_chunks {
                mac.update(chunk);
            }
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }

    match alg {
        TpmAlgId::Sha256 => hmac!(Sha256),
        TpmAlgId::Sha384 => hmac!(Sha384),
        TpmAlgId::Sha512 => hmac!(Sha512),
        _ => Err(TpmRc::from(TpmRcBase::Hash)),
    }
}

/// Verifies an HMAC signature over a series of data chunks.
///
/// # Errors
///
/// Returns a `TpmRc` error if the key is invalid, the algorithm is unsupported,
/// or the signature does not match.
pub fn crypto_hmac_verify(
    alg: TpmAlgId,
    key: &[u8],
    data_chunks: &[&[u8]],
    signature: &[u8],
) -> Result<(), TpmRc> {
    macro_rules! verify_hmac {
        ($digest:ty) => {{
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(key)
                .map_err(|_| TpmRc::from(TpmRcBase::Value))?;
            for chunk in data_chunks {
                mac.update(chunk);
            }
            mac.verify_slice(signature)
                .map_err(|_| TpmRc::from(TpmRcBase::Integrity))
        }};
    }

    match alg {
        TpmAlgId::Sha256 => verify_hmac!(Sha256),
        TpmAlgId::Sha384 => verify_hmac!(Sha384),
        TpmAlgId::Sha512 => verify_hmac!(Sha512),
        _ => Err(TpmRc::from(TpmRcBase::Hash)),
    }
}

/// Implements the `KDFa` key derivation function from the TPM specification.
///
/// # Errors
///
/// Returns a `TpmRc` error on failure.
pub fn crypto_kdfa(
    auth_hash: TpmAlgId,
    hmac_key: &[u8],
    label: &str,
    context_a: &[u8],
    context_b: &[u8],
    key_bits: u16,
) -> Result<Vec<u8>, TpmRc> {
    let mut key_stream = Vec::new();
    let key_bytes = (key_bits as usize).div_ceil(8);
    let label_bytes = {
        let mut bytes = label.as_bytes().to_vec();
        bytes.push(0);
        bytes
    };

    let mut counter: u32 = 1;
    while key_stream.len() < key_bytes {
        let counter_bytes = counter.to_be_bytes();
        let key_bits_bytes = u32::from(key_bits).to_be_bytes();
        let hmac_payload = [
            counter_bytes.as_slice(),
            label_bytes.as_slice(),
            context_a,
            context_b,
            key_bits_bytes.as_slice(),
        ];

        let result = crypto_hmac(auth_hash, hmac_key, &hmac_payload)?;
        let remaining = key_bytes - key_stream.len();
        let to_take = remaining.min(result.len());
        key_stream.extend_from_slice(&result[..to_take]);

        counter += 1;
    }

    Ok(key_stream)
}

/// A trait to abstract RSA OAEP encryption over different hash algorithms.
///
/// # Errors
///
/// Returns a `TpmRc` error on failure.
trait TpmRsaOaepEncrypt {
    fn oaep_encrypt(
        key: &rsa::RsaPublicKey,
        rng: &mut (impl CryptoRng + RngCore),
        label: &str,
        data: &[u8],
    ) -> rsa::Result<Vec<u8>>;
}

impl TpmRsaOaepEncrypt for Sha1 {
    fn oaep_encrypt(
        key: &rsa::RsaPublicKey,
        rng: &mut (impl CryptoRng + RngCore),
        label: &str,
        data: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        key.encrypt(rng, Oaep::new_with_label::<Sha1, _>(label), data)
    }
}

impl TpmRsaOaepEncrypt for Sha256 {
    fn oaep_encrypt(
        key: &rsa::RsaPublicKey,
        rng: &mut (impl CryptoRng + RngCore),
        label: &str,
        data: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        key.encrypt(rng, Oaep::new_with_label::<Sha256, _>(label), data)
    }
}

impl TpmRsaOaepEncrypt for Sha384 {
    fn oaep_encrypt(
        key: &rsa::RsaPublicKey,
        rng: &mut (impl CryptoRng + RngCore),
        label: &str,
        data: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        key.encrypt(rng, Oaep::new_with_label::<Sha384, _>(label), data)
    }
}

impl TpmRsaOaepEncrypt for Sha512 {
    fn oaep_encrypt(
        key: &rsa::RsaPublicKey,
        rng: &mut (impl CryptoRng + RngCore),
        label: &str,
        data: &[u8],
    ) -> rsa::Result<Vec<u8>> {
        key.encrypt(rng, Oaep::new_with_label::<Sha512, _>(label), data)
    }
}

/// Dispatches RSA OAEP encryption based on the `TpmAlgId`.
fn dispatch_rsa_oaep_encrypt(
    key: &rsa::RsaPublicKey,
    rng: &mut (impl CryptoRng + RngCore),
    name_alg: TpmAlgId,
    label: &str,
    data: &[u8],
) -> Result<Vec<u8>, TpmRc> {
    match name_alg {
        TpmAlgId::Sha1 => Sha1::oaep_encrypt(key, rng, label, data),
        TpmAlgId::Sha256 => Sha256::oaep_encrypt(key, rng, label, data),
        TpmAlgId::Sha384 => Sha384::oaep_encrypt(key, rng, label, data),
        TpmAlgId::Sha512 => Sha512::oaep_encrypt(key, rng, label, data),
        _ => return Err(TpmRc::from(TpmRcBase::Scheme)),
    }
    .map_err(|_| TpmRc::from(TpmRcBase::Value))
}

/// Encrypts the import seed using the parent's RSA public key.
///
/// See Table 27 in TCG TPM 2.0 Architectures specification for more information.
///
/// # Errors
///
/// Returns a `TpmRc` error on failure.
pub fn protect_seed_with_rsa(
    parent_public: &TpmtPublic,
    seed: &[u8; 32],
) -> Result<(Tpm2bEncryptedSecret, Tpm2bData), TpmRc> {
    let n = match &parent_public.unique {
        TpmuPublicId::Rsa(data) => Ok(data.as_ref()),
        _ => Err(TpmRc::from(TpmRcBase::Key)),
    }?;
    let e_raw = match &parent_public.parameters {
        TpmuPublicParms::Rsa(params) => Ok(params.exponent),
        _ => Err(TpmRc::from(TpmRcBase::Key)),
    }?;
    let e = if e_raw == 0 { 65537 } else { e_raw };
    let rsa_pub_key = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(n),
        rsa::BigUint::from_u32(e).ok_or(TpmRc::from(TpmRcBase::Value))?,
    )
    .map_err(|_| TpmRc::from(TpmRcBase::Value))?;

    let mut rng = thread_rng();
    let encrypted_seed = dispatch_rsa_oaep_encrypt(
        &rsa_pub_key,
        &mut rng,
        parent_public.name_alg,
        KDF_LABEL_DUPLICATE,
        seed,
    )?;

    Ok((
        Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice())
            .map_err(TpmErrorKindExt::to_tpm_rc)?,
        Tpm2bData::default(),
    ))
}

/// Encrypts the import seed using an ECDH shared secret derived from the parent's ECC public key.
///
/// # Errors
///
/// Returns a `TpmRc` error on failure.
pub fn protect_seed_with_ecc(
    parent_public: &TpmtPublic,
    seed: &[u8; 32],
) -> Result<(Tpm2bEncryptedSecret, Tpm2bData), TpmRc> {
    let (parent_point, curve_id) = match (&parent_public.unique, &parent_public.parameters) {
        (TpmuPublicId::Ecc(point), TpmuPublicParms::Ecc(params)) => Ok((point, params.curve_id)),
        _ => Err(TpmRc::from(TpmRcBase::Key)),
    }?;

    let (encrypted_seed, ephemeral_point_bytes) = match curve_id {
        TpmEccCurve::NistP256 => crypto_ecdh_p256(parent_point, parent_public.name_alg, seed)?,
        TpmEccCurve::NistP384 => crypto_ecdh_p384(parent_point, parent_public.name_alg, seed)?,
        TpmEccCurve::NistP521 => crypto_ecdh_p521(parent_point, parent_public.name_alg, seed)?,
        _ => return Err(TpmRc::from(TpmRcBase::Curve)),
    };

    if ephemeral_point_bytes.is_empty() || ephemeral_point_bytes[0] != UNCOMPRESSED_POINT_TAG {
        return Err(TpmRc::from(TpmRcBase::Value));
    }
    let coord_len = (ephemeral_point_bytes.len() - 1) / 2;
    let x = &ephemeral_point_bytes[1..=coord_len];
    let y = &ephemeral_point_bytes[1 + coord_len..];

    Ok((
        Tpm2bEncryptedSecret::try_from(encrypted_seed.as_slice())
            .map_err(TpmErrorKindExt::to_tpm_rc)?,
        Tpm2bData::try_from(
            util::build_to_vec(&TpmsEccPoint {
                x: Tpm2bEccParameter::try_from(x).map_err(TpmErrorKindExt::to_tpm_rc)?,
                y: Tpm2bEccParameter::try_from(y).map_err(TpmErrorKindExt::to_tpm_rc)?,
            })
            .map_err(|_| TpmRc::from(TpmRcBase::Value))?
            .as_slice(),
        )
        .map_err(TpmErrorKindExt::to_tpm_rc)?,
    ))
}

macro_rules! ecdh {
    (
        $vis:vis $fn_name:ident,
        $pk_ty:ty, $sk_ty:ty, $affine_ty:ty, $dh_fn:path, $encoded_point_ty:ty
    ) => {
        #[allow(clippy::similar_names, clippy::missing_errors_doc)]
        $vis fn $fn_name(
            parent_point: &TpmsEccPoint,
            name_alg: TpmAlgId,
            seed: &[u8; 32],
        ) -> Result<(Vec<u8>, Vec<u8>), TpmRc> {
            let encoded_point = <$encoded_point_ty>::from_affine_coordinates(
                parent_point.x.as_ref().into(),
                parent_point.y.as_ref().into(),
                false,
            );
            let affine_point_opt: Option<$affine_ty> =
                <$affine_ty>::from_encoded_point(&encoded_point).into();
            let affine_point = affine_point_opt.ok_or(TpmRc::from(TpmRcBase::EccPoint))?;

            if affine_point.is_identity().into() {
                return Err(TpmRc::from(TpmRcBase::EccPoint));
            }

            let parent_pk =
                <$pk_ty>::from_affine(affine_point).map_err(|_| TpmRc::from(TpmRcBase::Value))?;

            let context_b: Vec<u8> = [parent_point.x.as_ref(), parent_point.y.as_ref()].concat();

            let ephemeral_sk = <$sk_ty>::random(&mut rand::thread_rng());
            let ephemeral_pk_bytes_encoded = ephemeral_sk.public_key().to_encoded_point(false);
            let ephemeral_pk_bytes = ephemeral_pk_bytes_encoded.as_bytes();
            if ephemeral_pk_bytes.is_empty() || ephemeral_pk_bytes[0] != UNCOMPRESSED_POINT_TAG {
                return Err(TpmRc::from(TpmRcBase::Value));
            }
            let context_a = &ephemeral_pk_bytes[1..];

            let shared_secret = $dh_fn(ephemeral_sk.to_nonzero_scalar(), parent_pk.as_affine());
            let z = shared_secret.raw_secret_bytes();
            let sym_material =
                crypto_kdfa(name_alg, &z, KDF_LABEL_STORAGE, context_a, &context_b, 256)?;
            let (aes_key, iv) = sym_material.split_at(16);
            let mut encrypted_seed_buf = *seed;
            let cipher = Encryptor::<Aes128>::new(aes_key.into(), iv.into());
            cipher.encrypt(&mut encrypted_seed_buf);

            Ok((encrypted_seed_buf.to_vec(), ephemeral_pk_bytes.to_vec()))
        }
    };
}

ecdh!(
    pub crypto_ecdh_p256,
    p256::PublicKey,
    p256::SecretKey,
    p256::AffinePoint,
    p256::ecdh::diffie_hellman,
    p256::EncodedPoint
);

ecdh!(
    pub crypto_ecdh_p384,
    p384::PublicKey,
    p384::SecretKey,
    p384::AffinePoint,
    p384::ecdh::diffie_hellman,
    p384::EncodedPoint
);

ecdh!(
    pub crypto_ecdh_p521,
    p521::PublicKey,
    p521::SecretKey,
    p521::AffinePoint,
    p521::ecdh::diffie_hellman,
    p521::EncodedPoint
);

/// Calculates the TPM name of a public object.
///
/// # Errors
///
/// Returns a `TpmRc` error on failure.
pub fn crypto_make_name(public: &TpmtPublic) -> Result<Vec<u8>, TpmRc> {
    let mut name_buf = Vec::new();
    let name_alg = public.name_alg;
    name_buf.extend_from_slice(&(name_alg as u16).to_be_bytes());
    let public_area_bytes =
        util::build_to_vec(public).map_err(|_| TpmRc::from(TpmRcBase::Value))?;
    let digest: Vec<u8> = match name_alg {
        TpmAlgId::Sha256 => Sha256::digest(&public_area_bytes).to_vec(),
        TpmAlgId::Sha384 => Sha384::digest(&public_area_bytes).to_vec(),
        TpmAlgId::Sha512 => Sha512::digest(&public_area_bytes).to_vec(),
        _ => return Err(TpmRc::from(TpmRcBase::Hash)),
    };
    name_buf.extend_from_slice(&digest);
    Ok(name_buf)
}

/// RSA or ECC private key
#[derive(Clone)]
pub enum PrivateKey {
    Rsa(Box<RsaPrivateKey>),
    Ecc(SecretKey),
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rsa(key) => f.debug_tuple("Rsa").field(key).finish(),
            Self::Ecc(key) => f.debug_tuple("Ecc").field(key).finish(),
        }
    }
}

impl PrivateKey {
    /// Converts key to `TpmtPublic`.
    ///
    /// Implementation note: according to TCG TPM 2.0 Structures specification,
    /// exponent zero maps to the default RSA exponent 65537, and the support
    /// for other values is optional.
    ///
    /// # Errors
    ///
    /// Returns a `TpmRc` on failure.
    pub fn to_public(&self, hash_alg: TpmAlgId) -> Result<TpmtPublic, TpmRc> {
        match self {
            PrivateKey::Rsa(rsa_key) => {
                let modulus_bytes = rsa_key.n().to_bytes_be();
                let key_bits = u16::try_from(modulus_bytes.len() * 8)
                    .map_err(|_| TpmRc::from(TpmRcBase::KeySize))?;

                let exponent = {
                    let e_bytes = rsa_key.e().to_bytes_be();
                    if e_bytes.len() > 4 {
                        return Err(TpmRc::from(TpmRcBase::Value));
                    }
                    let mut buf = [0u8; 4];
                    buf[4 - e_bytes.len()..].copy_from_slice(&e_bytes);
                    u32::from_be_bytes(buf)
                };

                let exponent = if exponent == 65537 {
                    0
                } else {
                    return Err(TpmRc::from(TpmRcBase::Value));
                };

                Ok(TpmtPublic {
                    object_type: TpmAlgId::Rsa,
                    name_alg: hash_alg,
                    object_attributes: TpmaObject::RESTRICTED
                        | TpmaObject::DECRYPT
                        | TpmaObject::USER_WITH_AUTH,
                    auth_policy: Tpm2bDigest::default(),
                    parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                        symmetric: TpmtSymDefObject::default(),
                        scheme: TpmtScheme::default(),
                        key_bits,
                        exponent,
                    }),
                    unique: TpmuPublicId::Rsa(
                        Tpm2bPublicKeyRsa::try_from(modulus_bytes.as_slice())
                            .map_err(|_| TpmRc::from(TpmRcBase::Value))?,
                    ),
                })
            }
            PrivateKey::Ecc(secret_key) => {
                let encoded_point = secret_key.public_key().to_encoded_point(false);
                let pub_bytes = encoded_point.as_bytes();

                if pub_bytes.is_empty() || pub_bytes[0] != UNCOMPRESSED_POINT_TAG {
                    return Err(TpmRc::from(TpmRcBase::Value));
                }

                let coord_len = (pub_bytes.len() - 1) / 2;
                let x = &pub_bytes[1..=coord_len];
                let y = &pub_bytes[1 + coord_len..];

                let der_bytes = secret_key
                    .to_pkcs8_der()
                    .map_err(|_| TpmRc::from(TpmRcBase::Value))?;
                let pki = PrivateKeyInfo::from_der(der_bytes.as_bytes())
                    .map_err(|_| TpmRc::from(TpmRcBase::Value))?;
                let Some(params) = pki.algorithm.parameters.as_ref() else {
                    return Err(TpmRc::from(TpmRcBase::Value));
                };

                let curve_id = ec_oid_to_tpm_curve(params)?;

                Ok(TpmtPublic {
                    object_type: TpmAlgId::Ecc,
                    name_alg: hash_alg,
                    object_attributes: TpmaObject::RESTRICTED
                        | TpmaObject::DECRYPT
                        | TpmaObject::USER_WITH_AUTH,
                    auth_policy: Tpm2bDigest::default(),
                    parameters: TpmuPublicParms::Ecc(TpmsEccParms {
                        symmetric: TpmtSymDefObject::default(),
                        scheme: TpmtScheme::default(),
                        curve_id,
                        kdf: TpmtKdfScheme::default(),
                    }),
                    unique: TpmuPublicId::Ecc(TpmsEccPoint {
                        x: Tpm2bEccParameter::try_from(x)
                            .map_err(|_| TpmRc::from(TpmRcBase::Value))?,
                        y: Tpm2bEccParameter::try_from(y)
                            .map_err(|_| TpmRc::from(TpmRcBase::Value))?,
                    }),
                })
            }
        }
    }

    /// Returns the sensitive part of the private key required for import.
    #[must_use]
    pub fn sensitive_blob(&self) -> Vec<u8> {
        match self {
            PrivateKey::Rsa(rsa_key) => rsa_key.primes()[0].to_bytes_be(),
            PrivateKey::Ecc(secret_key) => secret_key.to_bytes().to_vec(),
        }
    }
}

/// Convert ECC curve OID from DER `AnyRef` to TPM curve enum.
fn ec_oid_to_tpm_curve(any: &AnyRef) -> Result<TpmEccCurve, TpmRc> {
    let der_bytes = any.to_der().map_err(|_| TpmRc::from(TpmRcBase::Value))?;
    let mut reader =
        der::SliceReader::new(&der_bytes).map_err(|_| TpmRc::from(TpmRcBase::Value))?;
    let oid = ObjectIdentifier::decode(&mut reader).map_err(|_| TpmRc::from(TpmRcBase::Value))?;
    match oid {
        SECP_256_R_1 => Ok(TpmEccCurve::NistP256),
        SECP_384_R_1 => Ok(TpmEccCurve::NistP384),
        SECP_521_R_1 => Ok(TpmEccCurve::NistP521),
        _ => Err(TpmRc::from(TpmRcBase::Curve)),
    }
}

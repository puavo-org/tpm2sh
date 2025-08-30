// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This file contains cryptographic algorithms shared by tpm2sh and `MockTPM`.

use crate::util;

use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
use hmac::{Hmac, Mac};
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use pkcs8::{
    der::{self, asn1::AnyRef, Decode, Encode},
    EncodePrivateKey, ObjectIdentifier, PrivateKeyInfo,
};
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use tpm2_protocol::data::{
    Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmAlgId, TpmEccCurve, TpmRc, TpmRcBase,
    TpmaObject, TpmsEccParms, TpmsEccPoint, TpmsRsaParms, TpmtKdfScheme, TpmtPublic, TpmtScheme,
    TpmtSymDefObject, TpmuPublicId, TpmuPublicParms,
};

pub const ID_IMPORTABLE_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.4");
pub const ID_SEALED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.5");
pub const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

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
#[allow(clippy::large_enum_variant)]
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ecc(SecretKey),
}

impl Clone for PrivateKey {
    fn clone(&self) -> Self {
        match self {
            Self::Rsa(key) => Self::Rsa(key.clone()),
            Self::Ecc(key) => Self::Ecc(key.clone())
        }
    }
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

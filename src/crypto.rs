// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! This file contains cryptographic algorithms shared by tpm2sh and `MockTPM`.

use crate::util;
use hmac::{Hmac, Mac};
use pkcs8::ObjectIdentifier;
use sha2::{Digest, Sha256, Sha384, Sha512};
use tpm2_protocol::data::{TpmAlgId, TpmRc, TpmRcBase, TpmtPublic};

pub const ID_IMPORTABLE_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.4");
pub const ID_SEALED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.5");

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

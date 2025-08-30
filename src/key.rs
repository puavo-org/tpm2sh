// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::CliError;
use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
use hmac::{Hmac, Mac};
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use pkcs8::{
    der::{
        self,
        asn1::{AnyRef, OctetString},
        Decode, DecodeValue, Encode, EncodeValue, Reader, Sequence, Writer,
    },
    DecodePrivateKey, EncodePrivateKey, ObjectIdentifier, PrivateKeyInfo,
};
use rsa::{
    traits::{PrivateKeyParts, PublicKeyParts},
    RsaPrivateKey,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{cmp::Ordering, str::FromStr};
use tpm2_protocol::data::{
    Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmAlgId, TpmCc, TpmEccCurve, TpmaObject,
    TpmsAuthCommand, TpmsEccParms, TpmsEccPoint, TpmsRsaParms, TpmtKdfScheme, TpmtPublic,
    TpmtScheme, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms,
};

pub const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlgInfo {
    Rsa { key_bits: u16 },
    Ecc { curve_id: TpmEccCurve },
    KeyedHash,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Alg {
    pub name: String,
    pub object_type: TpmAlgId,
    pub name_alg: TpmAlgId,
    pub params: AlgInfo,
}

impl Default for Alg {
    fn default() -> Self {
        Self {
            name: String::new(),
            object_type: TpmAlgId::Null,
            name_alg: TpmAlgId::Null,
            params: AlgInfo::KeyedHash,
        }
    }
}

impl FromStr for Alg {
    type Err = CliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.as_slice() {
            ["rsa", key_bits_str, name_alg_str] => {
                let key_bits: u16 = key_bits_str.parse().map_err(|_| {
                    CliError::Usage(format!("Invalid RSA key bits value: '{key_bits_str}'"))
                })?;
                let name_alg =
                    crate::key::tpm_alg_id_from_str(name_alg_str).map_err(CliError::Usage)?;
                Ok(Self {
                    name: s.to_string(),
                    object_type: TpmAlgId::Rsa,
                    name_alg,
                    params: AlgInfo::Rsa { key_bits },
                })
            }
            ["ecc", curve_id_str, name_alg_str] => {
                let curve_id =
                    crate::key::tpm_ecc_curve_from_str(curve_id_str).map_err(CliError::Usage)?;
                let name_alg =
                    crate::key::tpm_alg_id_from_str(name_alg_str).map_err(CliError::Usage)?;
                Ok(Self {
                    name: s.to_string(),
                    object_type: TpmAlgId::Ecc,
                    name_alg,
                    params: AlgInfo::Ecc { curve_id },
                })
            }
            ["keyedhash", name_alg_str] => {
                let name_alg =
                    crate::key::tpm_alg_id_from_str(name_alg_str).map_err(CliError::Usage)?;
                Ok(Self {
                    name: s.to_string(),
                    object_type: TpmAlgId::KeyedHash,
                    name_alg,
                    params: AlgInfo::KeyedHash,
                })
            }
            _ => Err(CliError::Usage(format!("Invalid algorithm format: '{s}'"))),
        }
    }
}

impl Ord for Alg {
    fn cmp(&self, other: &Self) -> Ordering {
        self.name.cmp(&other.name)
    }
}

impl PartialOrd for Alg {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Converts a user-friendly string to a `TpmAlgId`.
pub(crate) fn tpm_alg_id_from_str(s: &str) -> Result<TpmAlgId, String> {
    match s {
        "rsa" => Ok(TpmAlgId::Rsa),
        "sha1" => Ok(TpmAlgId::Sha1),
        "hmac" => Ok(TpmAlgId::Hmac),
        "aes" => Ok(TpmAlgId::Aes),
        "keyedhash" => Ok(TpmAlgId::KeyedHash),
        "xor" => Ok(TpmAlgId::Xor),
        "sha256" => Ok(TpmAlgId::Sha256),
        "sha384" => Ok(TpmAlgId::Sha384),
        "sha512" => Ok(TpmAlgId::Sha512),
        "null" => Ok(TpmAlgId::Null),
        "sm3_256" => Ok(TpmAlgId::Sm3_256),
        "sm4" => Ok(TpmAlgId::Sm4),
        "ecc" => Ok(TpmAlgId::Ecc),
        _ => Err(format!("Unsupported algorithm '{s}'")),
    }
}

/// Converts a `TpmAlgId` to its user-friendly string representation.
pub(crate) fn tpm_alg_id_to_str(alg: TpmAlgId) -> &'static str {
    match alg {
        TpmAlgId::Sha1 => "sha1",
        TpmAlgId::Sha256 => "sha256",
        TpmAlgId::Sha384 => "sha384",
        TpmAlgId::Sha512 => "sha512",
        TpmAlgId::Rsa => "rsa",
        TpmAlgId::Hmac => "hmac",
        TpmAlgId::Aes => "aes",
        TpmAlgId::KeyedHash => "keyedhash",
        TpmAlgId::Xor => "xor",
        TpmAlgId::Null => "null",
        TpmAlgId::Sm3_256 => "sm3_256",
        TpmAlgId::Sm4 => "sm4",
        TpmAlgId::Ecc => "ecc",
        _ => "unknown",
    }
}

/// Converts a user-friendly string to a `TpmEccCurve`.
pub(crate) fn tpm_ecc_curve_from_str(s: &str) -> Result<TpmEccCurve, String> {
    match s {
        "nist-p192" => Ok(TpmEccCurve::NistP192),
        "nist-p224" => Ok(TpmEccCurve::NistP224),
        "nist-p256" => Ok(TpmEccCurve::NistP256),
        "nist-p384" => Ok(TpmEccCurve::NistP384),
        "nist-p521" => Ok(TpmEccCurve::NistP521),
        _ => Err(format!("Unsupported ECC curve '{s}'")),
    }
}

/// Converts a `TpmEccCurve` to its user-friendly string representation.
pub(crate) fn tpm_ecc_curve_to_str(curve: TpmEccCurve) -> &'static str {
    match curve {
        TpmEccCurve::NistP192 => "nist-p192",
        TpmEccCurve::NistP224 => "nist-p224",
        TpmEccCurve::NistP256 => "nist-p256",
        TpmEccCurve::NistP384 => "nist-p384",
        TpmEccCurve::NistP521 => "nist-p521",
        TpmEccCurve::None => "none",
    }
}

/// Returns an iterator over all CLI-supported algorithm combinations.
pub fn enumerate_all() -> impl Iterator<Item = Alg> {
    let name_algs = [TpmAlgId::Sha256, TpmAlgId::Sha384, TpmAlgId::Sha512];
    let rsa_key_sizes = [2048, 3072, 4096];
    let ecc_curves = [
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
    ];

    let rsa_iter = rsa_key_sizes.into_iter().flat_map(move |key_bits| {
        name_algs.into_iter().map(move |name_alg| Alg {
            name: format!("rsa:{}:{}", key_bits, tpm_alg_id_to_str(name_alg)),
            object_type: TpmAlgId::Rsa,
            name_alg,
            params: AlgInfo::Rsa { key_bits },
        })
    });

    let ecc_iter = ecc_curves.into_iter().flat_map(move |curve_id| {
        name_algs.into_iter().map(move |name_alg| Alg {
            name: format!(
                "ecc:{}:{}",
                tpm_ecc_curve_to_str(curve_id),
                tpm_alg_id_to_str(name_alg)
            ),
            object_type: TpmAlgId::Ecc,
            name_alg,
            params: AlgInfo::Ecc { curve_id },
        })
    });

    let keyedhash_iter = name_algs.into_iter().map(move |name_alg| Alg {
        name: format!("keyedhash:{}", tpm_alg_id_to_str(name_alg)),
        object_type: TpmAlgId::KeyedHash,
        name_alg,
        params: AlgInfo::KeyedHash,
    });

    rsa_iter.chain(ecc_iter).chain(keyedhash_iter)
}

/// A TPM key struct that is directly compatible with ASN.1 DER encoding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TpmKey {
    pub oid: ObjectIdentifier,
    pub parent: u32,
    pub pub_key: OctetString,
    pub priv_key: OctetString,
}

impl Sequence<'_> for TpmKey {}

impl<'a> DecodeValue<'a> for TpmKey {
    fn decode_value<R: Reader<'a>>(reader: &mut R, _header: der::Header) -> der::Result<Self> {
        reader.sequence(|reader| {
            let oid = ObjectIdentifier::decode(reader)?;
            let parent = u32::decode(reader)?;
            let pub_key = OctetString::decode(reader)?;
            let priv_key = OctetString::decode(reader)?;
            Ok(Self {
                oid,
                parent,
                pub_key,
                priv_key,
            })
        })
    }
}

impl EncodeValue for TpmKey {
    fn value_len(&self) -> der::Result<der::Length> {
        self.oid.encoded_len()?
            + self.parent.encoded_len()?
            + self.pub_key.encoded_len()?
            + self.priv_key.encoded_len()?
    }

    fn encode_value(&self, writer: &mut impl Writer) -> der::Result<()> {
        self.oid.encode(writer)?;
        self.parent.encode(writer)?;
        self.pub_key.encode(writer)?;
        self.priv_key.encode(writer)?;
        Ok(())
    }
}

/// RSA or ECC private key
#[allow(clippy::large_enum_variant)]
pub enum PrivateKey {
    Rsa(RsaPrivateKey),
    Ecc(SecretKey),
}

impl PrivateKey {
    /// Load and parse a PEM-encoded PKCS#8 private key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `CliError` on parsing failure.
    pub fn from_pem_bytes(pem_bytes: &[u8]) -> Result<Self, CliError> {
        let pem_str = std::str::from_utf8(pem_bytes).map_err(|e| CliError::Parse(e.to_string()))?;

        let pem_block = pem::parse(pem_str)?;

        if pem_block.tag() != "PRIVATE KEY" {
            return Err(CliError::Parse(format!(
                "invalid PEM tag: {}",
                pem_block.tag()
            )));
        }

        let contents = pem_block.contents();
        let private_key_info = PrivateKeyInfo::from_der(contents)?;
        let oid = private_key_info.algorithm.oid;

        let key = match oid {
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") => {
                PrivateKey::Rsa(rsa::RsaPrivateKey::from_pkcs8_der(contents)?)
            }
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") => {
                PrivateKey::Ecc(SecretKey::from_pkcs8_der(contents)?)
            }
            _ => {
                return Err(CliError::Parse(
                    "unsupported key algorithm in PEM file".to_string(),
                ))
            }
        };

        Ok(key)
    }

    /// Load and parse PEM-encoded PKCS#8 private key from a file.
    ///
    /// # Errors
    ///
    /// Returns `CliError` on file I/O or parsing failure.
    pub fn from_pem_file(path: &std::path::Path) -> Result<Self, CliError> {
        let pem_bytes =
            std::fs::read(path).map_err(|e| CliError::File(path.display().to_string(), e))?;
        Self::from_pem_bytes(&pem_bytes)
    }

    /// Converts key to `TpmtPublic`.
    ///
    /// Implementation note: according to TCG TPM 2.0 Structures specification,
    /// exponent zero maps to the default RSA exponent 65537, and the support
    /// for other values is optional.
    ///
    /// # Errors
    ///
    /// Returns `CliError`.
    pub fn to_tpmt_public(&self, hash_alg: TpmAlgId) -> Result<TpmtPublic, CliError> {
        match self {
            PrivateKey::Rsa(rsa_key) => {
                let modulus_bytes = rsa_key.n().to_bytes_be();
                let key_bits = u16::try_from(modulus_bytes.len() * 8)
                    .map_err(|_| CliError::Parse("RSA key is too large".to_string()))?;

                let exponent = {
                    let e_bytes = rsa_key.e().to_bytes_be();
                    if e_bytes.len() > 4 {
                        return Err(CliError::Parse("RSA exponent is too large".to_string()));
                    }
                    let mut buf = [0u8; 4];
                    buf[4 - e_bytes.len()..].copy_from_slice(&e_bytes);
                    u32::from_be_bytes(buf)
                };

                let exponent = if exponent == 65537 {
                    0
                } else {
                    return Err(CliError::Parse("RSA exponent is unsupported".to_string()));
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
                    unique: TpmuPublicId::Rsa(Tpm2bPublicKeyRsa::try_from(
                        modulus_bytes.as_slice(),
                    )?),
                })
            }
            PrivateKey::Ecc(secret_key) => {
                let encoded_point = secret_key.public_key().to_encoded_point(false);
                let pub_bytes = encoded_point.as_bytes();

                if pub_bytes.is_empty() || pub_bytes[0] != UNCOMPRESSED_POINT_TAG {
                    return Err(CliError::Parse("invalid ECC public key format".to_string()));
                }

                let coord_len = (pub_bytes.len() - 1) / 2;
                let x = &pub_bytes[1..=coord_len];
                let y = &pub_bytes[1 + coord_len..];

                let der_bytes = secret_key.to_pkcs8_der()?;
                let pki = PrivateKeyInfo::from_der(der_bytes.as_bytes())?;
                let params =
                    pki.algorithm.parameters.as_ref().ok_or_else(|| {
                        CliError::Parse("missing ECC curve parameters".to_string())
                    })?;

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
                        x: Tpm2bEccParameter::try_from(x)?,
                        y: Tpm2bEccParameter::try_from(y)?,
                    }),
                })
            }
        }
    }

    /// Returns the sensitive part of the private key required for import.
    ///
    /// # Errors
    ///
    /// Returns a `CliError::Parse` if the key cannot be processed.
    pub fn get_sensitive_blob(&self) -> Result<Vec<u8>, CliError> {
        match self {
            PrivateKey::Rsa(rsa_key) => Ok(rsa_key.primes()[0].to_bytes_be()),
            PrivateKey::Ecc(secret_key) => Ok(secret_key.to_bytes().to_vec()),
        }
    }
}

/// Convert ECC curve OID from DER `AnyRef` to TPM curve enum.
fn ec_oid_to_tpm_curve(any: &AnyRef) -> Result<TpmEccCurve, CliError> {
    let der_bytes = any.to_der()?;
    let mut reader = der::SliceReader::new(&der_bytes)?;
    let oid = ObjectIdentifier::decode(&mut reader)
        .map_err(|_| CliError::Parse("Invalid DER in ECC curve parameters".to_string()))?;

    match oid {
        SECP_256_R_1 => Ok(TpmEccCurve::NistP256),
        SECP_384_R_1 => Ok(TpmEccCurve::NistP384),
        SECP_521_R_1 => Ok(TpmEccCurve::NistP521),
        _ => Err(CliError::Parse(format!("unsupported ECC curve OID: {oid}"))),
    }
}

impl TpmKey {
    /// Serialize TPM key to PEM.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the key's OID or other fields cannot be encoded to DER.
    pub fn to_pem(&self) -> Result<String, CliError> {
        let der = self.to_der()?;
        Ok(pem::encode(&pem::Pem::new("TSS2 PRIVATE KEY", der)))
    }

    /// Serialize TPM key to DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the key's OID or other fields cannot be encoded to DER.
    pub fn to_der(&self) -> Result<Vec<u8>, CliError> {
        Encode::to_der(self).map_err(|e| CliError::Parse(format!("DER encode error: {e}")))
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the PEM bytes cannot be parsed.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, CliError> {
        let pem = pem::parse(pem_bytes)?;
        if pem.tag() != "TSS2 PRIVATE KEY" {
            return Err(CliError::Parse("invalid PEM tag".to_string()));
        }
        Self::from_der(pem.contents())
    }

    /// Parse TPM key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the DER bytes cannot be parsed into a valid `TpmKeyAsn1` data.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, CliError> {
        Ok(Decode::from_der(der_bytes)?)
    }
}

fn compute_hmac(
    auth_hash: TpmAlgId,
    hmac_key: &[u8],
    attributes: u8,
    nonce_tpm: &[u8],
    nonce_caller: &[u8],
    cp_hash_payload: &[u8],
) -> Result<Vec<u8>, CliError> {
    macro_rules! hmac {
        ($digest:ty) => {{
            let cp_hash = <$digest as Digest>::digest(cp_hash_payload);
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(hmac_key)
                .map_err(|e| CliError::Execution(format!("HMAC init error: {e}")))?;
            mac.update(&cp_hash);
            mac.update(nonce_tpm);
            mac.update(nonce_caller);
            mac.update(&[attributes]);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }

    match auth_hash {
        TpmAlgId::Sha256 => hmac!(Sha256),
        TpmAlgId::Sha384 => hmac!(Sha384),
        TpmAlgId::Sha512 => hmac!(Sha512),
        _ => Err(CliError::Execution(format!(
            "unsupported session hash algorithm: {auth_hash}"
        ))),
    }
}

/// Computes the authorization HMAC for a command session.
///
/// # Errors
///
/// Returns a `CliError::Execution` if the session's hash algorithm is not
/// supported, or if an HMAC operation fails.
pub fn create_auth(
    session: &super::AuthSession,
    nonce_caller: &tpm2_protocol::data::Tpm2bNonce,
    command_code: TpmCc,
    handles: &[u32],
    parameters: &[u8],
) -> Result<TpmsAuthCommand, CliError> {
    let cp_hash_payload = {
        let mut payload = Vec::new();
        payload.extend_from_slice(&(command_code as u32).to_be_bytes());
        for handle in handles {
            payload.extend_from_slice(&handle.to_be_bytes());
        }
        payload.extend_from_slice(parameters);
        payload
    };

    let hmac_bytes = compute_hmac(
        session.auth_hash,
        &session.hmac_key,
        session.attributes.bits(),
        &session.nonce_tpm,
        nonce_caller,
        &cp_hash_payload,
    )?;

    Ok(TpmsAuthCommand {
        session_handle: session.handle,
        nonce: *nonce_caller,
        session_attributes: session.attributes,
        hmac: tpm2_protocol::data::Tpm2bAuth::try_from(hmac_bytes.as_slice())?,
    })
}

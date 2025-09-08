// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    crypto::PrivateKey,
    error::{CliError, ParseError},
    policy::alg_from_str,
};
use std::{fmt, str::FromStr};

use p256::SecretKey;
use pkcs8::{
    der::{
        self, asn1::OctetString, Decode, DecodeValue, Encode, EncodeValue, Reader, Sequence, Writer,
    },
    DecodePrivateKey, ObjectIdentifier, PrivateKeyInfo,
};
use rsa::RsaPrivateKey;
use tpm2_protocol::{
    data::{TpmAlgId, TpmEccCurve, TpmRc},
    TpmErrorKind,
};

#[derive(Debug)]
pub enum AuthError {
    Build(TpmErrorKind),
    Hmac(TpmRc),
    InvalidAlgorithm(TpmAlgId),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Build(e) => write!(f, "TPM protocol error: {e}"),
            Self::Hmac(rc) => write!(f, "HMAC failure: {rc}"),
            Self::InvalidAlgorithm(alg) => write!(f, "Invalid algorithm: {alg:?}"),
        }
    }
}

impl std::error::Error for AuthError {}

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
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let parts: Vec<&str> = s.split(':').collect();
        match parts.as_slice() {
            ["rsa", key_bits_str, name_alg_str] => {
                let key_bits: u16 = key_bits_str
                    .parse()
                    .map_err(|_| format!("Invalid RSA key bits value: '{key_bits_str}'"))?;
                let name_alg = alg_from_str(name_alg_str)
                    .map_err(|e| format!("Invalid algorithm name: {e}"))?;
                Ok(Self {
                    name: s.to_string(),
                    object_type: TpmAlgId::Rsa,
                    name_alg,
                    params: AlgInfo::Rsa { key_bits },
                })
            }
            ["ecc", curve_id_str, name_alg_str] => {
                let curve_id = tpm_ecc_curve_from_str(curve_id_str)?;
                let name_alg = alg_from_str(name_alg_str)
                    .map_err(|e| format!("Invalid algorithm name: {e}"))?;
                Ok(Self {
                    name: s.to_string(),
                    object_type: TpmAlgId::Ecc,
                    name_alg,
                    params: AlgInfo::Ecc { curve_id },
                })
            }
            ["keyedhash", name_alg_str] => {
                let name_alg = alg_from_str(name_alg_str)
                    .map_err(|e| format!("Invalid algorithm name: {e}"))?;
                Ok(Self {
                    name: s.to_string(),
                    object_type: TpmAlgId::KeyedHash,
                    name_alg,
                    params: AlgInfo::KeyedHash,
                })
            }
            _ => Err(format!("Invalid algorithm format: '{s}'")),
        }
    }
}

impl std::cmp::Ord for Alg {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name.cmp(&other.name)
    }
}

impl std::cmp::PartialOrd for Alg {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// A newtype wrapper to provide a project-specific `Display` implementation for `TpmAlgId`.
#[derive(Debug, Clone, Copy)]
pub struct Tpm2shAlgId(pub TpmAlgId);

impl fmt::Display for Tpm2shAlgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self.0 {
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
        };
        write!(f, "{s}")
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
        TpmEccCurve::BnP638 => "bn-p638",
        TpmEccCurve::Sm2P256 => "sm2-p256",
        TpmEccCurve::BpP256R1 => "bp-p256-r1",
        TpmEccCurve::BpP384R1 => "bp-p384-r1",
        TpmEccCurve::BpP512R1 => "bp-p512-r1",
        TpmEccCurve::BnP256 => "bn-p256",
        TpmEccCurve::Curve448 => "curve-448",
        TpmEccCurve::Curve25519 => "curve-25519",
        TpmEccCurve::None => "none",
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
        "bn-p638" => Ok(TpmEccCurve::BnP638),
        "sm2-p256" => Ok(TpmEccCurve::Sm2P256),
        "bp-p256-r1" => Ok(TpmEccCurve::BpP256R1),
        "bp-p384-r1" => Ok(TpmEccCurve::BpP384R1),
        "bp-p512-r1" => Ok(TpmEccCurve::BpP512R1),
        "bn-p256" => Ok(TpmEccCurve::BnP256),
        "curve-448" => Ok(TpmEccCurve::Curve448),
        "curve-25519" => Ok(TpmEccCurve::Curve25519),
        "none" => Ok(TpmEccCurve::None),
        _ => Err(format!("unknown '{s}'")),
    }
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
        Encode::to_der(self)
            .map_err(|e| ParseError::Custom(format!("DER encode error: {e}")).into())
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the PEM bytes cannot be parsed.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, CliError> {
        let pem = pem::parse(pem_bytes).map_err(ParseError::from)?;
        if pem.tag() != "TSS2 PRIVATE KEY" {
            return Err(ParseError::Custom("invalid PEM tag".to_string()).into());
        }
        Self::from_der(pem.contents())
    }

    /// Parse TPM key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the DER bytes cannot be parsed into a valid `TpmKeyAsn1` data.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, CliError> {
        Ok(Decode::from_der(der_bytes).map_err(ParseError::from)?)
    }
}

/// Load and parse a PKCS#8 private key from a byte slice, trying DER then PEM.
///
/// # Errors
///
/// Returns `CliError` on parsing failure.
pub fn private_key_from_bytes(bytes: &[u8]) -> Result<PrivateKey, CliError> {
    private_key_from_der_bytes(bytes)
        .or_else(|_| private_key_from_pem_bytes(bytes))
        .map_err(|_| {
            CliError::Parse(ParseError::Custom(
                "failed to parse key: not a valid PKCS#8 DER or PEM encoded key".to_string(),
            ))
        })
}

/// Load and parse a DER-encoded PKCS#8 private key from a byte slice.
///
/// # Errors
///
/// Returns `CliError` on parsing failure.
pub fn private_key_from_der_bytes(der_bytes: &[u8]) -> Result<PrivateKey, CliError> {
    let private_key_info = PrivateKeyInfo::from_der(der_bytes).map_err(ParseError::from)?;
    let oid = private_key_info.algorithm.oid;

    let key = match oid {
        oid if oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") => PrivateKey::Rsa(
            Box::new(RsaPrivateKey::from_pkcs8_der(der_bytes).map_err(ParseError::from)?),
        ),
        oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") => {
            PrivateKey::Ecc(SecretKey::from_pkcs8_der(der_bytes).map_err(ParseError::from)?)
        }
        _ => {
            return Err(
                ParseError::Custom("unsupported key algorithm in DER data".to_string()).into(),
            )
        }
    };

    Ok(key)
}

/// Load and parse a PEM-encoded PKCS#8 private key from a byte slice.
///
/// # Errors
///
/// Returns `CliError` on parsing failure.
pub fn private_key_from_pem_bytes(pem_bytes: &[u8]) -> Result<PrivateKey, CliError> {
    let pem_str = std::str::from_utf8(pem_bytes).map_err(ParseError::from)?;
    let pem_block = pem::parse(pem_str).map_err(ParseError::from)?;

    if pem_block.tag() != "PRIVATE KEY" {
        return Err(ParseError::Custom(format!("invalid PEM tag: {}", pem_block.tag())).into());
    }
    private_key_from_der_bytes(pem_block.contents())
}

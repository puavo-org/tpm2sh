// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::TpmError;
use const_oid::db::rfc5912::{SECP_256_R_1, SECP_384_R_1, SECP_521_R_1};
use hmac::{Hmac, Mac};
use p256::{elliptic_curve::sec1::ToEncodedPoint, SecretKey};
use pkcs8::{
    der::{
        self,
        asn1::{AnyRef, OctetString},
        Decode, DecodeValue, Encode, EncodeValue, Reader, Sequence, Writer,
    },
    ObjectIdentifier, PrivateKeyInfo,
};
use rsa::traits::{PrivateKeyParts, PublicKeyParts};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tpm2_protocol::data::{
    Tpm2bDigest, Tpm2bEccParameter, Tpm2bPublicKeyRsa, TpmAlgId, TpmCc, TpmEccCurve, TpmaObject,
    TpmsAuthCommand, TpmsEccParms, TpmsEccPoint, TpmsRsaParms, TpmtKdfScheme, TpmtPublic,
    TpmtScheme, TpmtSymDefObject, TpmuPublicId, TpmuPublicParms,
};

use pkcs8::{DecodePrivateKey, EncodePrivateKey};

pub const ID_IMPORTABLE_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.4");
pub const ID_SEALED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.23.133.1.5");

pub const UNCOMPRESSED_POINT_TAG: u8 = 0x04;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TpmKeyAsn1 {
    pub oid: ObjectIdentifier,
    pub parent: u32,
    pub pub_key: OctetString,
    pub priv_key: OctetString,
}

impl Sequence<'_> for TpmKeyAsn1 {}

impl<'a> DecodeValue<'a> for TpmKeyAsn1 {
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

impl EncodeValue for TpmKeyAsn1 {
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

/// A parsed RSA or ECC private key.
#[allow(clippy::large_enum_variant)]
pub enum ParsedKey {
    Rsa(rsa::RsaPrivateKey),
    Ecc(SecretKey),
}

/// Loaded private key from PEM file.
pub struct PrivateKey {
    key: ParsedKey,
}

impl PrivateKey {
    /// Load and parse a PEM-encoded PKCS#8 private key from a byte slice.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` on parsing failure.
    pub fn from_pem_bytes(pem_bytes: &[u8]) -> Result<Self, TpmError> {
        let pem_str = std::str::from_utf8(pem_bytes).map_err(|e| TpmError::Parse(e.to_string()))?;

        let pem_block = pem::parse(pem_str)?;

        if pem_block.tag() != "PRIVATE KEY" {
            return Err(TpmError::Parse(format!(
                "invalid PEM tag: {}",
                pem_block.tag()
            )));
        }

        let contents = pem_block.contents();
        let private_key_info = PrivateKeyInfo::from_der(contents)?;
        let oid = private_key_info.algorithm.oid;

        let key = match oid {
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1") => {
                ParsedKey::Rsa(rsa::RsaPrivateKey::from_pkcs8_der(contents)?)
            }
            oid if oid == ObjectIdentifier::new_unwrap("1.2.840.10045.2.1") => {
                ParsedKey::Ecc(SecretKey::from_pkcs8_der(contents)?)
            }
            _ => {
                return Err(TpmError::Parse(
                    "unsupported key algorithm in PEM file".to_string(),
                ))
            }
        };

        Ok(Self { key })
    }

    /// Load and parse PEM-encoded PKCS#8 private key from a file.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` on file I/O or parsing failure.
    pub fn from_pem_file(path: &std::path::Path) -> Result<Self, TpmError> {
        let pem_bytes =
            std::fs::read(path).map_err(|e| TpmError::File(path.display().to_string(), e))?;
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
    /// Returns `TpmError`.
    pub fn to_tpmt_public(&self, hash_alg: TpmAlgId) -> Result<TpmtPublic, TpmError> {
        match &self.key {
            ParsedKey::Rsa(rsa_key) => {
                let modulus_bytes = rsa_key.n().to_bytes_be();
                let key_bits = u16::try_from(modulus_bytes.len() * 8)
                    .map_err(|_| TpmError::Parse("RSA key is too large".to_string()))?;

                let exponent = {
                    let e_bytes = rsa_key.e().to_bytes_be();
                    if e_bytes.len() > 4 {
                        return Err(TpmError::Parse("RSA exponent is too large".to_string()));
                    }
                    let mut buf = [0u8; 4];
                    buf[4 - e_bytes.len()..].copy_from_slice(&e_bytes);
                    u32::from_be_bytes(buf)
                };

                let exponent = if exponent == 65537 {
                    0
                } else {
                    return Err(TpmError::Parse("RSA exponent is unsupported".to_string()));
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
            ParsedKey::Ecc(secret_key) => {
                let encoded_point = secret_key.public_key().to_encoded_point(false);
                let pub_bytes = encoded_point.as_bytes();

                if pub_bytes.is_empty() || pub_bytes[0] != UNCOMPRESSED_POINT_TAG {
                    return Err(TpmError::Parse("invalid ECC public key format".to_string()));
                }

                let coord_len = (pub_bytes.len() - 1) / 2;
                let x = &pub_bytes[1..=coord_len];
                let y = &pub_bytes[1 + coord_len..];

                let der_bytes = secret_key.to_pkcs8_der()?;
                let pki = PrivateKeyInfo::from_der(der_bytes.as_bytes())?;
                let params =
                    pki.algorithm.parameters.as_ref().ok_or_else(|| {
                        TpmError::Parse("missing ECC curve parameters".to_string())
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
    /// Returns a `TpmError::Parse` if the key cannot be processed.
    pub fn get_sensitive_blob(&self) -> Result<Vec<u8>, TpmError> {
        match &self.key {
            ParsedKey::Rsa(rsa_key) => Ok(rsa_key.primes()[0].to_bytes_be()),
            ParsedKey::Ecc(secret_key) => Ok(secret_key.to_bytes().to_vec()),
        }
    }
}

/// Convert ECC curve OID from DER `AnyRef` to TPM curve enum.
fn ec_oid_to_tpm_curve(any: &AnyRef) -> Result<TpmEccCurve, TpmError> {
    let der_bytes = any.to_der()?;
    let mut reader = der::SliceReader::new(&der_bytes)?;
    let oid = ObjectIdentifier::decode(&mut reader)
        .map_err(|_| TpmError::Parse("Invalid DER in ECC curve parameters".to_string()))?;

    match oid {
        SECP_256_R_1 => Ok(TpmEccCurve::NistP256),
        SECP_384_R_1 => Ok(TpmEccCurve::NistP384),
        SECP_521_R_1 => Ok(TpmEccCurve::NistP521),
        _ => Err(TpmError::Parse(format!("unsupported ECC curve OID: {oid}"))),
    }
}

/// TPM key ready for serialization or deserialization.
pub struct TpmKey {
    pub oid: Vec<u32>,
    pub parent: String,
    pub pub_key: Vec<u8>,
    pub priv_key: Vec<u8>,
}

impl TpmKey {
    /// Serialize TPM key to PEM.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` if the key's OID or other fields cannot be encoded to DER.
    pub fn to_pem(&self) -> Result<String, TpmError> {
        let der = self.to_der()?;
        Ok(pem::encode(&pem::Pem::new("TSS2 PRIVATE KEY", der)))
    }

    /// Serialize TPM key to DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` if the key's OID or other fields cannot be encoded to DER.
    pub fn to_der(&self) -> Result<Vec<u8>, TpmError> {
        let asn1 = TpmKeyAsn1 {
            oid: ObjectIdentifier::from_arcs(self.oid.iter().copied())
                .map_err(|e| TpmError::Parse(format!("OID encode error: {e:?}")))?,
            parent: u32::from_str_radix(self.parent.trim_start_matches("0x"), 16)?,
            pub_key: OctetString::new(self.pub_key.clone())?,
            priv_key: OctetString::new(self.priv_key.clone())?,
        };

        asn1.to_der()
            .map_err(|e| TpmError::Parse(format!("DER encode error: {e}")))
    }

    /// Parse TPM key from PEM bytes.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` if the PEM bytes cannot be parsed.
    pub fn from_pem(pem_bytes: &[u8]) -> Result<Self, TpmError> {
        let pem = pem::parse(pem_bytes)?;
        if pem.tag() != "TSS2 PRIVATE KEY" {
            return Err(TpmError::Parse("invalid PEM tag".to_string()));
        }
        Self::from_der(pem.contents())
    }

    /// Parse TPM key from DER bytes.
    ///
    /// # Errors
    ///
    /// Returns `TpmError` if the DER bytes cannot be parsed into a valid `TpmKeyAsn1` data.
    pub fn from_der(der_bytes: &[u8]) -> Result<Self, TpmError> {
        let asn1 = TpmKeyAsn1::from_der(der_bytes)?;

        Ok(TpmKey {
            oid: asn1.oid.arcs().collect(),
            parent: format!("{:#010x}", asn1.parent),
            pub_key: asn1.pub_key.as_bytes().to_vec(),
            priv_key: asn1.priv_key.as_bytes().to_vec(),
        })
    }
}

fn compute_hmac(
    auth_hash: TpmAlgId,
    hmac_key: &[u8],
    attributes: u8,
    nonce_tpm: &[u8],
    nonce_caller: &[u8],
    cp_hash_payload: &[u8],
) -> Result<Vec<u8>, TpmError> {
    macro_rules! do_hmac {
        ($digest:ty) => {{
            let cp_hash = <$digest as Digest>::digest(cp_hash_payload);
            let mut mac = <Hmac<$digest> as Mac>::new_from_slice(hmac_key)
                .map_err(|e| TpmError::Execution(format!("HMAC init error: {e}")))?;
            mac.update(&cp_hash);
            mac.update(nonce_tpm);
            mac.update(nonce_caller);
            mac.update(&[attributes]);
            Ok(mac.finalize().into_bytes().to_vec())
        }};
    }

    match auth_hash {
        TpmAlgId::Sha256 => do_hmac!(Sha256),
        TpmAlgId::Sha384 => do_hmac!(Sha384),
        TpmAlgId::Sha512 => do_hmac!(Sha512),
        _ => Err(TpmError::Execution(format!(
            "unsupported session hash algorithm: {auth_hash}"
        ))),
    }
}

/// Computes the authorization HMAC for a command session.
///
/// # Errors
///
/// Returns a `TpmError::Execution` if the session's hash algorithm is not
/// supported, or if an HMAC operation fails.
pub fn create_auth(
    session: &super::AuthSession,
    nonce_caller: &tpm2_protocol::data::Tpm2bNonce,
    command_code: TpmCc,
    handles: &[u32],
    parameters: &[u8],
) -> Result<TpmsAuthCommand, TpmError> {
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

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::CliError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tpm2_protocol::data::{TpmtPublic, TpmuPublicParms};

#[derive(Serialize, Deserialize, Debug)]
pub struct Pipeline {
    pub version: u32,
    pub objects: Vec<PipelineObject>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "type")]
pub enum PipelineObject {
    #[serde(rename = "tpm")]
    Tpm(Tpm),
    #[serde(rename = "key")]
    Key(Key),
    #[serde(rename = "data")]
    Data(Data),
    #[serde(rename = "pcr-values")]
    PcrValues(PcrValues),
    #[serde(rename = "hmac-session")]
    HmacSession(HmacSession),
    #[serde(rename = "policy-session")]
    PolicySession(PolicySession),
}

impl PipelineObject {
    /// Returns a reference to the inner `Tpm` if the variant is `Tpm`, else `None`.
    #[must_use]
    pub fn as_tpm(&self) -> Option<&Tpm> {
        if let Self::Tpm(v) = self {
            Some(v)
        } else {
            None
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Tpm {
    pub context: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Key {
    pub public: String,
    pub private: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct Data {
    pub encoding: String,
    pub value: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PcrValues {
    pub update: u32,
    pub banks: BTreeMap<String, BTreeMap<String, String>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct HmacSession {
    pub context: String,
    pub algorithm: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct PolicySession {
    pub context: String,
    pub algorithm: String,
    pub digest: String,
}

/// A non-serializable struct for displaying a human-readable public area.
#[derive(Debug, Serialize)]
pub struct PublicArea {
    #[serde(rename = "type")]
    pub object_type: String,
    pub name_alg: String,
    pub attributes: Vec<String>,
    pub parameters: serde_json::Value,
}

impl TryFrom<&TpmtPublic> for PublicArea {
    type Error = CliError;

    fn try_from(public: &TpmtPublic) -> Result<Self, Self::Error> {
        let object_type = crate::key::tpm_alg_id_to_str(public.object_type).to_string();
        let name_alg = crate::key::tpm_alg_id_to_str(public.name_alg).to_string();
        let attributes: Vec<String> = public
            .object_attributes
            .flag_names()
            .map(String::from)
            .collect();

        let parameters = match &public.parameters {
            TpmuPublicParms::Rsa(p) => {
                let exponent = if p.exponent == 0 { 65537 } else { p.exponent };
                serde_json::json!({
                    "rsa": {
                        "key_bits": p.key_bits,
                        "exponent": exponent,
                    }
                })
            }
            TpmuPublicParms::Ecc(p) => serde_json::json!({
                "ecc": {
                    "curve": crate::key::tpm_ecc_curve_to_str(p.curve_id),
                }
            }),
            TpmuPublicParms::KeyedHash(_) => serde_json::json!({"keyedhash": {}}),
            _ => serde_json::Value::Null,
        };

        Ok(Self {
            object_type,
            name_alg,
            attributes,
            parameters,
        })
    }
}

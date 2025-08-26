// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy

use crate::{key::tpm_alg_id_from_str, TpmError};
use std::collections::BTreeMap;
use tpm2_protocol::data;

#[derive(Debug, Clone)]
pub struct PcrOutput {
    pub update_counter: u32,
    pub banks: BTreeMap<String, BTreeMap<String, String>>,
}

impl PcrOutput {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.banks.values().all(BTreeMap::is_empty)
    }

    #[must_use]
    pub fn to_json(&self) -> json::JsonValue {
        let mut banks_obj = json::object::Object::new();
        for (bank_name, pcrs) in &self.banks {
            let mut pcrs_obj = json::object::Object::new();
            for (pcr_index, digest) in pcrs {
                pcrs_obj.insert(pcr_index, json::JsonValue::String(digest.clone()));
            }
            banks_obj.insert(bank_name, json::JsonValue::Object(pcrs_obj));
        }

        json::object! {
            "update-counter": self.update_counter,
            "banks": banks_obj,
        }
    }

    /// Deserializes a `PcrOutput` from a `json::JsonValue`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Parse` if the JSON object is missing required fields
    /// or contains values of the wrong type.
    pub fn from_json(value: &json::JsonValue) -> Result<Self, TpmError> {
        let update_counter = value["update-counter"]
            .as_u32()
            .ok_or_else(|| TpmError::Parse("missing or invalid 'update-counter'".to_string()))?;

        let mut banks = BTreeMap::new();
        for (bank_name, pcrs_val) in value["banks"].entries() {
            let mut pcrs = BTreeMap::new();
            for (pcr_index, digest_val) in pcrs_val.entries() {
                let digest = digest_val
                    .as_str()
                    .ok_or_else(|| TpmError::Parse("pcr digest is not a string".to_string()))?
                    .to_string();
                pcrs.insert(pcr_index.to_string(), digest);
            }
            banks.insert(bank_name.to_string(), pcrs);
        }

        Ok(Self {
            update_counter,
            banks,
        })
    }

    /// Converts a `PcrOutput` into a `TpmlPcrSelection` list.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the structure cannot be converted.
    pub fn to_tpml_pcr_selection(
        pcr_values: &PcrOutput,
        pcr_count: usize,
    ) -> Result<data::TpmlPcrSelection, TpmError> {
        let mut list = data::TpmlPcrSelection::new();
        let pcr_select_size = pcr_count.div_ceil(8);
        if pcr_select_size > data::TPM_PCR_SELECT_MAX {
            return Err(TpmError::PcrSelection(format!(
                "required pcr select size {pcr_select_size} exceeds maximum {}",
                data::TPM_PCR_SELECT_MAX
            )));
        }

        for (bank_name, pcr_map) in &pcr_values.banks {
            let alg = tpm_alg_id_from_str(bank_name).map_err(TpmError::Parse)?;
            let mut pcr_select_bytes = vec![0u8; pcr_select_size];
            for pcr_str in pcr_map.keys() {
                let pcr_index: usize = pcr_str.parse()?;
                if pcr_index >= pcr_count {
                    return Err(TpmError::PcrSelection(format!(
                        "pcr index {pcr_index} is out of range for a TPM with {pcr_count} PCRs"
                    )));
                }
                pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
            }
            list.try_push(data::TpmsPcrSelection {
                hash: alg,
                pcr_select: tpm2_protocol::TpmBuffer::try_from(pcr_select_bytes.as_slice())?,
            })?;
        }
        Ok(list)
    }
}
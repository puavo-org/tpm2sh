// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    error::ParseError,
    key::{tpm_alg_id_to_str, JsonPcrValues},
    CliError, TpmDevice,
};

use std::{collections::BTreeMap, str::FromStr};

use pest::Parser as PestParser;
use pest_derive::Parser;
use tpm2_protocol::{
    data::{
        TpmAlgId, TpmCap, TpmlPcrSelection, TpmsPcrSelection, TpmuCapabilities, TPM_PCR_SELECT_MAX,
    },
    message::TpmPcrReadResponse,
    TpmBuffer,
};

#[derive(Parser)]
#[grammar = "command/pcr_selection.pest"]
pub struct PcrSelectionParser;

/// Gets the number of PCRs from the TPM.
pub(crate) fn pcr_get_count(device: &mut TpmDevice) -> Result<usize, CliError> {
    let cap_data = device.get_capability(TpmCap::Pcrs, 0, crate::device::TPM_CAP_PROPERTY_MAX)?;
    let Some(first_cap) = cap_data.into_iter().next() else {
        return Err(CliError::Execution(
            "TPM reported no capabilities for PCRs.".to_string(),
        ));
    };

    if let TpmuCapabilities::Pcrs(pcrs) = first_cap.data {
        if let Some(first_bank) = pcrs.iter().next() {
            Ok(first_bank.pcr_select.len() * 8)
        } else {
            Err(CliError::Execution(
                "TPM reported no active PCR banks.".to_string(),
            ))
        }
    } else {
        Err(CliError::Execution(
            "Unexpected capability data type when querying for PCRs.".to_string(),
        ))
    }
}

/// Converts a `TpmPcrReadResponse` to a serializable `JsonPcrValues` format.
pub(crate) fn pcr_to_values(resp: &TpmPcrReadResponse) -> Result<JsonPcrValues, CliError> {
    let mut pcr_output = JsonPcrValues {
        update: resp.pcr_update_counter,
        banks: BTreeMap::default(),
    };
    let mut digest_iter = resp.pcr_values.iter();

    for selection in resp.pcr_selection_out.iter() {
        let bank_name = tpm_alg_id_to_str(selection.hash).to_string();
        let bank_map = pcr_output.banks.entry(bank_name).or_default();

        for (byte_idx, &byte) in selection.pcr_select.iter().enumerate() {
            if byte == 0 {
                continue;
            }
            for bit_idx in 0..8 {
                if (byte & (1 << bit_idx)) != 0 {
                    let pcr_index = byte_idx * 8 + bit_idx;
                    let digest = digest_iter.next().ok_or_else(|| {
                        ParseError::Custom(
                            "TPM response had fewer digests than selected PCRs".to_string(),
                        )
                    })?;
                    bank_map.insert(pcr_index.to_string(), hex::encode(digest));
                }
            }
        }
    }
    Ok(pcr_output)
}

/// Parses a PCR selection string (e.g., "sha256:0,7+sha1:1") into a TPM list.
pub(crate) fn pcr_parse_selection(
    selection_str: &str,
    pcr_count: usize,
) -> Result<TpmlPcrSelection, CliError> {
    let mut list = TpmlPcrSelection::new();
    let pcr_select_size = pcr_count.div_ceil(8);
    if pcr_select_size > TPM_PCR_SELECT_MAX {
        return Err(CliError::PcrSelection(format!(
            "required pcr select size {pcr_select_size} exceeds maximum {TPM_PCR_SELECT_MAX}"
        )));
    }

    let pairs = PcrSelectionParser::parse(Rule::selection, selection_str)
        .map_err(|e| CliError::PcrSelection(e.to_string()))?;

    for pair in pairs.flatten().filter(|p| p.as_rule() == Rule::bank) {
        let mut inner_pairs = pair.into_inner();

        let alg_str = inner_pairs.next().unwrap().as_str();
        let alg = PcrAlgId::from_str(alg_str)
            .map_err(|()| CliError::PcrSelection(format!("invalid algorithm: {alg_str}")))?
            .0;

        let colon_and_list_pair = inner_pairs.next().unwrap();
        let pcr_list_pair = colon_and_list_pair.into_inner().next().unwrap();
        let mut pcr_select_bytes = vec![0u8; pcr_select_size];

        for pcr_index_pair in pcr_list_pair.into_inner() {
            let pcr_index: usize = pcr_index_pair.as_str().parse()?;

            if pcr_index >= pcr_count {
                return Err(CliError::PcrSelection(format!(
                    "pcr index {pcr_index} is out of range for a TPM with {pcr_count} PCRs"
                )));
            }

            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }

        list.try_push(TpmsPcrSelection {
            hash: alg,
            pcr_select: TpmBuffer::try_from(pcr_select_bytes.as_slice())?,
        })?;
    }

    Ok(list)
}

struct PcrAlgId(TpmAlgId);

impl FromStr for PcrAlgId {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "sha1" => Ok(Self(TpmAlgId::Sha1)),
            "sha256" => Ok(Self(TpmAlgId::Sha256)),
            "sha384" => Ok(Self(TpmAlgId::Sha384)),
            "sha512" => Ok(Self(TpmAlgId::Sha512)),
            _ => Err(()),
        }
    }
}

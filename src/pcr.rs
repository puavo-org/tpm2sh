// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    error::ParseError,
    key::{tpm_alg_id_to_str, PcrValues},
    CliError, TpmDevice,
};

use tpm2_protocol::{
    data::{TpmCap, TpmuCapabilities},
    message::TpmPcrReadResponse,
};

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

/// Converts a `TpmPcrReadResponse` to a serializable `PcrValues` format.
pub(crate) fn pcr_to_values(resp: &TpmPcrReadResponse) -> Result<PcrValues, CliError> {
    let mut pcr_output = PcrValues {
        update: resp.pcr_update_counter,
        ..Default::default()
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

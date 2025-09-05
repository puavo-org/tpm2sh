// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{device::TpmDevice, error::CliError};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tpm2_protocol::{
    data::{TpmAlgId, TpmCap, TpmlPcrSelection, TpmuCapabilities},
    message::TpmPcrReadCommand,
};

/// Represents the state of a single PCR register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcr {
    pub bank: TpmAlgId,
    pub index: u32,
    pub value: Vec<u8>,
}

/// Reads the selected PCRs and returns them in a structured format.
///
/// This function serves as the high-level API for reading PCRs, abstracting away
/// the complexity of the raw TPM response.
///
/// # Errors
///
/// Returns a `CliError` if the TPM command fails or the response is inconsistent.
pub fn read(
    device: &mut TpmDevice,
    pcr_selection_in: &TpmlPcrSelection,
) -> Result<Vec<Pcr>, CliError> {
    let cmd = TpmPcrReadCommand {
        pcr_selection_in: *pcr_selection_in,
    };
    let (_, resp, _) = device.execute(&cmd, &[])?;
    let pcr_read_resp = resp
        .PcrRead()
        .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;

    let mut pcrs = Vec::new();
    let mut digest_iter = pcr_read_resp.pcr_values.iter();

    for selection in pcr_read_resp.pcr_selection_out.iter() {
        for (byte_idx, &byte) in selection.pcr_select.iter().enumerate() {
            if byte == 0 {
                continue;
            }
            for bit_idx in 0..8 {
                if (byte >> bit_idx) & 1 == 1 {
                    let pcr_index = u32::try_from(byte_idx * 8 + bit_idx)
                        .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
                    let value = digest_iter
                        .next()
                        .ok_or_else(|| CliError::Execution("PCR selection mismatch".to_string()))?;
                    pcrs.push(Pcr {
                        bank: selection.hash,
                        index: pcr_index,
                        value: value.to_vec(),
                    });
                }
            }
        }
    }

    Ok(pcrs)
}

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

/// Computes a composite digest from a set of PCRs using a specified algorithm.
///
/// # Errors
///
/// Returns a `CliError` on failure.
pub(crate) fn pcr_composite_digest(pcrs: &[Pcr], alg: TpmAlgId) -> Result<Vec<u8>, CliError> {
    let mut composite = Vec::new();
    for pcr in pcrs {
        composite.extend_from_slice(&pcr.value);
    }
    match alg {
        TpmAlgId::Sha256 => Ok(Sha256::digest(&composite).to_vec()),
        TpmAlgId::Sha384 => Ok(Sha384::digest(&composite).to_vec()),
        TpmAlgId::Sha512 => Ok(Sha512::digest(&composite).to_vec()),
        _ => unimplemented!(),
    }
}

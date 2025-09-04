// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{CliError, TpmDevice};

use sha2::{Digest, Sha256, Sha384, Sha512};
use tpm2_protocol::{
    data::{TpmAlgId, TpmCap, TpmuCapabilities},
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

/// Computes a composite digest from a PCR read response using a specified algorithm.
///
/// # Errors
///
/// Returns a `CliError` on failure.
pub(crate) fn pcr_composite_digest(
    pcr_read_resp: &TpmPcrReadResponse,
    alg: TpmAlgId,
) -> Result<Vec<u8>, CliError> {
    let mut composite = Vec::new();
    for digest in pcr_read_resp.pcr_values.iter() {
        composite.extend_from_slice(digest);
    }
    match alg {
        TpmAlgId::Sha256 => Ok(Sha256::digest(&composite).to_vec()),
        TpmAlgId::Sha384 => Ok(Sha384::digest(&composite).to_vec()),
        TpmAlgId::Sha512 => Ok(Sha512::digest(&composite).to_vec()),
        _ => Err(CliError::Execution(format!(
            "unsupported hash algorithm for PCR composite digest: '{alg}'"
        ))),
    }
}

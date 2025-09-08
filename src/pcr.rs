// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

//! Abstractions and logic for handling Platform Configuration Registers (PCRs).

use crate::{
    device::{TpmDevice, TpmDeviceError, TPM_CAP_PROPERTY_MAX},
    policy::alg_from_str,
};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::fmt;
use tpm2_protocol::{
    data::{
        TpmAlgId, TpmCap, TpmCc, TpmlPcrSelection, TpmsPcrSelection, TpmuCapabilities,
        TPM_PCR_SELECT_MAX,
    },
    message::TpmPcrReadCommand,
    TpmBuffer, TpmErrorKind,
};

#[derive(Debug)]
pub enum PcrError {
    Device(TpmDeviceError),
    InvalidAlgorithm(TpmAlgId),
    InvalidPcrSelection(String),
    Tpm(TpmErrorKind),
}

impl std::error::Error for PcrError {}

impl fmt::Display for PcrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Device(e) => write!(f, "device: {e}"),
            Self::InvalidAlgorithm(alg) => write!(f, "invalid algorithm: {alg:?}"),
            Self::InvalidPcrSelection(s) => write!(f, "invalid PCR selection: {s}"),
            Self::Tpm(err) => write!(f, "TPM: {err}"),
        }
    }
}

impl From<TpmDeviceError> for PcrError {
    fn from(err: TpmDeviceError) -> Self {
        Self::Device(err)
    }
}

impl From<TpmErrorKind> for PcrError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Tpm(err)
    }
}

/// Represents the state of a single PCR register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pcr {
    pub bank: TpmAlgId,
    pub index: u32,
    pub value: Vec<u8>,
}

/// Represents the properties of a single PCR bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrBank {
    pub alg: TpmAlgId,
    pub count: usize,
}

/// Represents a user's selection of PCR indices for a specific bank.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcrSelection {
    pub alg: TpmAlgId,
    pub indices: Vec<u32>,
}

/// Discovers the list of available PCR banks and their sizes from the TPM.
pub fn pcr_get_bank_list(device: &mut TpmDevice) -> Result<Vec<PcrBank>, PcrError> {
    let cap_data = device.get_capability(TpmCap::Pcrs, 0, TPM_CAP_PROPERTY_MAX)?;
    let mut banks = Vec::new();
    for cap in cap_data {
        if let TpmuCapabilities::Pcrs(pcrs) = cap.data {
            for bank in pcrs.iter() {
                banks.push(PcrBank {
                    alg: bank.hash,
                    count: bank.pcr_select.len() * 8,
                });
            }
        }
    }
    if banks.is_empty() {
        return Err(PcrError::InvalidPcrSelection(
            "TPM reported no active PCR banks.".to_string(),
        ));
    }
    Ok(banks)
}

/// Parses a PCR selection string (e.g., "sha256:0,7+sha1:1") into a vector of
/// `PcrSelection`.
pub fn pcr_selection_vec_from_str(selection_str: &str) -> Result<Vec<PcrSelection>, PcrError> {
    let mut selections = Vec::new();
    for bank_str in selection_str.split('+') {
        let (alg_str, indices_str) = bank_str.split_once(':').ok_or_else(|| {
            PcrError::InvalidPcrSelection(format!("invalid bank format: '{bank_str}'"))
        })?;
        let alg =
            alg_from_str(alg_str).map_err(|e| PcrError::InvalidPcrSelection(e.to_string()))?;
        let indices: Vec<u32> = indices_str
            .split(',')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|e: std::num::ParseIntError| PcrError::InvalidPcrSelection(e.to_string()))?;
        selections.push(PcrSelection { alg, indices });
    }
    Ok(selections)
}

/// Converts a vector of `PcrSelection` into the low-level `TpmlPcrSelection`
/// format.
pub fn pcr_selection_vec_to_tpml(
    selections: &[PcrSelection],
    banks: &[PcrBank],
) -> Result<TpmlPcrSelection, PcrError> {
    let mut list = TpmlPcrSelection::new();
    for selection in selections {
        let bank = banks
            .iter()
            .find(|b| b.alg == selection.alg)
            .ok_or_else(|| {
                PcrError::InvalidPcrSelection(format!(
                    "PCR bank for algorithm {:?} not found or supported by TPM",
                    selection.alg
                ))
            })?;
        let pcr_select_size = bank.count.div_ceil(8);
        if pcr_select_size > TPM_PCR_SELECT_MAX {
            return Err(PcrError::InvalidPcrSelection(format!(
                "invalid select size {pcr_select_size} (> {TPM_PCR_SELECT_MAX})"
            )));
        }
        let mut pcr_select_bytes = vec![0u8; pcr_select_size];
        for &pcr_index in &selection.indices {
            let pcr_index = pcr_index as usize;
            if pcr_index >= bank.count {
                return Err(PcrError::InvalidPcrSelection(format!(
                    "invalid index {pcr_index} for {:?} bank (max is {})",
                    bank.alg,
                    bank.count - 1
                )));
            }
            pcr_select_bytes[pcr_index / 8] |= 1 << (pcr_index % 8);
        }
        list.try_push(TpmsPcrSelection {
            hash: selection.alg,
            pcr_select: TpmBuffer::try_from(pcr_select_bytes.as_slice())?,
        })?;
    }
    Ok(list)
}

/// Reads the selected PCRs and returns them in a structured format.
pub fn read(
    device: &mut TpmDevice,
    pcr_selection_in: &TpmlPcrSelection,
) -> Result<Vec<Pcr>, PcrError> {
    let cmd = TpmPcrReadCommand {
        pcr_selection_in: *pcr_selection_in,
    };
    let (resp, _) = device.execute(&cmd, &[])?;
    let pcr_read_resp = resp
        .PcrRead()
        .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::PcrRead))?;
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
                        .map_err(|_| PcrError::InvalidPcrSelection("PCR index overflow".into()))?;
                    let value = digest_iter.next().ok_or_else(|| {
                        PcrError::InvalidPcrSelection("PCR selection mismatch".to_string())
                    })?;
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

/// Computes a composite digest from a set of PCRs using a specified algorithm.
pub fn pcr_composite_digest(pcrs: &[Pcr], alg: TpmAlgId) -> Result<Vec<u8>, PcrError> {
    let mut composite = Vec::new();
    for pcr in pcrs {
        composite.extend_from_slice(&pcr.value);
    }
    match alg {
        TpmAlgId::Sha256 => Ok(Sha256::digest(&composite).to_vec()),
        TpmAlgId::Sha384 => Ok(Sha384::digest(&composite).to_vec()),
        TpmAlgId::Sha512 => Ok(Sha512::digest(&composite).to_vec()),
        _ => Err(PcrError::InvalidAlgorithm(alg)),
    }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::LogFormat,
    error::ParseError,
    key::{tpm_ecc_curve_to_str, Tpm2shAlgId},
    print::TpmPrint,
    TEARDOWN,
};
use std::{
    collections::HashSet,
    fmt::Debug,
    io::{self, IsTerminal, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc,
    },
    thread,
    time::Duration,
};
use thiserror::Error;

use log::trace;
use tpm2_protocol::{
    data::{
        TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmRc, TpmRcBase, TpmSt, TpmaCc, TpmsAuthCommand,
        TpmsCapabilityData, TpmsRsaParms, TpmtPublicParms, TpmuCapabilities, TpmuPublicParms,
    },
    message::{
        tpm_build_command, tpm_parse_response, TpmAuthResponses, TpmCommandBuild,
        TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmHeader, TpmResponseBody,
        TpmTestParmsCommand,
    },
    TpmErrorKind, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

pub const TPM_CAP_PROPERTY_MAX: u32 = 128;

#[derive(Debug, Error)]
pub enum TpmDeviceError {
    #[error("TPM device lock poisoned")]
    LockPoisoned,

    #[error("TPM device not provided for a device command")]
    NotProvided,

    #[error("I/O error with TPM device")]
    Io(#[from] io::Error),

    #[error("TPM protocol error")]
    Protocol(TpmErrorKind),

    #[error("TPM returned an error code: {0}")]
    Tpm(TpmRc),

    #[error("Mismatched response type for command '{command}'")]
    MismatchedResponse { command: TpmCc },

    #[error("Invalid response from TPM: {0}")]
    InvalidResponse(String),

    #[error("Failed to parse TPM response")]
    Parse(#[from] ParseError),
}

impl From<TpmErrorKind> for TpmDeviceError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Protocol(err)
    }
}

impl From<TpmRc> for TpmDeviceError {
    fn from(rc: TpmRc) -> Self {
        Self::Tpm(rc)
    }
}

/// A trait combining the I/O and safety traits required for a TPM transport.
pub trait TpmTransport: Read + Write + Send + Debug {}

/// Blanket implementation to automatically apply `TpmTransport` to all valid types.
impl<T: Read + Write + Send + Debug> TpmTransport for T {}

#[derive(Debug)]
pub struct TpmDevice {
    transport: Box<dyn TpmTransport>,
    log_format: LogFormat,
}

/// Checks if the TPM supports a given set of RSA parameters.
fn test_rsa_parms(device: &mut TpmDevice, key_bits: u16) -> Result<TpmRc, TpmDeviceError> {
    let cmd = TpmTestParmsCommand {
        parameters: TpmtPublicParms {
            object_type: TpmAlgId::Rsa,
            parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                key_bits,
                ..Default::default()
            }),
        },
    };
    device
        .execute(&cmd, &[])
        .map(|(_, _)| TpmRcBase::Success.into())
}

impl TpmDevice {
    /// Creates a new TPM device from an owned transport.
    pub fn new<T: TpmTransport + 'static>(transport: T, log_format: LogFormat) -> Self {
        Self {
            transport: Box::new(transport),
            log_format,
        }
    }

    /// Sends a command to the TPM and waits for the response.
    ///
    /// Displays a spinner on stderr if the operation takes longer than one second.
    ///
    /// # Errors
    ///
    /// This function will return an error if building the command fails, I/O
    /// with the device fails, or the TPM itself returns an error.
    pub fn execute<C>(
        &mut self,
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), TpmDeviceError>
    where
        C: TpmHeader + TpmCommandBuild + TpmPrint,
    {
        if let LogFormat::Pretty = self.log_format {
            trace!(target: "cli::device", "{}", C::COMMAND);
            command.print("", 1);
        }

        let mut command_buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut command_buf);
            let tag = if sessions.is_empty() {
                TpmSt::NoSessions
            } else {
                TpmSt::Sessions
            };
            tpm_build_command(command, tag, sessions, &mut writer)?;
            writer.len()
        };
        let command_bytes = &command_buf[..len];

        let (tx, rx) = mpsc::channel::<()>();
        let spinner_started = Arc::new(AtomicBool::new(false));
        if std::io::stderr().is_terminal() && C::COMMAND != TpmCc::FlushContext {
            let spinner_started = spinner_started.clone();
            thread::spawn(move || {
                if let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(Duration::from_secs(1)) {
                    spinner_started.store(true, Ordering::Relaxed);
                    let spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                    let message = "Waiting for TPM...";
                    let mut stderr = io::stderr();

                    let _ = write!(stderr, "\x1B[?25l");
                    let _ = stderr.flush();

                    let mut i = 0;
                    while !TEARDOWN.load(Ordering::Relaxed)
                        && rx.recv_timeout(Duration::from_millis(100)).is_err()
                    {
                        let frame = spinner_chars[i % spinner_chars.len()];
                        let _ = write!(stderr, "\r\x1B[1m\x1B[36m{frame} {message}\x1B[0m");
                        let _ = stderr.flush();
                        i += 1;
                    }
                }
            });
        }

        if let LogFormat::Plain = self.log_format {
            trace!(target: "cli::device", "Command: {}", hex::encode(command_bytes));
        }
        self.transport.write_all(command_bytes)?;
        self.transport.flush()?;

        let mut header = [0u8; 10];
        self.transport.read_exact(&mut header)?;

        let Ok(size_bytes): Result<[u8; 4], _> = header[2..6].try_into() else {
            return Err(TpmDeviceError::InvalidResponse(
                "input data underflow".to_string(),
            ));
        };
        let size = u32::from_be_bytes(size_bytes) as usize;

        if size < header.len() || size > TPM_MAX_COMMAND_SIZE {
            drop(tx);
            return Err(TpmDeviceError::InvalidResponse(format!(
                "Invalid response size in header: {size}"
            )));
        }

        let mut resp_buf = header.to_vec();
        resp_buf.resize(size, 0);
        self.transport.read_exact(&mut resp_buf[header.len()..])?;

        drop(tx);

        if spinner_started.load(Ordering::Relaxed) && !TEARDOWN.load(Ordering::Relaxed) {
            let mut stderr = io::stderr();
            let final_message = "✔ TPM operation complete.";
            let _ = write!(stderr, "\r\x1B[1m\x1B[32m{final_message}\x1B[0m\n\x1B[?25h");
            let _ = stderr.flush();
        }

        if let LogFormat::Plain = self.log_format {
            trace!(target: "cli::device", "Response: {}", hex::encode(&resp_buf));
        }

        let result = tpm_parse_response(C::COMMAND, &resp_buf)?;
        match &result {
            Ok((response, _)) => {
                if let LogFormat::Pretty = self.log_format {
                    trace!(target: "cli::device", "Response");
                    response.print("", 1);
                }
            }
            Err(_) => {
                if let LogFormat::Pretty = self.log_format {
                    trace!(target: "cli::device", "Response: {}", hex::encode(&resp_buf));
                }
            }
        }

        match result {
            Ok((response, auth)) => Ok((response, auth)),
            Err(rc) => Err(TpmDeviceError::Tpm(rc)),
        }
    }

    /// Retrieves all supported algorithms from the TPM by probing its capabilities.
    ///
    /// # Errors
    ///
    /// Returns a `TpmDeviceError` if querying the TPM fails.
    pub fn get_all_algorithms(&mut self) -> Result<Vec<(TpmAlgId, String)>, TpmDeviceError> {
        let mut supported_algs = Vec::new();

        let alg_props_vec = self.get_capability(TpmCap::Algs, 0, TPM_CAP_PROPERTY_MAX)?;
        let all_algs: HashSet<TpmAlgId> = alg_props_vec
            .iter()
            .flat_map(|cap_data| {
                if let TpmuCapabilities::Algs(p) = &cap_data.data {
                    p.iter().map(|prop| prop.alg).collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            })
            .collect();

        let name_algs: Vec<TpmAlgId> = [TpmAlgId::Sha256, TpmAlgId::Sha384, TpmAlgId::Sha512]
            .into_iter()
            .filter(|alg| all_algs.contains(alg))
            .collect();

        if all_algs.contains(&TpmAlgId::Rsa) {
            let rsa_key_sizes = [2048, 3072, 4096];
            for key_bits in rsa_key_sizes {
                if let Ok(rc) = test_rsa_parms(self, key_bits) {
                    if !rc.is_error() {
                        for &name_alg in &name_algs {
                            supported_algs.push((
                                TpmAlgId::Rsa,
                                format!("rsa:{}:{}", key_bits, Tpm2shAlgId(name_alg)),
                            ));
                        }
                    }
                }
            }
        }

        if all_algs.contains(&TpmAlgId::Ecc) {
            let ecc_caps = self.get_capability(TpmCap::EccCurves, 0, TPM_CAP_PROPERTY_MAX)?;
            let supported_curves: Vec<TpmEccCurve> = ecc_caps
                .iter()
                .flat_map(|cap_data| {
                    if let TpmuCapabilities::EccCurves(curves) = &cap_data.data {
                        curves.iter().copied().collect()
                    } else {
                        Vec::new()
                    }
                })
                .collect();

            for curve_id in supported_curves {
                for &name_alg in &name_algs {
                    supported_algs.push((
                        TpmAlgId::Ecc,
                        format!(
                            "ecc:{}:{}",
                            tpm_ecc_curve_to_str(curve_id),
                            Tpm2shAlgId(name_alg)
                        ),
                    ));
                }
            }
        }

        if all_algs.contains(&TpmAlgId::KeyedHash) {
            for &name_alg in &name_algs {
                supported_algs.push((
                    TpmAlgId::KeyedHash,
                    format!("keyedhash:{}", Tpm2shAlgId(name_alg)),
                ));
            }
        }

        Ok(supported_algs)
    }

    /// Retrieves all handles of a specific type from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `TpmDeviceError` if the `get_capability` call to the TPM device fails.
    pub fn get_all_handles(&mut self, handle_type: u32) -> Result<Vec<u32>, TpmDeviceError> {
        let cap_data_vec =
            self.get_capability(TpmCap::Handles, handle_type, TPM_CAP_PROPERTY_MAX)?;
        let handles: Vec<u32> = cap_data_vec
            .into_iter()
            .flat_map(|cap_data| {
                if let TpmuCapabilities::Handles(handles) = cap_data.data {
                    handles.iter().copied().collect()
                } else {
                    Vec::new()
                }
            })
            .collect();
        Ok(handles)
    }

    /// Fetches and returns all capabilities of a certain type from the TPM.
    ///
    /// # Errors
    ///
    /// This function will return an error if the underlying `execute` call fails
    /// or if the TPM returns a response of an unexpected type.
    pub fn get_capability(
        &mut self,
        cap: TpmCap,
        mut property: u32,
        count: u32,
    ) -> Result<Vec<TpmsCapabilityData>, TpmDeviceError> {
        let mut all_caps = Vec::new();
        loop {
            let cmd = TpmGetCapabilityCommand {
                cap,
                property,
                property_count: count,
            };

            let (resp, _) = self.execute(&cmd, &[])?;
            let TpmGetCapabilityResponse {
                more_data,
                capability_data,
            } = resp
                .GetCapability()
                .map_err(|_| TpmDeviceError::MismatchedResponse {
                    command: TpmCc::GetCapability,
                })?;

            let next_prop = if more_data.into() {
                match &capability_data.data {
                    TpmuCapabilities::Algs(algs) => algs.last().map(|p| p.alg as u32 + 1),
                    TpmuCapabilities::Handles(handles) => handles.last().map(|&h| h + 1),
                    TpmuCapabilities::Commands(commands) => commands
                        .last()
                        .map(|c| (c.bits() & TpmaCc::COMMAND_INDEX.bits()) + 1),
                    TpmuCapabilities::Pcrs(_) => None,
                    TpmuCapabilities::EccCurves(curves) => curves.last().map(|&c| c as u32 + 1),
                    TpmuCapabilities::TpmProperties(props) => {
                        props.last().map(|p| p.property as u32 + 1)
                    }
                }
            } else {
                None
            };

            all_caps.push(capability_data);

            if let Some(p) = next_prop {
                property = p;
            } else {
                break;
            }
        }
        Ok(all_caps)
    }
}

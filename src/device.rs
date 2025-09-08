// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::LogFormat,
    key::{tpm_ecc_curve_to_str, Tpm2shAlgId},
    print::TpmPrint,
    transport::Transport,
    TEARDOWN,
};
use std::{
    collections::HashSet,
    io::{self, IsTerminal, Write},
    sync::{atomic::Ordering, mpsc},
    thread,
    time::{Duration, Instant},
};

use log::trace;
use tpm2_protocol::{
    data::{
        TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmRc, TpmRcBase, TpmSt, TpmaCc, TpmsAuthCommand,
        TpmsCapabilityData, TpmsRsaParms, TpmtPublicParms, TpmuCapabilities, TpmuPublicParms,
    },
    message::{
        tpm_build_command, tpm_parse_response, TpmAuthResponses, TpmCommandBuild,
        TpmFlushContextResponse, TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmHeader,
        TpmResponseBody, TpmTestParmsCommand,
    },
    TpmErrorKind, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

pub const TPM_CAP_PROPERTY_MAX: u32 = 128;

/// A type-erased object safe TPM command object
pub trait TpmCommandObject: TpmPrint {
    fn tpm_cc(&self) -> TpmCc;

    /// Build the command.
    ///
    /// # Errors
    ///
    /// Returns `TpmErrorKind` on failure analogous to `tpm_build_command`
    /// behavior.
    fn build(
        &self,
        tag: TpmSt,
        sessions: &[TpmsAuthCommand],
        writer: &mut TpmWriter,
    ) -> Result<(), TpmErrorKind>;
}

impl<T> TpmCommandObject for T
where
    T: TpmHeader + TpmCommandBuild + TpmPrint,
{
    fn tpm_cc(&self) -> TpmCc {
        TpmHeader::tpm_cc(self)
    }

    fn build(
        &self,
        tag: TpmSt,
        sessions: &[TpmsAuthCommand],
        writer: &mut TpmWriter,
    ) -> Result<(), TpmErrorKind> {
        tpm_build_command(self, tag, sessions, writer)
    }
}

#[derive(Debug)]
pub enum TpmDeviceError {
    Io(std::io::Error),
    ResponseMismatch(TpmCc),
    ResponseOverflow,
    ResponseUnderflow,
    Tpm(TpmErrorKind),
    TpmRc(TpmRc),
    ThreadPanic,
}

impl std::error::Error for TpmDeviceError {}

impl std::fmt::Display for TpmDeviceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(s) => write!(f, "I/O: {s}"),
            Self::ResponseMismatch(cc) => write!(f, "response mismatch: {cc}"),
            Self::ResponseOverflow => write!(f, "response overflow"),
            Self::ResponseUnderflow => write!(f, "response underflow"),
            Self::Tpm(err) => write!(f, "TPM: {err}"),
            Self::TpmRc(rc) => write!(f, "TPM RC: {rc}"),
            Self::ThreadPanic => write!(f, "background I/O thread panicked"),
        }
    }
}
impl From<std::io::Error> for TpmDeviceError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<TpmErrorKind> for TpmDeviceError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Tpm(err)
    }
}

impl From<TpmRc> for TpmDeviceError {
    fn from(rc: TpmRc) -> Self {
        Self::TpmRc(rc)
    }
}

#[derive(Debug)]
pub struct TpmDevice {
    transport: Box<dyn Transport>,
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
    pub fn new(transport: impl Transport + 'static, log_format: LogFormat) -> Self {
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
    pub fn execute(
        &mut self,
        command: &dyn TpmCommandObject,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), TpmDeviceError> {
        let cc = command.tpm_cc();
        if let LogFormat::Pretty = self.log_format {
            trace!(target: "cli::device", "{cc}");
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
            command.build(tag, sessions, &mut writer)?;
            writer.len()
        };
        let command_bytes = &command_buf[..len];

        if !std::io::stderr().is_terminal() || cc == TpmCc::FlushContext {
            if let LogFormat::Plain = self.log_format {
                trace!(target: "cli::device", "Command: {}", hex::encode(command_bytes));
            }
            self.transport.send(command_bytes)?;
        } else {
            return self.execute_interactive(command_bytes, cc);
        }

        let resp_buf = self.transport.receive()?;

        if let LogFormat::Plain = self.log_format {
            trace!(target: "cli::device", "Response: {}", hex::encode(&resp_buf));
        }
        self.parse_response(&resp_buf, cc)
    }

    fn parse_response(
        &self,
        resp_buf: &[u8],
        cc: TpmCc,
    ) -> Result<(TpmResponseBody, TpmAuthResponses), TpmDeviceError> {
        let result = tpm_parse_response(cc, resp_buf)?;
        if let LogFormat::Pretty = self.log_format {
            match &result {
                Ok((response, _)) => {
                    trace!(target: "cli::device", "Response");
                    response.print("", 1);
                }
                Err(_) => {
                    trace!(target: "cli::device", "Response: {}", hex::encode(resp_buf));
                }
            }
        }
        result.map_err(TpmDeviceError::TpmRc)
    }

    fn execute_interactive(
        &mut self,
        command_bytes: &[u8],
        cc: TpmCc,
    ) -> Result<(TpmResponseBody, TpmAuthResponses), TpmDeviceError> {
        let (io_tx, io_rx) = mpsc::channel();
        let mut transport = std::mem::replace(
            &mut self.transport,
            Box::new(crate::transport::PipeTransport::new()),
        );
        let command_bytes_owned = command_bytes.to_vec();

        thread::spawn(move || {
            let res = (|| -> Result<Vec<u8>, TpmDeviceError> {
                transport.send(&command_bytes_owned)?;
                transport.receive()
            })();
            let _ = io_tx.send((res, transport));
        });

        let (spinner_tx, spinner_rx) = mpsc::channel();
        thread::spawn(move || {
            while spinner_tx.send(()).is_ok() {
                thread::sleep(Duration::from_millis(100));
            }
        });

        let start_time = Instant::now();
        let mut spinner_active = false;
        let stderr = io::stderr();
        let spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
        let mut i = 0;

        loop {
            if TEARDOWN.load(Ordering::Relaxed) {
                break;
            }
            match io_rx.try_recv() {
                Ok((io_result, transport_back)) => {
                    self.transport = transport_back;
                    if spinner_active {
                        let final_message = "✔ TPM operation complete.";
                        let _ = write!(
                            stderr.lock(),
                            "\r\x1B[1m\x1B[32m{final_message}\x1B[0m\n\x1B[?25h"
                        );
                    }
                    return self.parse_response(&io_result?, cc);
                }
                Err(mpsc::TryRecvError::Disconnected) => return Err(TpmDeviceError::ThreadPanic),
                Err(mpsc::TryRecvError::Empty) => {
                    if !spinner_active && start_time.elapsed() > Duration::from_secs(1) {
                        spinner_active = true;
                        let _ = write!(stderr.lock(), "\x1B[?25l");
                    }
                    if spinner_active {
                        let frame = spinner_chars[i % spinner_chars.len()];
                        let message = "Waiting for TPM...";
                        let _ = write!(stderr.lock(), "\r\x1B[1m\x1B[36m{frame} {message}\x1B[0m");
                        let _ = stderr.lock().flush();
                        i += 1;
                    }
                    let _ = spinner_rx.recv_timeout(Duration::from_millis(100));
                }
            }
        }
        Ok((
            TpmResponseBody::FlushContext(TpmFlushContextResponse {}),
            TpmAuthResponses::default(),
        ))
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
                .map_err(|_| TpmDeviceError::ResponseMismatch(TpmCc::GetCapability))?;

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

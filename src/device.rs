// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{Cli, LogFormat},
    error::ParseError,
    key::{tpm_alg_id_to_str, tpm_ecc_curve_to_str},
    parser::PolicyExpr,
    print::TpmPrint,
    session::session_from_args,
    uri::Uri,
    util::build_to_vec,
    CliError,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::{
    collections::HashSet,
    fmt::Debug,
    io::{self, IsTerminal, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc,
    },
    time::Duration,
};

use log::{trace, warn};
use tpm2_protocol::{
    data::{
        Tpm2bName, TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmRh, TpmSt, TpmaCc, TpmlPcrSelection,
        TpmsAuthCommand, TpmsCapabilityData, TpmsContext, TpmsRsaParms, TpmtPublic,
        TpmtPublicParms, TpmuCapabilities, TpmuPublicParms,
    },
    message::{
        tpm_build_command, tpm_parse_response, TpmAuthResponses, TpmCommandBuild,
        TpmContextLoadCommand, TpmContextSaveCommand, TpmEccParametersCommand,
        TpmEvictControlCommand, TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmHeader,
        TpmPcrReadCommand, TpmPcrReadResponse, TpmReadPublicCommand, TpmResponseBody,
        TpmTestParmsCommand,
    },
    TpmParse, TpmPersistent, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

pub const TPM_CAP_PROPERTY_MAX: u32 = 128;

#[derive(Debug)]
pub enum TpmDeviceErrorKind {
    NotProvided,
    LockPoisoned,
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
fn test_rsa_parms(device: &mut TpmDevice, key_bits: u16) -> Result<(), CliError> {
    let cmd = TpmTestParmsCommand {
        parameters: TpmtPublicParms {
            object_type: TpmAlgId::Rsa,
            parameters: TpmuPublicParms::Rsa(TpmsRsaParms {
                key_bits,
                ..Default::default()
            }),
        },
    };
    device.execute(&cmd, &[]).map(|_| ())
}

/// Checks if the TPM supports a given ECC curve.
fn test_ecc_parms(device: &mut TpmDevice, curve_id: TpmEccCurve) -> Result<(), CliError> {
    let cmd = TpmEccParametersCommand { curve_id };
    device.execute(&cmd, &[]).map(|_| ())
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
    ) -> Result<(TpmResponseBody, TpmAuthResponses), CliError>
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
            std::thread::spawn(move || {
                if let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(Duration::from_secs(1)) {
                    spinner_started.store(true, Ordering::Relaxed);
                    let spinner_chars = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
                    let message = "Waiting for TPM...";
                    let mut stderr = io::stderr();

                    let _ = write!(stderr, "\x1B[?25l");
                    let _ = stderr.flush();

                    let mut i = 0;
                    while let Err(RecvTimeoutError::Timeout) =
                        rx.recv_timeout(Duration::from_millis(100))
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
            return Err(CliError::Execution("input data underflow".to_string()));
        };
        let size = u32::from_be_bytes(size_bytes) as usize;

        if size < header.len() || size > TPM_MAX_COMMAND_SIZE {
            drop(tx);
            return Err(
                ParseError::Custom(format!("Invalid response size in header: {size}")).into(),
            );
        }

        let mut resp_buf = header.to_vec();
        resp_buf.resize(size, 0);
        self.transport.read_exact(&mut resp_buf[header.len()..])?;

        drop(tx);

        if spinner_started.load(Ordering::Relaxed) {
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
            Ok((rc, response_body, _)) => {
                if let LogFormat::Pretty = self.log_format {
                    trace!(target: "cli::device", "Response (rc={rc})");
                    response_body.print("", 1);
                }
            }
            Err((rc, _)) => {
                trace!(target: "cli::device", "Error Response (rc={rc})");
                if let LogFormat::Pretty = self.log_format {
                    trace!(target: "cli::device", "Response: {}", hex::encode(&resp_buf));
                }
            }
        }

        match result {
            Ok((rc, response, auth)) => {
                if rc.is_warning() {
                    warn!(target: "cli::device", "TPM command completed with a warning: rc = {rc}");
                }
                Ok((response, auth))
            }
            Err((rc, _)) => Err(CliError::TpmRc(rc)),
        }
    }

    /// Loads a TPM context from URI, and return a pair, where the boolean flag
    /// tells whether the context needs to be cleaned up or not.
    ///
    /// `tpm://` URIs are considered to be managed by the caller, and thus they are
    /// paired with `false`. Other types of URIs are paired with `true`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` on parsing or TPM command failure.
    pub fn context_load(&mut self, uri: &Uri) -> Result<(TpmTransient, bool), CliError> {
        match uri.ast() {
            PolicyExpr::TpmHandle(handle) => Ok((TpmTransient(*handle), false)),
            PolicyExpr::Data { .. } | PolicyExpr::FilePath(_) => {
                let context_blob = uri.to_bytes()?;
                let (context, remainder) = TpmsContext::parse(&context_blob)?;
                if !remainder.is_empty() {
                    return Err(ParseError::Custom("trailing data".to_string()).into());
                }
                let cmd = TpmContextLoadCommand { context };
                let (resp, _) = self.execute(&cmd, &[])?;
                let resp = resp
                    .ContextLoad()
                    .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
                Ok((resp.loaded_handle, true))
            }
            _ => Err(ParseError::Custom(format!("invalid URI: '{uri}'")).into()),
        }
    }

    /// Saves a transient object context and writes it to a writer as a data URI.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the TPM command or I/O fails.
    pub fn context_save<W: Write>(
        &mut self,
        handle: TpmTransient,
        writer: &mut W,
    ) -> Result<(), CliError> {
        let save_cmd = TpmContextSaveCommand {
            save_handle: handle,
        };
        let (resp, _) = self.execute(&save_cmd, &[])?;
        let save_resp = resp
            .ContextSave()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let context_bytes = build_to_vec(&save_resp.context)?;

        writeln!(
            writer,
            "data://base64,{}",
            base64_engine.encode(context_bytes)
        )?;
        Ok(())
    }

    /// Makes a transient object persistent.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the `EvictControl` command fails.
    pub fn evict_control(
        &mut self,
        cli: &Cli,
        object_handle: u32,
        persistent_handle: TpmPersistent,
    ) -> Result<(), CliError> {
        let auth_handle = TpmRh::Owner;
        let cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: object_handle.into(),
            persistent_handle,
        };
        let handles = [auth_handle as u32, object_handle];
        let sessions = session_from_args(&cmd, &handles, cli)?;
        let (resp, _) = self.execute(&cmd, &sessions)?;
        resp.EvictControl()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        Ok(())
    }

    /// Retrieves all supported algorithms from the TPM by probing its capabilities.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if querying the TPM fails.
    pub fn get_all_algorithms(&mut self) -> Result<Vec<(TpmAlgId, String)>, CliError> {
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
                if test_rsa_parms(self, key_bits).is_ok() {
                    for &name_alg in &name_algs {
                        supported_algs.push((
                            TpmAlgId::Rsa,
                            format!("rsa:{}:{}", key_bits, tpm_alg_id_to_str(name_alg)),
                        ));
                    }
                }
            }
        }

        if all_algs.contains(&TpmAlgId::Ecc) {
            let ecc_curves = [
                TpmEccCurve::NistP256,
                TpmEccCurve::NistP384,
                TpmEccCurve::NistP521,
            ];
            for curve_id in ecc_curves {
                if test_ecc_parms(self, curve_id).is_ok() {
                    for &name_alg in &name_algs {
                        supported_algs.push((
                            TpmAlgId::Ecc,
                            format!(
                                "ecc:{}:{}",
                                tpm_ecc_curve_to_str(curve_id),
                                tpm_alg_id_to_str(name_alg)
                            ),
                        ));
                    }
                }
            }
        }

        if all_algs.contains(&TpmAlgId::KeyedHash) {
            for &name_alg in &name_algs {
                supported_algs.push((
                    TpmAlgId::KeyedHash,
                    format!("keyedhash:{}", tpm_alg_id_to_str(name_alg)),
                ));
            }
        }

        Ok(supported_algs)
    }

    /// Retrieves all handles of a specific type from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the `get_capability` call to the TPM device fails.
    pub fn get_all_handles(&mut self, handle_type: TpmRh) -> Result<Vec<u32>, CliError> {
        let cap_data_vec =
            self.get_capability(TpmCap::Handles, handle_type as u32, TPM_CAP_PROPERTY_MAX)?;
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
    ) -> Result<Vec<TpmsCapabilityData>, CliError> {
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
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

            let next_prop = if more_data.into() {
                match &capability_data.data {
                    TpmuCapabilities::Algs(algs) => algs.last().map(|p| p.alg as u32 + 1),
                    TpmuCapabilities::Handles(handles) => handles.last().map(|&h| h + 1),
                    TpmuCapabilities::Commands(commands) => commands
                        .last()
                        .map(|c| (c.bits() & TpmaCc::COMMAND_INDEX.bits()) + 1),
                    TpmuCapabilities::Pcrs(_) => None,
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

    /// Reads PCR values from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the TPM command fails.
    pub fn pcr_read(
        &mut self,
        pcr_selection_in: &TpmlPcrSelection,
    ) -> Result<TpmPcrReadResponse, CliError> {
        let cmd = TpmPcrReadCommand {
            pcr_selection_in: *pcr_selection_in,
        };
        let (resp, _) = self.execute(&cmd, &[])?;
        resp.PcrRead()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))
    }

    /// Reads the public area and name of a TPM object.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the `ReadPublic` command fails.
    pub fn read_public(
        &mut self,
        handle: TpmTransient,
    ) -> Result<(TpmtPublic, Tpm2bName), CliError> {
        let cmd = TpmReadPublicCommand {
            object_handle: handle.0.into(),
        };
        let (resp, _) = self.execute(&cmd, &[])?;
        let read_public_resp = resp
            .ReadPublic()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        Ok((read_public_resp.out_public.inner, read_public_resp.name))
    }
}

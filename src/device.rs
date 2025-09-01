// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::{Cli, LogFormat},
    error::ParseError,
    print::TpmPrint,
    uri, CliError,
};

use std::{
    collections::HashSet,
    fmt::Debug,
    io::{self, IsTerminal, Read, Write},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc, Mutex,
    },
    time::Duration,
};

use log::{trace, warn};
use tpm2_protocol::{
    self,
    data::{
        Tpm2bName, TpmAlgId, TpmCap, TpmCc, TpmRh, TpmSt, TpmaCc, TpmsAuthCommand,
        TpmsCapabilityData, TpmsContext, TpmtPublic, TpmuCapabilities,
    },
    message::{
        tpm_build_command, tpm_parse_response, TpmAuthResponses, TpmCommandBuild,
        TpmContextLoadCommand, TpmFlushContextCommand, TpmGetCapabilityCommand,
        TpmGetCapabilityResponse, TpmHeader, TpmReadPublicCommand, TpmResponseBody,
    },
    TpmParse, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

pub const TPM_CAP_PROPERTY_MAX: u32 = 128;

/// A wrapper for a transient handle that ensures it is flushed when it goes out of scope.
#[derive(Debug)]
pub struct ScopedHandle {
    handle: TpmTransient,
    device: Arc<Mutex<TpmDevice>>,
}

impl ScopedHandle {
    /// Creates a new scoped handle.
    #[must_use]
    pub fn new(handle: TpmTransient, device: Arc<Mutex<TpmDevice>>) -> Self {
        Self { handle, device }
    }

    /// Creates a new scoped handle by resolving a URI. This can load a context if needed.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the URI is invalid or the context cannot be loaded.
    pub fn from_uri(
        device_arc: &Arc<Mutex<TpmDevice>>,
        log_format: LogFormat,
        uri: &str,
    ) -> Result<ScopedHandle, CliError> {
        if uri.starts_with("tpm://") {
            let handle = uri::uri_to_tpm_handle(uri)?;
            Ok(ScopedHandle::new(TpmTransient(handle), device_arc.clone()))
        } else if uri.starts_with("data://") || uri.starts_with("file://") {
            let context_blob = uri::uri_to_bytes(uri, &[])?;
            let (context, remainder) = TpmsContext::parse(&context_blob)?;
            if !remainder.is_empty() {
                return Err(ParseError::Custom("trailing data".to_string()).into());
            }
            let mut device = device_arc
                .lock()
                .map_err(|_| CliError::Execution("no transport".to_string()))?;
            let load_cmd = TpmContextLoadCommand { context };
            let (resp, _) = device.execute(log_format, &load_cmd, &[])?;
            let load_resp = resp
                .ContextLoad()
                .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
            Ok(ScopedHandle::new(
                load_resp.loaded_handle,
                device_arc.clone(),
            ))
        } else {
            Err(ParseError::Custom(format!("invalid URI: '{uri}'")).into())
        }
    }

    /// Returns the inner handle.
    #[must_use]
    pub const fn handle(&self) -> TpmTransient {
        self.handle
    }

    /// Consumes the guard without flushing the handle. This should be used when
    /// the handle has been consumed by another command, such as `TPM2_EvictControl`.
    pub fn forget(self) {
        std::mem::forget(self);
    }
}

impl Drop for ScopedHandle {
    fn drop(&mut self) {
        let handle = self.handle;
        if let Ok(mut device) = self.device.lock() {
            let cmd = TpmFlushContextCommand {
                flush_handle: handle.into(),
            };
            if let Err(err) = device.execute(LogFormat::Plain, &cmd, &[]) {
                warn!(target: "cli::device", "tpm://{handle:#010x}: {err}");
            }
        } else {
            warn!(target: "cli::device", "tpm://{handle:#010x}: no transport");
        }
    }
}

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
}

impl TpmDevice {
    /// Creates a new TPM device from an owned transport.
    pub fn new<T: TpmTransport + 'static>(transport: T) -> Self {
        Self {
            transport: Box::new(transport),
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
        log_format: LogFormat,
        command: &C,
        sessions: &[TpmsAuthCommand],
    ) -> Result<(TpmResponseBody, TpmAuthResponses), CliError>
    where
        C: TpmHeader + TpmCommandBuild + TpmPrint,
    {
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

        match log_format {
            LogFormat::Pretty => {
                trace!(target: "cli::device", "{}", C::COMMAND);
                command.print("", 1);
            }
            LogFormat::Plain => {
                trace!(target: "cli::device", "Command: {}", hex::encode(command_bytes));
            }
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

        let result = tpm_parse_response(C::COMMAND, &resp_buf)?;
        match &result {
            Ok((rc, response_body, _)) => match log_format {
                LogFormat::Pretty => {
                    trace!(target: "cli::device", "Response (rc={rc})");
                    response_body.print("", 1);
                }
                LogFormat::Plain => {
                    trace!(target: "cli::device", "Response: {}", hex::encode(&resp_buf));
                }
            },
            Err((rc, _)) => {
                trace!(target: "cli::device", "Error Response (rc={rc})");
                trace!(target: "cli::device", "Response: {}", hex::encode(&resp_buf));
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

    /// Retrieves all algorithms from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the `get_capability` call to the TPM device fails.
    pub fn get_all_algorithms(&mut self, cli: &Cli) -> Result<HashSet<TpmAlgId>, CliError> {
        let cap_data_vec = self.get_capability(cli, TpmCap::Algs, 0, TPM_CAP_PROPERTY_MAX)?;
        let algorithms: HashSet<TpmAlgId> = cap_data_vec
            .into_iter()
            .flat_map(|cap_data| {
                if let TpmuCapabilities::Algs(p) = cap_data.data {
                    p.iter().map(|prop| prop.alg).collect::<Vec<_>>()
                } else {
                    Vec::new()
                }
            })
            .collect();
        Ok(algorithms)
    }

    /// Retrieves all handles of a specific type from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the `get_capability` call to the TPM device fails.
    pub fn get_all_handles(&mut self, cli: &Cli, handle_type: TpmRh) -> Result<Vec<u32>, CliError> {
        let cap_data_vec = self.get_capability(
            cli,
            TpmCap::Handles,
            handle_type as u32,
            TPM_CAP_PROPERTY_MAX,
        )?;
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
        cli: &Cli,
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

            let (resp, _) = self.execute(cli.log_format, &cmd, &[])?;
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

    /// Reads the public area and name of a TPM object.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the `ReadPublic` command fails.
    pub fn read_public(
        &mut self,
        log_format: LogFormat,
        handle: TpmTransient,
    ) -> Result<(TpmtPublic, Tpm2bName), CliError> {
        let cmd = TpmReadPublicCommand {
            object_handle: handle.0.into(),
        };
        let (resp, _) = self.execute(log_format, &cmd, &[])?;
        let read_public_resp = resp
            .ReadPublic()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        Ok((read_public_resp.out_public.inner, read_public_resp.name))
    }
}

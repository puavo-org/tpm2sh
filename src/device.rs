// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{get_log_format, pretty_printer::PrettyTrace, TpmError, POOL};
use log::{trace, warn};
use std::{
    fmt::Debug,
    io::{self, IsTerminal, Read, Write},
    sync::mpsc::{self, RecvTimeoutError},
    time::Duration,
};
use tpm2_protocol::{
    self,
    data::{self, TpmSt, TpmaCc, TpmuCapabilities},
    message::{TpmGetCapabilityCommand, TpmGetCapabilityResponse, TpmResponseBody},
    TpmWriter, TPM_MAX_COMMAND_SIZE,
};

pub const TPM_CAP_PROPERTY_MAX: u32 = 128;

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
        command: &C,
        sessions: &[tpm2_protocol::data::TpmsAuthCommand],
    ) -> Result<(TpmResponseBody, tpm2_protocol::message::TpmAuthResponses), TpmError>
    where
        C: tpm2_protocol::message::TpmHeaderCommand + PrettyTrace,
    {
        let log_format = get_log_format();
        let mut command_buf = [0u8; TPM_MAX_COMMAND_SIZE];
        let len = {
            let mut writer = TpmWriter::new(&mut command_buf);
            let tag = if sessions.is_empty() {
                TpmSt::NoSessions
            } else {
                TpmSt::Sessions
            };
            tpm2_protocol::message::tpm_build_command(command, tag, sessions, &mut writer)?;
            writer.len()
        };
        let command_bytes = &command_buf[..len];

        let (tx, rx) = mpsc::channel::<()>();
        if std::io::stderr().is_terminal() && C::COMMAND != data::TpmCc::FlushContext {
            POOL.execute(move || {
                if let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(Duration::from_secs(1)) {
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

                    let final_message = "✔ TPM operation complete.";
                    let _ = write!(stderr, "\r\x1B[1m\x1B[32m{final_message}\x1B[0m\n\x1B[?25h");
                    let _ = stderr.flush();
                }
            });
        }

        match log_format {
            crate::cli::LogFormat::Pretty => {
                trace!(target: "cli::device", "{}", C::COMMAND);
                command.pretty_trace("", 1);
            }
            crate::cli::LogFormat::Plain => {
                trace!(target: "cli::device", "Command: {}", hex::encode(command_bytes));
            }
        }
        self.transport.write_all(command_bytes)?;
        self.transport.flush()?;

        let mut header = [0u8; 10];
        self.transport.read_exact(&mut header)?;

        let Ok(size_bytes): Result<[u8; 4], _> = header[2..6].try_into() else {
            return Err(TpmError::Execution(
                "Could not read response size".to_string(),
            ));
        };
        let size = u32::from_be_bytes(size_bytes) as usize;

        if size < header.len() || size > TPM_MAX_COMMAND_SIZE {
            drop(tx);
            return Err(TpmError::Parse(format!(
                "Invalid response size in header: {size}"
            )));
        }

        let mut resp_buf = header.to_vec();
        resp_buf.resize(size, 0);
        self.transport.read_exact(&mut resp_buf[header.len()..])?;

        drop(tx);

        let result = tpm2_protocol::message::tpm_parse_response(C::COMMAND, &resp_buf)?;

        match &result {
            Ok((rc, response_body, _)) => match log_format {
                crate::cli::LogFormat::Pretty => {
                    trace!(target: "cli::device", "Response (rc={rc})");
                    response_body.pretty_trace("", 1);
                }
                crate::cli::LogFormat::Plain => {
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
            Err((rc, _)) => Err(TpmError::TpmRc(rc)),
        }
    }

    /// Retrieves all handles of a specific type from the TPM.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the `get_capability` call to the TPM device fails.
    pub fn get_all_handles(&mut self, handle_type: data::TpmRh) -> Result<Vec<u32>, TpmError> {
        let cap_data_vec = self.get_capability(
            data::TpmCap::Handles,
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
        cap: data::TpmCap,
        mut property: u32,
        count: u32,
    ) -> Result<Vec<data::TpmsCapabilityData>, TpmError> {
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
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;

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
}

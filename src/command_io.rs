// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{cli, AuthSession, TpmError};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use polling::{Event, Events, Poller};
use std::io::{self, IsTerminal, Read, Write};
use std::time::Duration;
use tpm2_protocol::data::{Tpm2bAuth, Tpm2bNonce, TpmAlgId, TpmaSession};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

/// Checks if stdin has data ready to be read within a 100ms timeout.
///
/// # Safety
///
/// This function contains an `unsafe` block that calls `poller.add()`. This is
/// considered safe because the file descriptor or handle for `stdin` is
/// guaranteed to be a valid, open resource for the duration of the process.
fn stdin_ready() -> Result<bool, TpmError> {
    #[cfg(any(unix, windows))]
    {
        let poller = Poller::new()?;
        let mut events = Events::new();

        #[cfg(unix)]
        let source = io::stdin().as_raw_fd();
        #[cfg(windows)]
        let source = io::stdin().as_raw_handle();

        unsafe { poller.add(source, Event::readable(0))? };

        poller.wait(&mut events, Some(Duration::from_millis(100)))?;
        Ok(!events.is_empty())
    }

    #[cfg(not(any(unix, windows)))]
    {
        Ok(true)
    }
}

/// Manages the streaming I/O for a command in the JSON pipeline.
pub struct CommandIo<W: Write> {
    writer: W,
    input_objects: Vec<cli::Object>,
    output_objects: Vec<cli::Object>,
    log_format: cli::LogFormat,
    hydrated: bool,
}

impl<W: Write> CommandIo<W> {
    /// Creates a new command context for the pipeline. Does not read stdin.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if reading from the input stream fails.
    pub fn new(writer: W, log_format: cli::LogFormat) -> Result<Self, TpmError> {
        Ok(Self {
            writer,
            input_objects: Vec::new(),
            output_objects: Vec::new(),
            log_format,
            hydrated: false,
        })
    }

    /// Reads from stdin on the first call, populating the input objects.
    fn hydrate(&mut self) -> Result<(), TpmError> {
        if self.hydrated {
            return Ok(());
        }

        let mut input_string = String::new();
        let mut should_read = !io::stdin().is_terminal();

        if io::stdin().is_terminal() {
            should_read = stdin_ready()?;
        }

        if should_read {
            io::stdin().read_to_string(&mut input_string)?;
        }

        if !input_string.trim().is_empty() {
            let doc = json::parse(&input_string)?;
            if !doc["objects"].is_array() {
                return Err(TpmError::Parse(
                    "input JSON document is missing 'objects' array".to_string(),
                ));
            }
            for value in doc["objects"].members() {
                self.input_objects.push(cli::Object::from_json(value)?);
            }
        }

        self.hydrated = true;
        Ok(())
    }

    /// Returns the log format.
    pub const fn log_format(&self) -> cli::LogFormat {
        self.log_format
    }

    /// Returns a mutable reference to the underlying writer.
    pub fn writer(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Finds and removes the session object from the input pipeline, if it exists.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if an object appears to be a session but is malformed.
    pub fn take_session(&mut self) -> Result<Option<AuthSession>, TpmError> {
        self.hydrate()?;
        let session_pos = self
            .input_objects
            .iter()
            .position(|obj| matches!(obj, cli::Object::Session(_)));

        if let Some(pos) = session_pos {
            let obj = self.input_objects.remove(pos);
            if let cli::Object::Session(session_data) = obj {
                let original_json = cli::Object::Session(session_data.clone()).to_json().dump();

                let session = AuthSession {
                    handle: session_data.handle.into(),
                    nonce_tpm: Tpm2bNonce::try_from(
                        base64_engine.decode(session_data.nonce_tpm)?.as_slice(),
                    )?,
                    attributes: TpmaSession::from_bits_truncate(session_data.attributes),
                    hmac_key: Tpm2bAuth::try_from(
                        base64_engine.decode(session_data.hmac_key)?.as_slice(),
                    )?,
                    auth_hash: TpmAlgId::try_from(session_data.auth_hash).map_err(|()| {
                        TpmError::Parse("invalid auth_hash in session".to_string())
                    })?,
                    original_json,
                };
                return Ok(Some(session));
            }
        }

        Ok(None)
    }

    /// Finds and removes the first object from the input pipeline that matches a predicate.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if no matching object is found.
    pub fn consume_object<F>(&mut self, predicate: F) -> Result<cli::Object, TpmError>
    where
        F: FnMut(&cli::Object) -> bool,
    {
        self.hydrate()?;
        let pos = self
            .input_objects
            .iter()
            .position(predicate)
            .ok_or_else(|| {
                TpmError::Execution("required object not found in input pipeline".to_string())
            })?;
        Ok(self.input_objects.remove(pos))
    }

    /// Consumes and returns all input objects.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if reading from stdin fails.
    pub fn consume_all_objects(&mut self) -> Result<Vec<cli::Object>, TpmError> {
        self.hydrate()?;
        Ok(std::mem::take(&mut self.input_objects))
    }

    /// Adds an object to be written to the output stream upon finalization.
    pub fn push_object(&mut self, obj: cli::Object) {
        self.output_objects.push(obj);
    }

    /// Finalizes the command, writing all new and unconsumed objects to the output stream.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if JSON serialization or I/O fails.
    pub fn finalize(mut self) -> Result<(), TpmError> {
        self.hydrate()?;
        let mut final_objects = self.input_objects;
        final_objects.append(&mut self.output_objects);

        if final_objects.is_empty() {
            return Ok(());
        }

        let mut objects_array = json::JsonValue::new_array();
        for obj in final_objects {
            objects_array.push(obj.to_json())?;
        }

        let output_doc = json::object! {
            version: 1,
            objects: objects_array
        };

        writeln!(self.writer, "{}", output_doc.dump())?;
        Ok(())
    }
}

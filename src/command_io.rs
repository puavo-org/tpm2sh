// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    parse_tpm_handle_from_uri, resolve_uri_to_bytes,
    schema::{Data, HmacSession, Key, PcrValues, Pipeline, PipelineObject, PolicySession, Tpm},
    TpmDevice, TpmError, POOL,
};
use log::warn;
use polling::{Event, Events, Poller};
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tpm2_protocol::{
    self,
    data::TpmsContext,
    message::{TpmContextLoadCommand, TpmFlushContextCommand},
    TpmParse, TpmTransient,
};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

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

    /// Returns the inner handle.
    #[must_use]
    pub const fn handle(&self) -> TpmTransient {
        self.handle
    }
}

impl Drop for ScopedHandle {
    fn drop(&mut self) {
        let handle = self.handle;
        let device_arc = self.device.clone();
        POOL.execute(move || {
            if let Ok(mut device) = device_arc.lock() {
                let cmd = TpmFlushContextCommand {
                    flush_handle: handle.into(),
                };
                if let Err(e) = device.execute(&cmd, &[]) {
                    warn!(
                        target: "cli::util",
                        "Failed to flush transient handle {handle:#010x}: {e}"
                    );
                }
            }
        });
    }
}

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
pub struct CommandIo<R: Read, W: Write> {
    reader: R,
    writer: W,
    input_objects: Vec<PipelineObject>,
    output_objects: Vec<PipelineObject>,
    hydrated: bool,
    is_reader_tty: bool,
}

impl<R: Read, W: Write> CommandIo<R, W> {
    /// Creates a new command context for the pipeline.
    pub fn new(reader: R, writer: W, is_reader_tty: bool) -> Self {
        Self {
            reader,
            writer,
            input_objects: Vec::new(),
            output_objects: Vec::new(),
            hydrated: false,
            is_reader_tty,
        }
    }

    /// Returns a mutable reference to the underlying writer.
    pub fn writer(&mut self) -> &mut W {
        &mut self.writer
    }

    /// Adds an object to be written to the output stream upon finalization.
    pub fn push_object(&mut self, obj: PipelineObject) {
        self.output_objects.push(obj);
    }

    /// Reads from the reader on the first call, populating the input objects.
    fn hydrate(&mut self) -> Result<(), TpmError> {
        if self.hydrated {
            return Ok(());
        }

        let mut input_string = String::new();
        if !self.is_reader_tty || stdin_ready()? {
            self.reader.read_to_string(&mut input_string)?;
        }

        if !input_string.trim().is_empty() {
            let pipeline: Pipeline = serde_json::from_str(&input_string)?;
            self.input_objects = pipeline.objects;
        }

        self.hydrated = true;
        Ok(())
    }

    /// Returns the active object (last on the stack) without consuming it.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Execution` if the pipeline is empty.
    pub fn get_active_object(&mut self) -> Result<&PipelineObject, TpmError> {
        self.hydrate()?;
        self.input_objects.last().ok_or_else(|| {
            TpmError::Execution("Required object not found in input pipeline".to_string())
        })
    }

    /// Consumes the active object (last on the stack) and returns it.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Execution` if the pipeline is empty.
    pub fn pop_active_object(&mut self) -> Result<PipelineObject, TpmError> {
        self.hydrate()?;
        self.input_objects.pop().ok_or_else(|| {
            TpmError::Execution("Required object not found in input pipeline".to_string())
        })
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

        let output_doc = Pipeline {
            version: 1,
            objects: final_objects,
        };

        let json_string = serde_json::to_string_pretty(&output_doc)?;
        writeln!(self.writer, "{json_string}")?;
        Ok(())
    }

    /// Resolves a `Tpm` object into a transient handle that will be auto-flushed.
    /// This is the "smart" resolver that handles loading contexts automatically.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the context URI is invalid or the context cannot be loaded.
    pub fn resolve_tpm_context(
        &mut self,
        device_arc: Arc<Mutex<TpmDevice>>,
        tpm_obj: &Tpm,
    ) -> Result<ScopedHandle, TpmError> {
        let uri = &tpm_obj.context;
        if uri.starts_with("tpm://") {
            let handle = parse_tpm_handle_from_uri(uri)?;
            Ok(ScopedHandle::new(TpmTransient(handle), device_arc))
        } else if uri.starts_with("data://") {
            let context_blob = resolve_uri_to_bytes(uri, &self.input_objects)?;
            let (context, remainder) = TpmsContext::parse(&context_blob)?;
            if !remainder.is_empty() {
                return Err(TpmError::Parse(
                    "Context object contains trailing data".to_string(),
                ));
            }

            let mut device = device_arc
                .lock()
                .map_err(|_| TpmError::Execution("TPM device lock poisoned".to_string()))?;
            let load_cmd = TpmContextLoadCommand { context };
            let (resp, _) = device.execute(&load_cmd, &[])?;
            let load_resp = resp
                .ContextLoad()
                .map_err(|e| TpmError::UnexpectedResponse(format!("{e:?}")))?;
            Ok(ScopedHandle::new(
                load_resp.loaded_handle,
                device_arc.clone(),
            ))
        } else {
            Err(TpmError::Parse(format!(
                "Unsupported URI scheme for a tpm context: '{uri}'"
            )))
        }
    }
}

macro_rules! command_pop {
    ($name:ident, $variant:path, $struct:ty, $type_str:literal) => {
        impl<R: Read, W: Write> CommandIo<R, W> {
            /// Pops the first object of a specific type from the pipeline.
            ///
            /// # Errors
            ///
            /// Returns a `TpmError::Execution` if a required object of this type
            /// is not found in the pipeline.
            pub fn $name(&mut self) -> Result<$struct, TpmError> {
                self.hydrate()?;
                let pos = self
                    .input_objects
                    .iter()
                    .position(|obj| matches!(obj, $variant(_)))
                    .ok_or_else(|| {
                        TpmError::Execution(format!(
                            "Pipeline missing required '{}' object",
                            $type_str
                        ))
                    })?;

                let obj = self.input_objects.remove(pos);
                if let $variant(inner) = obj {
                    Ok(inner)
                } else {
                    unreachable!();
                }
            }
        }
    };
}

command_pop!(pop_tpm, PipelineObject::Tpm, Tpm, "tpm");
command_pop!(pop_key, PipelineObject::Key, Key, "key");
command_pop!(pop_data, PipelineObject::Data, Data, "data");
command_pop!(
    pop_pcr_values,
    PipelineObject::PcrValues,
    PcrValues,
    "pcr-values"
);
command_pop!(
    pop_hmac_session,
    PipelineObject::HmacSession,
    HmacSession,
    "hmac-session"
);
command_pop!(
    pop_policy_session,
    PipelineObject::PolicySession,
    PolicySession,
    "policy-session"
);

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    device::{TpmDevice, TpmDeviceError},
    policy::{session_from_uri, Expression, PolicyError, Uri},
    util::build_to_vec,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::{TpmCc, TpmRc, TpmRh, TpmsContext, TPM_RH_PERSISTENT_FIRST, TPM_RH_TRANSIENT_FIRST},
    message::{
        TpmContextLoadCommand, TpmContextSaveCommand, TpmEvictControlCommand,
        TpmFlushContextCommand, MAX_HANDLES,
    },
    TpmErrorKind, TpmParse, TpmPersistent, TpmTransient,
};

#[derive(Debug)]
pub enum ContextError {
    AlreadyTracked(TpmTransient),
    CapacityExceeded(usize),
    Device(TpmDeviceError),
    InvalidHandle(u32),
    InvalidUri(Uri),
    Io(std::io::Error),
    NotTracked(TpmTransient),
    Policy(PolicyError),
    Tpm(TpmErrorKind),
    TpmRc(TpmRc),
}

impl std::error::Error for ContextError {}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AlreadyTracked(h) => write!(f, "already tracked: {h}"),
            Self::CapacityExceeded(s) => write!(f, "capacity exceeded: {s}"),
            Self::Device(e) => write!(f, "device: {e}"),
            Self::InvalidHandle(h) => write!(f, "invalid handle: {h}"),
            Self::InvalidUri(u) => write!(f, "invalid URI: {u}"),
            Self::Io(s) => write!(f, "I/O: {s}"),
            Self::NotTracked(h) => write!(f, "not tracked: {h}"),
            Self::Policy(p) => write!(f, "policy: {p}"),
            Self::Tpm(err) => write!(f, "TPM: {err}"),
            Self::TpmRc(rc) => write!(f, "TPM RC: {rc}"),
        }
    }
}

impl From<PolicyError> for ContextError {
    fn from(err: PolicyError) -> Self {
        Self::Policy(err)
    }
}

impl From<TpmDeviceError> for ContextError {
    fn from(err: TpmDeviceError) -> Self {
        Self::Device(err)
    }
}

impl From<TpmErrorKind> for ContextError {
    fn from(err: TpmErrorKind) -> Self {
        Self::Tpm(err)
    }
}

impl From<std::io::Error> for ContextError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

pub struct Context<'a> {
    pub handles: [Option<TpmTransient>; MAX_HANDLES],
    pub max_handles: Option<usize>,
    pub writer: &'a mut dyn std::io::Write,
}

impl std::fmt::Debug for Context<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let handles: Vec<String> = self
            .handles
            .iter()
            .filter_map(|h| h.map(|t| format!("tpm://{t:#010x}")))
            .collect();
        f.debug_struct("Context")
            .field("handles", &handles)
            .field("max_handles", &self.max_handles)
            .field("writer", &"<dyn Write>")
            .finish()
    }
}

impl<'a> Context<'a> {
    #[must_use]
    pub fn new(writer: &'a mut dyn std::io::Write) -> Context<'a> {
        Self {
            handles: [None; MAX_HANDLES],
            max_handles: None,
            writer,
        }
    }

    #[must_use]
    pub fn handles_len(&self) -> usize {
        self.handles.iter().filter(|h| h.is_some()).count()
    }

    #[must_use]
    pub fn handles_is_empty(&self) -> bool {
        self.handles_len() == 0
    }

    /// Loads a TPM object from a URI.
    ///
    /// If the URI points to a transient context (e.g., `file://` or `data://`),
    /// the object is loaded into the TPM and its handle is tracked for automatic
    /// cleanup. Persistent handles from `tpm://` URIs are returned directly and
    /// are not tracked.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` on parsing or TPM command failure.
    pub fn load(
        &mut self,
        device: &mut TpmDevice,
        uri: &Uri,
    ) -> Result<TpmTransient, ContextError> {
        self.capacity_invariant()?;
        match uri.ast() {
            Expression::TpmHandle(handle) => Ok(TpmTransient(*handle)),
            Expression::Data { .. } | Expression::FilePath(_) => {
                let context_blob = uri.to_bytes()?;
                let (context, _) = TpmsContext::parse(&context_blob)?;
                let cmd = TpmContextLoadCommand { context };
                let (resp, _) = device.execute(&cmd, &[])?;
                let resp = resp
                    .ContextLoad()
                    .map_err(|_| TpmDeviceError::MismatchedResponse {
                        command: TpmCc::ContextLoad,
                    })?;
                self.track(resp.loaded_handle)?;
                Ok(resp.loaded_handle)
            }
            _ => Err(ContextError::InvalidUri(uri.clone())),
        }
    }

    /// Saves a tracked transient object's context to a file or stdout.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if the handle is not tracked, or if TPM command or
    /// I/O operations fail.
    pub fn save_context(
        &mut self,
        device: &mut TpmDevice,
        handle_to_save: TpmTransient,
        output_uri: Option<&Uri>,
    ) -> Result<(), ContextError> {
        self.existence_invariant(handle_to_save)?;
        let save_cmd = TpmContextSaveCommand {
            save_handle: handle_to_save,
        };
        let (resp, _) = device.execute(&save_cmd, &[])?;
        let save_resp = resp
            .ContextSave()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::ContextSave,
            })?;
        let context_bytes = build_to_vec(&save_resp.context)?;

        self.handle_data_output(output_uri, &context_bytes)
    }

    /// Deletes a persistent or transient object by URI.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if the handle is invalid or the delete operation fails.
    pub fn delete(
        &mut self,
        device: &mut TpmDevice,
        uri: &Uri,
        session: Option<&Uri>,
    ) -> Result<u32, ContextError> {
        match uri.ast() {
            Expression::TpmHandle(handle) => {
                let handle = *handle;
                if handle >= TPM_RH_PERSISTENT_FIRST {
                    self.delete_persistent(device, TpmPersistent(handle), session)?;
                } else if handle >= TPM_RH_TRANSIENT_FIRST {
                    self.delete_transient(device, TpmTransient(handle))?;
                } else {
                    return Err(ContextError::InvalidHandle(handle));
                }
                Ok(handle)
            }
            Expression::Data { .. } | Expression::FilePath(_) => {
                let transient_handle = self.load(device, uri)?;
                self.delete_transient(device, transient_handle)?;
                Ok(transient_handle.0)
            }
            _ => Err(ContextError::InvalidUri(uri.clone())),
        }
    }

    /// Deletes a persistent object.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if the `EvictControl` command fails.
    pub fn delete_persistent(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmPersistent,
        session: Option<&Uri>,
    ) -> Result<(), ContextError> {
        let auth_handle = TpmRh::Owner;
        let cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: handle.0.into(),
            persistent_handle: handle,
        };
        let handles = [auth_handle as u32, handle.0];
        let sessions = session_from_uri(&cmd, &handles, session)?;
        let (resp, _) = device.execute(&cmd, &sessions)?;
        resp.EvictControl()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::EvictControl,
            })?;
        Ok(())
    }

    /// Deletes a transient object.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if the `FlushContext` command fails.
    pub fn delete_transient(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmTransient,
    ) -> Result<(), ContextError> {
        let cmd = TpmFlushContextCommand {
            flush_handle: handle.into(),
        };
        let (_, _) = device.execute(&cmd, &[])?;
        if let Some(slot) = self.handles.iter_mut().find(|slot| **slot == Some(handle)) {
            *slot = None;
        }
        Ok(())
    }

    /// Makes a tracked transient object persistent.
    ///
    /// After making the handle persistent, it is untracked to prevent an
    /// unintended flush of an invalid handle on exit.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if the handle is not a tracked transient handle,
    /// or if the `EvictControl` command fails.
    pub fn persist_transient(
        &mut self,
        device: &mut TpmDevice,
        transient_handle: TpmTransient,
        persistent_handle: TpmPersistent,
        session: Option<&Uri>,
    ) -> Result<(), ContextError> {
        self.existence_invariant(transient_handle)?;
        let auth_handle = TpmRh::Owner;
        let cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: transient_handle.0.into(),
            persistent_handle,
        };
        let handles = [auth_handle as u32, transient_handle.0];
        let sessions = session_from_uri(&cmd, &handles, session)?;
        let (resp, _) = device.execute(&cmd, &sessions)?;
        resp.EvictControl()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::EvictControl,
            })?;
        if let Some(slot) = self
            .handles
            .iter_mut()
            .find(|slot| **slot == Some(transient_handle))
        {
            *slot = None;
        }
        Ok(())
    }

    /// Tracks a transient handle for automatic cleanup at the end of execution.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if the handle is invalid or does not exist.
    pub fn track(&mut self, handle: TpmTransient) -> Result<(), ContextError> {
        self.non_existence_invariant(handle)?;
        self.capacity_invariant()?;
        if handle.0 < TPM_RH_TRANSIENT_FIRST {
            return Err(ContextError::InvalidHandle(handle.0));
        }
        if let Some(h) = self.handles.iter_mut().find(|h| h.is_none()) {
            *h = Some(handle);
        }
        Ok(())
    }

    /// Flushes all tracked transient handles out of the TPM device.
    ///
    /// # Errors
    ///
    /// Returns `ContextError` if the device mutex is poisoned or if flushing a
    /// handle fails. It returns the first error encountered.
    pub fn flush(self, device: Option<Arc<Mutex<TpmDevice>>>) -> Result<(), ContextError> {
        if let Some(device) = device {
            if self.handles_len() > 0 {
                let mut guard = device.lock().map_err(|_| TpmDeviceError::LockPoisoned)?;
                let mut first_err = None;

                for handle in self.handles.into_iter().flatten() {
                    let cmd = TpmFlushContextCommand {
                        flush_handle: handle.into(),
                    };
                    if let Err(err) = guard.execute(&cmd, &[]) {
                        log::warn!(target: "cli::device", "tpm://{handle:#010x}: {err}");
                        if first_err.is_none() {
                            first_err = Some(err.into());
                        }
                    }
                }

                if let Some(err) = first_err {
                    return Err(err);
                }
            }
        }
        Ok(())
    }

    /// Handles the output of a newly created or loaded object.
    ///
    /// Depending on the `output_uri`, this either makes the object persistent in
    /// the TPM or saves its context to an external location.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if persisting or saving fails.
    pub fn finalize_object_output(
        &mut self,
        device: &mut TpmDevice,
        object_handle: TpmTransient,
        output_uri: Option<&Uri>,
        session: Option<&Uri>,
    ) -> Result<(), ContextError> {
        if let Some(uri) = output_uri {
            if let Expression::TpmHandle(handle) = uri.ast() {
                let persistent_handle = TpmPersistent(*handle);
                self.persist_transient(device, object_handle, persistent_handle, session)?;
                writeln!(self.writer, "tpm://{persistent_handle:#010x}")?;
                return Ok(());
            }
        }
        self.save_context(device, object_handle, output_uri)
    }

    /// Handles writing data to an output file or stdout.
    ///
    /// Depending on the `output_uri`, this either writes the data to a file
    /// or to stdout as a `data://` URI.
    ///
    /// # Errors
    ///
    /// Returns a `ContextError` if writing fails or the URI scheme is unsupported.
    pub fn handle_data_output(
        &mut self,
        output_uri: Option<&Uri>,
        data: &[u8],
    ) -> Result<(), ContextError> {
        if let Some(uri) = output_uri {
            match uri.ast() {
                Expression::FilePath(path) => {
                    std::fs::write(path, data)?;
                    writeln!(self.writer, "file://{path}")?;
                }
                _ => return Err(ContextError::InvalidUri(uri.clone())),
            }
        } else {
            writeln!(self.writer, "data://base64,{}", base64_engine.encode(data))?;
        }
        Ok(())
    }

    fn capacity_invariant(&self) -> Result<(), ContextError> {
        if self.handles_len() == MAX_HANDLES {
            Err(ContextError::CapacityExceeded(MAX_HANDLES))
        } else {
            Ok(())
        }
    }

    fn existence_invariant(&self, handle: TpmTransient) -> Result<(), ContextError> {
        if self.handles.contains(&Some(handle)) {
            Ok(())
        } else {
            Err(ContextError::NotTracked(handle))
        }
    }

    fn non_existence_invariant(&self, handle: TpmTransient) -> Result<(), ContextError> {
        if self.handles.contains(&Some(handle)) {
            Err(ContextError::AlreadyTracked(handle))
        } else {
            Ok(())
        }
    }
}

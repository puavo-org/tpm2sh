// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use crate::{
    cli::Cli,
    device::TpmDevice,
    error::{CliError, ParseError},
    parser::PolicyExpr,
    session::session_from_args,
    uri::Uri,
    util::build_to_vec,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::{TpmRh, TpmsContext},
    message::{
        TpmContextLoadCommand, TpmContextSaveCommand, TpmEvictControlCommand,
        TpmFlushContextCommand, MAX_HANDLES,
    },
    TpmParse, TpmPersistent, TpmTransient,
};

pub struct Context<'a> {
    pub cli: &'a crate::cli::Cli,
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
            .field("cli", &self.cli)
            .field("handles", &handles)
            .field("max_handles", &self.max_handles)
            .field("writer", &"<dyn Write>")
            .finish()
    }
}

impl<'a> Context<'a> {
    #[must_use]
    pub fn new(cli: &'a Cli, writer: &'a mut dyn std::io::Write) -> Context<'a> {
        Self {
            cli,
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
    /// Returns a `CliError` on parsing or TPM command failure.
    pub fn load(&mut self, device: &mut TpmDevice, uri: &Uri) -> Result<TpmTransient, CliError> {
        self.capacity_invariant()?;
        match uri.ast() {
            PolicyExpr::TpmHandle(handle) => Ok(TpmTransient(*handle)),
            PolicyExpr::Data { .. } | PolicyExpr::FilePath(_) => {
                let context_blob = uri.to_bytes()?;
                let (context, remainder) = TpmsContext::parse(&context_blob)?;
                if !remainder.is_empty() {
                    return Err(ParseError::Custom("trailing data".to_string()).into());
                }
                let cmd = TpmContextLoadCommand { context };
                let (resp, _) = device.execute(&cmd, &[])?;
                let resp = resp
                    .ContextLoad()
                    .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
                self.track(resp.loaded_handle)?;
                Ok(resp.loaded_handle)
            }
            _ => Err(ParseError::Custom(format!("{uri}")).into()),
        }
    }

    /// Saves a transient object's context.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the TPM command or I/O fails.
    pub fn save(
        &mut self,
        device: &mut TpmDevice,
        save_handle: TpmTransient,
    ) -> Result<(), CliError> {
        self.existence_invariant(save_handle)?;
        let save_cmd = TpmContextSaveCommand { save_handle };
        let (resp, _) = device.execute(&save_cmd, &[])?;
        let save_resp = resp
            .ContextSave()
            .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
        let context_bytes = build_to_vec(&save_resp.context)?;
        writeln!(
            self.writer,
            "data://base64,{}",
            base64_engine.encode(context_bytes)
        )?;
        Ok(())
    }

    /// Deletes a persistent object.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the `EvictControl` command fails.
    pub fn delete_persistent(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmPersistent,
    ) -> Result<(), CliError> {
        let auth_handle = TpmRh::Owner;
        let cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: handle.0.into(),
            persistent_handle: handle,
        };
        let handles = [auth_handle as u32, handle.0];
        let sessions = session_from_args(&cmd, &handles, self.cli)?;
        let (resp, _) = device.execute(&cmd, &sessions)?;
        resp.EvictControl()
            .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
        Ok(())
    }

    /// Deletes a transient object.
    ///
    /// # Errors
    ///
    /// Returns `CliError` if the `FlushContext` command fails.
    pub fn delete_transient(
        &mut self,
        device: &mut TpmDevice,
        handle: TpmTransient,
    ) -> Result<(), CliError> {
        self.existence_invariant(handle)?;
        let cmd = TpmFlushContextCommand {
            flush_handle: handle.into(),
        };
        device.execute(&cmd, &[])?;
        if let Some(slot) = self.handles.iter_mut().find(|slot| **slot == Some(handle)) {
            *slot = None;
        }
        Ok(())
    }

    /// Convert a transient object as persistent.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the handle is not a tracked transient handle,
    /// or if the `EvictControl` command fails.
    pub fn evict(
        &mut self,
        device: &mut TpmDevice,
        transient_handle: TpmTransient,
        persistent_handle: TpmPersistent,
    ) -> Result<(), CliError> {
        let auth_handle = TpmRh::Owner;
        let cmd = TpmEvictControlCommand {
            auth: (auth_handle as u32).into(),
            object_handle: transient_handle.0.into(),
            persistent_handle,
        };
        let handles = [auth_handle as u32, transient_handle.0];
        let sessions = session_from_args(&cmd, &handles, self.cli)?;
        let (resp, _) = device.execute(&cmd, &sessions)?;
        resp.EvictControl()
            .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
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
    /// Returns a `CliError` if the handle is invalid or does not exist.
    pub fn track(&mut self, handle: TpmTransient) -> Result<(), CliError> {
        self.non_existence_invariant(handle)?;
        self.capacity_invariant()?;
        if handle.0 < TpmRh::TransientFirst as u32 {
            return Err(CliError::InvalidHandleType { handle: handle.0 });
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
    /// Returns `CliError::DeviceLockPoisoned` if the device mutex is poisoned.
    pub fn flush(self, device: Option<Arc<Mutex<TpmDevice>>>) -> Result<(), CliError> {
        if let Some(device) = device {
            if self.handles_len() > 0 {
                let mut guard = device.lock().map_err(|_| CliError::DeviceLockPoisoned)?;
                for handle in self.handles.into_iter().flatten() {
                    let cmd = TpmFlushContextCommand {
                        flush_handle: handle.into(),
                    };
                    if let Err(err) = guard.execute(&cmd, &[]) {
                        log::warn!(target: "cli::device", "tpm://{handle:#010x}: {err}");
                    }
                }
            }
        }
        Ok(())
    }

    fn capacity_invariant(&self) -> Result<(), CliError> {
        if self.handles_len() == MAX_HANDLES {
            Err(CliError::Execution(format!(
                "handle capacity {MAX_HANDLES} exceeded"
            )))
        } else {
            Ok(())
        }
    }

    fn existence_invariant(&self, handle: TpmTransient) -> Result<(), CliError> {
        if self.handles.contains(&Some(handle)) {
            Ok(())
        } else {
            Err(CliError::Execution(format!(
                "non-existing tpm://{handle:#010x}"
            )))
        }
    }

    fn non_existence_invariant(&self, handle: TpmTransient) -> Result<(), CliError> {
        if self.handles.contains(&Some(handle)) {
            Err(CliError::Execution(format!(
                "pre-existing tpm://{handle:#010x}"
            )))
        } else {
            Ok(())
        }
    }
}

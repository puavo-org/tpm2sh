// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, Load},
    device::ScopedHandle,
    session::session_from_args,
    uri::uri_to_bytes,
    util, CliError, Command, TpmDevice,
};

use std::io::Write;
use std::sync::{Arc, Mutex};

use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::{TpmContextSaveCommand, TpmLoadCommand},
    TpmParse,
};

impl Command for Load {
    /// Runs `load`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: Option<Arc<Mutex<TpmDevice>>>,
        writer: &mut W,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;

        let parent_uri = cli
            .parent
            .as_ref()
            .ok_or_else(|| CliError::Usage("Missing required --parent argument".to_string()))?;
        let parent_handle = ScopedHandle::from_uri(&device_arc, parent_uri)?;

        let pub_bytes = uri_to_bytes(&self.public_uri, &[])?;
        let priv_bytes = uri_to_bytes(&self.private_uri, &[])?;

        let (in_public, _) = Tpm2bPublic::parse(&pub_bytes)?;
        let (in_private, _) = Tpm2bPrivate::parse(&priv_bytes)?;

        let load_cmd = TpmLoadCommand {
            parent_handle: parent_handle.handle().0.into(),
            in_private,
            in_public,
        };

        let handles = [parent_handle.handle().into()];
        let sessions = session_from_args(&load_cmd, &handles, cli)?;
        let (resp, _) = {
            let mut chip = device_arc
                .lock()
                .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
            chip.execute(&load_cmd, &sessions)?
        };
        let load_resp = resp
            .Load()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        let save_handle = load_resp.object_handle;
        let save_handle_guard = ScopedHandle::new(save_handle, device_arc.clone());
        let (resp, _) = {
            let mut chip = device_arc
                .lock()
                .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;
            let save_cmd = TpmContextSaveCommand { save_handle };
            chip.execute(&save_cmd, &[])?
        };
        let save_resp = resp
            .ContextSave()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let context_bytes = util::build_to_vec(&save_resp.context)?;

        writeln!(
            writer,
            "data://base64,{}",
            base64_engine.encode(context_bytes)
        )?;

        save_handle_guard.flush()?;
        parent_handle.flush()?;

        Ok(())
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, Load},
    session::session_from_args,
    util::build_to_vec,
    CliError, TpmDevice,
};

use std::io::Write;

use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::{TpmContextSaveCommand, TpmLoadCommand},
    TpmParse, TpmTransient,
};

impl DeviceCommand for Load {
    /// Runs `load`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        cli: &Cli,
        device: &mut TpmDevice,
        writer: &mut W,
    ) -> Result<Vec<TpmTransient>, CliError> {
        let (parent_handle, parent_needs_flush) = device.load_context(&self.parent.parent)?;

        let mut handles_to_flush = Vec::new();
        if parent_needs_flush {
            handles_to_flush.push(parent_handle);
        }

        let pub_bytes = self.public.to_bytes()?;
        let priv_bytes = self.private.to_bytes()?;

        let (in_public, _) = Tpm2bPublic::parse(&pub_bytes)?;
        let (in_private, _) = Tpm2bPrivate::parse(&priv_bytes)?;

        let load_cmd = TpmLoadCommand {
            parent_handle: parent_handle.0.into(),
            in_private,
            in_public,
        };

        let handles = [parent_handle.into()];
        let sessions = session_from_args(&load_cmd, &handles, cli)?;
        let (resp, _) = device.execute(&load_cmd, &sessions)?;
        let load_resp = resp
            .Load()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        let save_handle = load_resp.object_handle;
        handles_to_flush.push(save_handle);

        let save_cmd = TpmContextSaveCommand { save_handle };
        let (resp, _) = device.execute(&save_cmd, &[])?;
        let save_resp = resp
            .ContextSave()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let context_bytes = build_to_vec(&save_resp.context)?;

        writeln!(
            writer,
            "data://base64,{}",
            base64_engine.encode(context_bytes)
        )?;

        Ok(handles_to_flush)
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{DeviceCommand, Load},
    session::session_from_args,
    CliError, Context, TpmDevice,
};

use std::io::Write;

use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::TpmLoadCommand,
    TpmParse,
};

impl DeviceCommand for Load {
    /// Runs `load`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        device: &mut TpmDevice,
        context: &mut Context<W>,
    ) -> Result<(), CliError> {
        let (parent_handle, parent_needs_flush) = device.context_load(&self.parent.parent)?;
        if parent_needs_flush {
            context.handles.push((parent_handle, true));
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
        let sessions = session_from_args(&load_cmd, &handles, context.cli)?;
        let (resp, _) = device.execute(&load_cmd, &sessions)?;
        let load_resp = resp
            .Load()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let save_handle = load_resp.object_handle;
        context.handles.push((save_handle, true));
        device.context_save(save_handle, &mut context.writer)?;
        Ok(())
    }
}

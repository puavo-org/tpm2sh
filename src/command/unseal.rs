// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, Unseal},
    session::session_from_args,
    CliError, TpmDevice,
};
use std::io::Write;
use tpm2_protocol::{message::TpmUnsealCommand, TpmTransient};

impl DeviceCommand for Unseal {
    /// Runs `unseal`.
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
        let handle = self.handle_uri.to_tpm_handle()?;
        let object_handle = TpmTransient(handle);

        let unseal_cmd = TpmUnsealCommand {
            item_handle: object_handle.0.into(),
        };
        let unseal_handles = [object_handle.into()];
        let unseal_sessions = session_from_args(&unseal_cmd, &unseal_handles, cli)?;

        let (unseal_resp, _) = device.execute(&unseal_cmd, &unseal_sessions)?;
        let unseal_resp = unseal_resp
            .Unseal()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        writer.write_all(&unseal_resp.out_data)?;

        Ok(Vec::new())
    }
}

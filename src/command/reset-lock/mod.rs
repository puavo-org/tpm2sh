// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{DeviceCommand, ResetLock},
    session::session_from_args,
    CliError, Context, TpmDevice,
};
use std::io::Write;
use tpm2_protocol::{data::TpmRh, message::TpmDictionaryAttackLockResetCommand};

impl DeviceCommand for ResetLock {
    /// Runs `reset-lock`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        device: &mut TpmDevice,
        context: &mut Context<W>,
    ) -> Result<(), CliError> {
        let command = TpmDictionaryAttackLockResetCommand {
            lock_handle: (TpmRh::Lockout as u32).into(),
        };
        let handles = [TpmRh::Lockout as u32];
        let sessions = session_from_args(&command, &handles, context.cli)?;
        let (resp, _) = device.execute(&command, &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        Ok(())
    }
}

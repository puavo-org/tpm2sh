// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, ResetLock},
    session::session_from_args,
    CliError, TpmDevice,
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
        cli: &Cli,
        device: &mut TpmDevice,
        _writer: &mut W,
    ) -> Result<crate::Resources, CliError> {
        let command = TpmDictionaryAttackLockResetCommand {
            lock_handle: (TpmRh::Lockout as u32).into(),
        };
        let handles = [TpmRh::Lockout as u32];
        let sessions = session_from_args(&command, &handles, cli)?;
        let (resp, _) = device.execute(&command, &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        Ok(crate::Resources::new(Vec::new()))
    }
}

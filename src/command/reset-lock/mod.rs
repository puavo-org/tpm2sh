// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::DeviceCommand,
    command::context::Context,
    device::{TpmDevice, TpmDeviceError},
    error::CliError,
    policy::session_from_uri,
    policy::Uri,
};
use argh::FromArgs;
use tpm2_protocol::{data::TpmCc, data::TpmRh, message::TpmDictionaryAttackLockResetCommand};

/// Resets the dictionary attack lockout timer.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "reset-lock")]
pub struct ResetLock {
    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,
}

impl DeviceCommand for ResetLock {
    /// Runs `reset-lock`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, _context: &mut Context) -> Result<(), CliError> {
        let command = TpmDictionaryAttackLockResetCommand {
            lock_handle: (TpmRh::Lockout as u32).into(),
        };
        let handles = [TpmRh::Lockout as u32];
        let sessions = session_from_uri(&command, &handles, self.session.as_ref())?;
        let (resp, _) = device.execute(&command, &sessions)?;
        resp.DictionaryAttackLockReset()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::DictionaryAttackLockReset,
            })?;
        Ok(())
    }
}

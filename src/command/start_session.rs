// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{Cli, DeviceCommand, SessionType, StartSession},
    CliError, TpmDevice,
};
use rand::{thread_rng, RngCore};
use std::io::Write;
use tpm2_protocol::{
    data::{
        Tpm2bEncryptedSecret, Tpm2bNonce, TpmAlgId, TpmRh, TpmtSymDefObject, TpmuSymKeyBits,
        TpmuSymMode,
    },
    message::TpmStartAuthSessionCommand,
    tpm_hash_size, TpmTransient,
};

impl DeviceCommand for StartSession {
    /// Runs `start-session`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<W: Write>(
        &self,
        _cli: &Cli,
        device: &mut TpmDevice,
        writer: &mut W,
    ) -> Result<Vec<TpmTransient>, CliError> {
        let auth_hash = TpmAlgId::Sha256;
        let digest_len = tpm_hash_size(&auth_hash)
            .ok_or_else(|| CliError::Execution("Unsupported hash algorithm".to_string()))?;
        let mut nonce_bytes = vec![0; digest_len];
        thread_rng().fill_bytes(&mut nonce_bytes);
        let cmd = TpmStartAuthSessionCommand {
            tpm_key: (TpmRh::Null as u32).into(),
            bind: (TpmRh::Null as u32).into(),
            nonce_caller: Tpm2bNonce::try_from(nonce_bytes.as_slice())?,
            encrypted_salt: Tpm2bEncryptedSecret::default(),
            session_type: self.session_type.into(),
            symmetric: TpmtSymDefObject {
                algorithm: TpmAlgId::Null,
                key_bits: TpmuSymKeyBits::Null,
                mode: TpmuSymMode::Null,
            },
            auth_hash,
        };
        let (response, _) = device.execute(&cmd, &[])?;
        let start_auth_session_resp = response
            .StartAuthSession()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let handle = start_auth_session_resp.session_handle;
        if self.session_type == SessionType::Policy {
            let digest = hex::encode(Vec::<u8>::new());
            writeln!(writer, "digest://sha256,{digest}")?;
        }
        writeln!(writer, "tpm://{handle:#010x}")?;
        Ok(Vec::new())
    }
}

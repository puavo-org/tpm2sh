// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    arguments,
    arguments::{format_subcommand_help, CommandLineOption},
    cli::{Commands, Load},
    get_auth_sessions,
    pipeline::{CommandIo, Entry as PipelineEntry, ScopedHandle, Tpm as PipelineTpm},
    resolve_uri_to_bytes, util, CliError, Command, CommandType, TpmDevice,
};
use base64::{engine::general_purpose::STANDARD as base64_engine, Engine};
use lexopt::prelude::*;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use tpm2_protocol::{
    data::{Tpm2bPrivate, Tpm2bPublic},
    message::{TpmContextSaveCommand, TpmLoadCommand},
    TpmParse,
};

const ABOUT: &str = "Loads a TPM key or sealed object";
const USAGE: &str = "tpm2sh load [OPTIONS]";
const OPTIONS: &[CommandLineOption] = &[(
    None,
    "--parent-password",
    "<PASSWORD>",
    "Authorization for the parent object",
)];

impl Command for Load {
    fn command_type(&self) -> CommandType {
        CommandType::Pipe
    }

    fn help() {
        println!(
            "{}",
            format_subcommand_help("load", ABOUT, USAGE, &[], OPTIONS)
        );
    }

    fn parse(parser: &mut lexopt::Parser) -> Result<Commands, CliError> {
        let mut args = Load::default();
        arguments!(parser, arg, Self::help, {
            Long("parent-password") => {
                args.parent_password.password = Some(parser.value()?.string()?);
            }
            _ => {
                return Err(CliError::from(arg.unexpected()));
            }
        });
        Ok(Commands::Load(args))
    }

    /// Runs `load`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run<R: Read, W: Write>(
        &self,
        io: &mut CommandIo<R, W>,
        device: Option<Arc<Mutex<TpmDevice>>>,
    ) -> Result<(), CliError> {
        let device_arc =
            device.ok_or_else(|| CliError::Execution("TPM device not provided".to_string()))?;
        let mut chip = device_arc
            .lock()
            .map_err(|_| CliError::Execution("TPM device lock poisoned".to_string()))?;

        let key_to_load = io.pop_key()?;
        let parent_obj = io.pop_tpm()?;
        let parent_handle_guard = io.resolve_tpm_context(device_arc.clone(), &parent_obj)?;
        let parent_handle = parent_handle_guard.handle();

        let pub_bytes = resolve_uri_to_bytes(&key_to_load.public, &[])?;
        let priv_bytes = resolve_uri_to_bytes(&key_to_load.private, &[])?;

        let (in_public, _) = Tpm2bPublic::parse(&pub_bytes)?;
        let (in_private, _) = Tpm2bPrivate::parse(&priv_bytes)?;

        let load_cmd = TpmLoadCommand {
            parent_handle: parent_handle.0.into(),
            in_private,
            in_public,
        };

        let handles = [parent_handle.into()];
        let sessions = get_auth_sessions(
            &load_cmd,
            &handles,
            None,
            self.parent_password.password.as_deref(),
        )?;

        let (resp, _) = chip.execute(&load_cmd, &sessions)?;
        let load_resp = resp
            .Load()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;

        let save_handle = load_resp.object_handle;
        let _ = ScopedHandle::new(save_handle, device_arc.clone());

        let save_cmd = TpmContextSaveCommand { save_handle };
        let (resp, _) = chip.execute(&save_cmd, &[])?;
        let save_resp = resp
            .ContextSave()
            .map_err(|e| CliError::UnexpectedResponse(format!("{e:?}")))?;
        let context_bytes = util::build_to_vec(&save_resp.context)?;

        let new_tpm_obj = PipelineTpm {
            context: format!("data://base64,{}", base64_engine.encode(context_bytes)),
            parent: Some(parent_obj.context),
        };

        io.push_object(PipelineEntry::Tpm(new_tpm_obj));
        Ok(())
    }
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::context::Context,
    device::TpmDevice,
    error::CliError,
    pcr::pcr_get_count,
    session::session_from_args,
    uri::Uri,
};
use lexopt::{Arg, Parser, ValueExt};
use tpm2_protocol::{data::Tpm2bEvent, message::TpmPcrEventCommand};

#[derive(Debug, Default)]
pub struct PcrEvent {
    pub pcr: Uri,
    pub data: Uri,
}

impl Subcommand for PcrEvent {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");

    fn parse(parser: &mut Parser) -> Result<Self, lexopt::Error> {
        let mut pcr = None;
        let mut data = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if pcr.is_none() => pcr = Some(val.parse()?),
                Arg::Value(val) if data.is_none() => data = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(PcrEvent {
            pcr: required(pcr, "<PCR>")?,
            data: required(data, "<DATA>")?,
        })
    }
}

impl DeviceCommand for PcrEvent {
    /// Runs `pcr-event`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, context: &mut Context) -> Result<(), CliError> {
        let pcr_count = pcr_get_count(device)?;
        let selection = self.pcr.to_pcr_selection(pcr_count)?;
        if selection.len() != 1 {
            return Err(CliError::Execution(
                "pcr-event requires a selection of exactly one PCR bank".to_string(),
            ));
        }
        let pcr_selection = &selection[0];
        let set_bits_count = pcr_selection
            .pcr_select
            .iter()
            .map(|byte| byte.count_ones())
            .sum::<u32>();
        if set_bits_count != 1 {
            return Err(CliError::Execution(format!(
                "pcr-event requires a selection of exactly one PCR (provided selection '{}' contains {})",
                self.pcr, set_bits_count
            )));
        }
        let pcr_index = pcr_selection
            .pcr_select
            .iter()
            .enumerate()
            .find_map(|(byte_idx, &byte)| {
                if byte != 0 {
                    Some(u32::try_from(byte_idx * 8).unwrap() + byte.trailing_zeros())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                CliError::Execution("pcr-event could not determine the index".to_string())
            })?;
        let handles = [pcr_index];
        let data_bytes = self.data.to_bytes()?;
        let event_data = Tpm2bEvent::try_from(data_bytes.as_slice())?;
        let command = TpmPcrEventCommand {
            pcr_handle: handles[0],
            event_data,
        };
        let sessions = session_from_args(&command, &handles, context.cli)?;
        let (resp, _) = device.execute(&command, &sessions)?;
        resp.PcrEvent()
            .map_err(|e| CliError::Unexpected(format!("{e:?}")))?;
        Ok(())
    }
}

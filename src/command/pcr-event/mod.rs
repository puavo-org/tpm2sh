// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::{handle_help, required, DeviceCommand, Subcommand},
    command::{context::Context, CommandError},
    device::{TpmDevice, TpmDeviceError},
    error::CliError,
    pcr::pcr_get_count,
    session::session_from_args,
    uri::pcr_selection_to_list,
};
use lexopt::{Arg, Parser, ValueExt};
use tpm2_protocol::{data::Tpm2bEvent, data::TpmCc, message::TpmPcrEventCommand};

#[derive(Debug, Default)]
pub struct PcrEvent {
    pub pcr_selection: String,
    pub data: crate::uri::Uri,
}

impl Subcommand for PcrEvent {
    const USAGE: &'static str = include_str!("usage.txt");
    const HELP: &'static str = include_str!("help.txt");
    const ARGUMENTS: &'static str = include_str!("arguments.txt");
    const OPTIONS: &'static str = include_str!("options.txt");
    const SUMMARY: &'static str = include_str!("summary.txt");

    fn parse(parser: &mut Parser) -> Result<Self, CliError> {
        let mut pcr_selection = None;
        let mut data = None;
        while let Some(arg) = parser.next()? {
            match arg {
                Arg::Value(val) if pcr_selection.is_none() => pcr_selection = Some(val.string()?),
                Arg::Value(val) if data.is_none() => data = Some(val.parse()?),
                _ => return handle_help(arg),
            }
        }
        Ok(PcrEvent {
            pcr_selection: required(pcr_selection, "<PCR>")?,
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
        let selection = pcr_selection_to_list(&self.pcr_selection, pcr_count)?;

        if selection.len() != 1 {
            return Err(CommandError::InvalidPcrSelection(
                "requires a selection of exactly one PCR bank".to_string(),
            )
            .into());
        }
        let pcr_selection = &selection[0];

        let set_bits_count: u32 = pcr_selection
            .pcr_select
            .iter()
            .map(|b| b.count_ones())
            .sum();
        if set_bits_count != 1 {
            return Err(CommandError::InvalidPcrSelection(format!(
                "requires a selection of exactly one PCR, but {set_bits_count} were provided in '{}'",
                self.pcr_selection
            ))
            .into());
        }

        let pcr_index = pcr_selection
            .pcr_select
            .iter()
            .enumerate()
            .find_map(|(byte_idx, &byte)| {
                if byte != 0 {
                    let base =
                        u32::try_from(byte_idx * 8).expect("PCR index calculation overflowed");
                    Some(base + byte.trailing_zeros())
                } else {
                    None
                }
            })
            .ok_or_else(|| {
                CommandError::InvalidPcrSelection(
                    "could not determine the PCR index from the selection".to_string(),
                )
            })?;

        let handles = [pcr_index];
        let data_bytes = self.data.to_bytes()?;
        let event_data = Tpm2bEvent::try_from(data_bytes.as_slice()).map_err(CommandError::from)?;
        let command = TpmPcrEventCommand {
            pcr_handle: handles[0],
            event_data,
        };
        let sessions = session_from_args(&command, &handles, context.cli)?;
        let (_rc, resp, _) = device.execute(&command, &sessions)?;
        resp.PcrEvent()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::PcrEvent,
            })?;
        Ok(())
    }
}

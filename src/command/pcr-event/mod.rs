// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2024-2025 Jarkko Sakkinen
// Copyright (c) 2025 Opinsys Oy

use crate::{
    cli::DeviceCommand,
    command::{context::Context, CommandError},
    device::{TpmDevice, TpmDeviceError},
    error::CliError,
    policy::pcr_get_count,
    policy::session_from_uri,
    policy::{pcr_selection_to_list, Uri},
};
use argh::FromArgs;
use tpm2_protocol::{data::Tpm2bEvent, data::TpmCc, message::TpmPcrEventCommand};

/// Extends a PCR with an event.
#[derive(FromArgs, Debug, Default)]
#[argh(subcommand, name = "pcr-event")]
pub struct PcrEvent {
    /// session URI or 'password://<PASS>'
    #[argh(option)]
    pub session: Option<Uri>,

    /// PCR selection to extend (e.g., "sha256:7")
    #[argh(positional)]
    pub pcr_selection: String,

    /// data URI for the event ('file://' or 'data://')
    #[argh(positional)]
    pub data: crate::policy::Uri,
}

impl DeviceCommand for PcrEvent {
    /// Runs `pcr-event`.
    ///
    /// # Errors
    ///
    /// Returns a `CliError` if the execution fails
    fn run(&self, device: &mut TpmDevice, _context: &mut Context) -> Result<(), CliError> {
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
        let sessions = session_from_uri(&command, &handles, self.session.as_ref())?;
        let (resp, _) = device.execute(&command, &sessions)?;
        resp.PcrEvent()
            .map_err(|_| TpmDeviceError::MismatchedResponse {
                command: TpmCc::PcrEvent,
            })?;
        Ok(())
    }
}

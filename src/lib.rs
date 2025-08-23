// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

pub mod arg_parser;
pub mod cli;
pub mod command;
pub mod command_io;
pub mod crypto;
pub mod device;
pub mod error;
pub mod formats;
pub mod key;
pub mod pcr;
pub mod pretty_printer;
pub mod session;
pub mod util;

pub use self::arg_parser::parse_cli;
pub use self::command_io::CommandIo;
pub use self::crypto::*;
pub use self::device::*;
pub use self::error::TpmError;
pub use self::formats::*;
pub use self::key::*;
pub use self::pcr::*;
pub use self::pretty_printer::PrettyTrace;
pub use self::session::*;
pub use self::util::*;

/// Describes the role a command plays in the JSON pipeline.
pub enum CommandType {
    /// Does not interact with the JSON pipeline. Prints human-readable text.
    Standalone,
    /// Creates new objects for a pipeline, but does not consume any.
    Source,
    /// Consumes and produces objects, acting as a pipeline transformer.
    Pipe,
    /// Consumes objects and terminates the pipeline with non-JSON output.
    Sink,
}

#[derive(Debug, Clone)]
pub struct ObjectData {
    pub oid: String,
    pub empty_auth: bool,
    pub parent: String,
    pub public: String,
    pub private: String,
}

impl ObjectData {
    #[must_use]
    pub fn to_json(&self) -> json::JsonValue {
        json::object! {
            oid: self.oid.clone(),
            empty_auth: self.empty_auth,
            parent: self.parent.clone(),
            public: self.public.clone(),
            private: self.private.clone(),
        }
    }

    /// Deserializes `ObjectData` from a `json::JsonValue`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Parse` if the JSON object is missing required fields
    /// or contains values of the wrong type.
    pub fn from_json(value: &json::JsonValue) -> Result<Self, TpmError> {
        Ok(Self {
            oid: value["oid"]
                .as_str()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'oid'".to_string()))?
                .to_string(),
            empty_auth: value["empty_auth"]
                .as_bool()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'empty_auth'".to_string()))?,
            parent: value["parent"]
                .as_str()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'parent'".to_string()))?
                .to_string(),
            public: value["public"]
                .as_str()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'public'".to_string()))?
                .to_string(),
            private: value["private"]
                .as_str()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'private'".to_string()))?
                .to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ContextData {
    pub context_blob: String,
}

impl ContextData {
    #[must_use]
    pub fn to_json(&self) -> json::JsonValue {
        json::object! {
            context_blob: self.context_blob.clone()
        }
    }

    /// Deserializes `ContextData` from a `json::JsonValue`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Parse` if the JSON object is missing required fields.
    pub fn from_json(value: &json::JsonValue) -> Result<Self, TpmError> {
        Ok(Self {
            context_blob: value["context_blob"]
                .as_str()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'context_blob'".to_string()))?
                .to_string(),
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SessionData {
    pub handle: u32,
    pub nonce_tpm: String,
    pub attributes: u8,
    pub hmac_key: String,
    pub auth_hash: u16,
    pub policy_digest: String,
}

impl SessionData {
    #[must_use]
    pub fn to_json(&self) -> json::JsonValue {
        json::object! {
            handle: self.handle,
            nonce_tpm: self.nonce_tpm.clone(),
            attributes: self.attributes,
            hmac_key: self.hmac_key.clone(),
            auth_hash: self.auth_hash,
            policy_digest: self.policy_digest.clone(),
        }
    }

    /// Deserializes `SessionData` from a `json::JsonValue`.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError::Parse` if the JSON object is missing required fields
    /// or contains values of the wrong type.
    pub fn from_json(value: &json::JsonValue) -> Result<Self, TpmError> {
        Ok(Self {
            handle: value["handle"]
                .as_u32()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'handle'".to_string()))?,
            nonce_tpm: value["nonce_tpm"]
                .as_str()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'nonce_tpm'".to_string()))?
                .to_string(),
            attributes: value["attributes"]
                .as_u8()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'attributes'".to_string()))?,
            hmac_key: value["hmac_key"]
                .as_str()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'hmac_key'".to_string()))?
                .to_string(),
            auth_hash: value["auth_hash"]
                .as_u16()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'auth_hash'".to_string()))?,
            policy_digest: value["policy_digest"]
                .as_str()
                .ok_or_else(|| TpmError::Parse("missing or invalid 'policy_digest'".to_string()))?
                .to_string(),
        })
    }
}

/// A trait for parsing and executing subcommands.
pub trait Command {
    /// Returns the command's role in the pipeline.
    fn command_type(&self) -> CommandType;

    /// Prints the help message for a subcommand.
    fn help()
    where
        Self: Sized;

    /// Parses the arguments for a subcommand.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` on parsing failure.
    fn parse(parser: &mut lexopt::Parser) -> Result<cli::Commands, TpmError>
    where
        Self: Sized;

    /// Returns `true` if the command does not require TPM device access.
    fn is_local(&self) -> bool {
        false
    }

    /// Runs a command.
    ///
    /// # Errors
    ///
    /// Returns a `TpmError` if the execution fails
    fn run(
        &self,
        device: &mut Option<TpmDevice>,
        log_format: cli::LogFormat,
    ) -> Result<(), TpmError>;
}

/// Parses command-line arguments and executes the corresponding command.
///
/// # Errors
///
/// Returns a `TpmError` if opening the device, or executing the command fails.
pub fn execute_cli() -> Result<(), TpmError> {
    let Some(cli) = parse_cli()? else {
        return Ok(());
    };

    if let Some(command) = cli.command {
        let mut device = if command.is_local() {
            None
        } else {
            Some(TpmDevice::new(&cli.device)?)
        };
        command.run(&mut device, cli.log_format)
    } else {
        Ok(())
    }
}

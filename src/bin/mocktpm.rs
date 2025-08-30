// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use cli::{crypto_kdfa, crypto_make_name};

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::exit,
};

use hmac::Mac;
use lexopt::prelude::*;
use log::{error, info, warn};
use rsa::{traits::PublicKeyParts, Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use tpm2_protocol::{
    data::{
        Tpm2bName, Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa, TpmAlgId, TpmCap, TpmCc, TpmRc,
        TpmRcBase, TpmRh, TpmaAlgorithm, TpmaCc, TpmlAlgProperty, TpmlCca, TpmlHandle,
        TpmsAlgProperty, TpmtPublic, TpmuCapabilities, TpmuPublicId, TpmuPublicParms,
    },
    message::{
        tpm_build_response, tpm_parse_command, TpmAuthResponses, TpmCommandBody,
        TpmContextLoadCommand, TpmContextLoadResponse, TpmContextSaveCommand,
        TpmContextSaveResponse, TpmCreatePrimaryCommand, TpmCreatePrimaryResponse,
        TpmFlushContextCommand, TpmFlushContextResponse, TpmGetCapabilityCommand,
        TpmGetCapabilityResponse, TpmImportCommand, TpmImportResponse, TpmLoadCommand,
        TpmLoadResponse, TpmReadPublicCommand, TpmReadPublicResponse, TpmResponseBody,
    },
    TpmErrorKind, TpmParse, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

const KDF_DUPLICATE: &str = "DUPLICATE";
const KDF_INTEGRITY: &str = "INTEGRITY";

#[derive(Debug, Clone)]
enum MockTpmPrivateKey {
    Rsa(RsaPrivateKey),
}

#[derive(Debug, Clone)]
struct MockTpmKey {
    public: TpmtPublic,
    private: Option<MockTpmPrivateKey>,
}

const SOCKET_NAME: &str = "mocktpm.sock";
const TPM_HEADER_SIZE: usize = 10;

type MockTpmResult = Result<(TpmRc, TpmResponseBody, TpmAuthResponses), TpmRc>;

/// MockTPM response trait
trait MockTpmResponse {
    fn build(
        &self,
        writer: &mut TpmWriter,
        rc: TpmRc,
        auth_responses: &TpmAuthResponses,
    ) -> Result<(), tpm2_protocol::TpmErrorKind>;
}

macro_rules! mock_tpm_response {
    ($($variant:ident),* $(,)?) => {
        impl MockTpmResponse for TpmResponseBody {
            fn build(
                &self,
                writer: &mut TpmWriter,
                rc: TpmRc,
                auth_responses: &TpmAuthResponses,
            ) -> Result<(), tpm2_protocol::TpmErrorKind> {
                match self {
                    $(
                        Self::$variant(r) => tpm_build_response(r, auth_responses, rc, writer),
                    )*
                    _ => Err(tpm2_protocol::TpmErrorKind::Unreachable),
                }
            }
        }
    };
}

mock_tpm_response!(
    CreatePrimary,
    ReadPublic,
    Import,
    Load,
    ContextSave,
    ContextLoad,
    FlushContext,
    GetCapability,
);

#[derive(Debug, Default)]
struct MockTpm {
    objects: HashMap<u32, MockTpmKey>,
    next_handle: u32,
}

macro_rules! mock_tpm_command {
    ($state:ident, $cmd_body:ident, $($variant:ident => $handler:path),* $(,)?) => {
        match $cmd_body {
            $(
                TpmCommandBody::$variant(cmd) => $handler($state, cmd),
            )*
            _ => Err(
                TpmRc::from(TpmRcBase::CommandCode),
            ),
        }
    };
}

impl MockTpm {
    fn new() -> Self {
        Self {
            next_handle: 0x8000_0000,
            ..Default::default()
        }
    }

    fn supported_commands() -> &'static [TpmCc] {
        &[
            TpmCc::ContextLoad,
            TpmCc::ContextSave,
            TpmCc::CreatePrimary,
            TpmCc::FlushContext,
            TpmCc::GetCapability,
            TpmCc::Import,
            TpmCc::Load,
            TpmCc::ReadPublic,
        ]
    }

    fn supported_algs() -> &'static [TpmsAlgProperty] {
        const OBJECT_ATTRS: TpmaAlgorithm = TpmaAlgorithm::from_bits_truncate(
            TpmaAlgorithm::OBJECT.bits() | TpmaAlgorithm::ASYMMETRIC.bits(),
        );
        &[
            TpmsAlgProperty {
                alg: TpmAlgId::Sha256,
                alg_properties: TpmaAlgorithm::HASH,
            },
            TpmsAlgProperty {
                alg: TpmAlgId::Sha384,
                alg_properties: TpmaAlgorithm::HASH,
            },
            TpmsAlgProperty {
                alg: TpmAlgId::Sha512,
                alg_properties: TpmaAlgorithm::HASH,
            },
            TpmsAlgProperty {
                alg: TpmAlgId::Rsa,
                alg_properties: OBJECT_ATTRS,
            },
            TpmsAlgProperty {
                alg: TpmAlgId::Ecc,
                alg_properties: OBJECT_ATTRS,
            },
        ]
    }

    fn parse(&mut self, request_buf: &[u8]) -> MockTpmResult {
        let Ok((_handles, cmd_body, _sessions)) = tpm_parse_command(request_buf) else {
            return Err(TpmRc::from(TpmRcBase::BadTag));
        };

        mock_tpm_command! {
            self, cmd_body,
            GetCapability => Self::get_capability,
            CreatePrimary => Self::create_primary,
            ReadPublic => Self::read_public,
            Import => Self::import,
            Load => Self::load,
            ContextSave => Self::context_save,
            ContextLoad => Self::context_load,
            FlushContext => Self::flush_context,
        }
    }

    fn context_load(&mut self, cmd: TpmContextLoadCommand) -> MockTpmResult {
        let resp = TpmContextLoadResponse {
            loaded_handle: cmd.context.saved_handle,
        };
        Ok((
            TpmRc::from(TpmRcBase::Success),
            TpmResponseBody::ContextLoad(resp),
            TpmAuthResponses::default(),
        ))
    }

    fn context_save(&mut self, cmd: TpmContextSaveCommand) -> MockTpmResult {
        let resp = TpmContextSaveResponse {
            context: tpm2_protocol::data::TpmsContext {
                sequence: 1,
                saved_handle: cmd.save_handle,
                hierarchy: TpmRh::Owner,
                context_blob: Default::default(),
            },
        };
        Ok((
            TpmRc::from(TpmRcBase::Success),
            TpmResponseBody::ContextSave(resp),
            TpmAuthResponses::default(),
        ))
    }

    fn create_primary(&mut self, cmd: TpmCreatePrimaryCommand) -> MockTpmResult {
        let mut public = cmd.in_public.inner;
        let mut private = None;

        if public.object_type == TpmAlgId::Rsa {
            let key_bits = if let TpmuPublicParms::Rsa(params) = public.parameters {
                params.key_bits
            } else {
                return Err(TpmRc::from(TpmRcBase::Value));
            };

            let Ok(rsa_key) = RsaPrivateKey::new(&mut rand::thread_rng(), key_bits.into()) else {
                return Err(TpmRc::from(TpmRcBase::Failure));
            };
            private = Some(MockTpmPrivateKey::Rsa(rsa_key.clone()));
            let modulus = rsa_key.n().to_bytes_be();
            let Ok(unique_rsa) = Tpm2bPublicKeyRsa::try_from(modulus.as_slice()) else {
                return Err(TpmRc::from(TpmRcBase::Value));
            };
            public.unique = TpmuPublicId::Rsa(unique_rsa);
        }

        let handle = self.next_handle;
        self.next_handle += 1;
        self.objects.insert(
            handle,
            MockTpmKey {
                public: public.clone(),
                private,
            },
        );

        let Ok(name_bytes) = crypto_make_name(&public) else {
            return Err(TpmRc::from(TpmRcBase::Hash));
        };
        let Ok(name) = Tpm2bName::try_from(name_bytes.as_slice()) else {
            return Err(TpmRc::from(TpmRcBase::Value));
        };
        let resp = TpmCreatePrimaryResponse {
            object_handle: TpmTransient(handle),
            out_public: Tpm2bPublic { inner: public },
            creation_data: Default::default(),
            creation_hash: Default::default(),
            creation_ticket: Default::default(),
            name: name.clone(),
        };
        Ok((
            TpmRc::from(TpmRcBase::Success),
            TpmResponseBody::CreatePrimary(resp),
            TpmAuthResponses::default(),
        ))
    }

    fn flush_context(&mut self, _cmd: TpmFlushContextCommand) -> MockTpmResult {
        let resp = TpmFlushContextResponse {};
        Ok((
            TpmRc::from(TpmRcBase::Success),
            TpmResponseBody::FlushContext(resp),
            TpmAuthResponses::default(),
        ))
    }

    fn get_capability(&mut self, cmd: TpmGetCapabilityCommand) -> MockTpmResult {
        let capability_data = match cmd.cap {
            TpmCap::Commands => {
                let all_cmds = Self::supported_commands();
                let filtered_cmds: Vec<TpmaCc> = all_cmds
                    .iter()
                    .filter(|c| (**c as u32) >= cmd.property)
                    .take(cmd.property_count as usize)
                    .map(|c| TpmaCc::from_bits_truncate(*c as u32))
                    .collect();

                let mut list = TpmlCca::new();
                for item in filtered_cmds {
                    list.try_push(item)
                        .map_err(|_| TpmRc::from(TpmRcBase::Failure))?;
                }
                TpmuCapabilities::Commands(list)
            }
            TpmCap::Algs => {
                let all_algs = Self::supported_algs();
                let filtered_algs: Vec<TpmsAlgProperty> = all_algs
                    .iter()
                    .filter(|a| (a.alg as u16) >= (cmd.property as u16))
                    .take(cmd.property_count as usize)
                    .cloned()
                    .collect();

                let mut list = TpmlAlgProperty::new();
                for item in filtered_algs {
                    list.try_push(item)
                        .map_err(|_| TpmRc::from(TpmRcBase::Failure))?;
                }
                TpmuCapabilities::Algs(list)
            }
            TpmCap::Handles => {
                let mut handles: Vec<u32> = Vec::new();
                let prop = cmd.property;
                if prop >= (TpmRh::TransientFirst as u32) && prop < (TpmRh::PersistentFirst as u32)
                {
                    handles = self.objects.keys().copied().collect();
                    handles.sort_unstable();
                }

                let mut list = TpmlHandle::new();
                for handle in handles {
                    list.try_push(handle)
                        .map_err(|_| TpmRc::from(TpmRcBase::Failure))?;
                }
                TpmuCapabilities::Handles(list)
            }
            _ => {
                return Err(TpmRc::from(TpmRcBase::Value));
            }
        };

        let resp = TpmGetCapabilityResponse {
            more_data: false.into(),
            capability_data: tpm2_protocol::data::TpmsCapabilityData {
                capability: cmd.cap,
                data: capability_data,
            },
        };
        Ok((
            TpmRc::from(TpmRcBase::Success),
            TpmResponseBody::GetCapability(resp),
            TpmAuthResponses::default(),
        ))
    }

    fn import(&mut self, cmd: TpmImportCommand) -> MockTpmResult {
        let Some(parent_key) = self.objects.get(&cmd.parent_handle.0) else {
            return Err(TpmRc::from(TpmRcBase::Handle));
        };

        let parent_private = match parent_key.private.as_ref() {
            Some(priv_key) => priv_key,
            None => return Err(TpmRc::from(TpmRcBase::Key)),
        };

        let Ok(parent_name_bytes) = crypto_make_name(&parent_key.public) else {
            return Err(TpmRc::from(TpmRcBase::Hash));
        };
        let Ok((parent_name, _)) = Tpm2bName::parse(&parent_name_bytes) else {
            return Err(TpmRc::from(TpmRcBase::Value));
        };

        let seed = match (parent_private, &parent_key.public) {
            (MockTpmPrivateKey::Rsa(rsa_priv), TpmtPublic { name_alg, .. }) => {
                let decrypt_result = match name_alg {
                    TpmAlgId::Sha1 => rsa_priv.decrypt(
                        Oaep::new_with_label::<Sha1, _>(KDF_DUPLICATE),
                        &cmd.in_sym_seed,
                    ),
                    TpmAlgId::Sha256 => rsa_priv.decrypt(
                        Oaep::new_with_label::<Sha256, _>(KDF_DUPLICATE),
                        &cmd.in_sym_seed,
                    ),
                    TpmAlgId::Sha384 => rsa_priv.decrypt(
                        Oaep::new_with_label::<Sha384, _>(KDF_DUPLICATE),
                        &cmd.in_sym_seed,
                    ),
                    TpmAlgId::Sha512 => rsa_priv.decrypt(
                        Oaep::new_with_label::<Sha512, _>(KDF_DUPLICATE),
                        &cmd.in_sym_seed,
                    ),
                    _ => return Err(TpmRc::from(TpmRcBase::Scheme)),
                };
                match decrypt_result {
                    Ok(seed) => seed,
                    Err(_) => {
                        return Err(TpmRc::from(TpmRcBase::Value));
                    }
                }
            }
        };

        let parent_name_alg = parent_key.public.name_alg;
        let Ok(integrity_key_bits) =
            u16::try_from(tpm2_protocol::tpm_hash_size(&parent_name_alg).unwrap_or(0) * 8)
        else {
            return Err(TpmRc::from(TpmRcBase::Value));
        };

        let Ok(hmac_key) = crypto_kdfa(
            parent_name_alg,
            &seed,
            KDF_INTEGRITY,
            &parent_name,
            &[],
            integrity_key_bits,
        ) else {
            return Err(TpmRc::from(TpmRcBase::Failure));
        };

        let Some(hash_len) = tpm2_protocol::tpm_hash_size(&parent_name_alg) else {
            return Err(TpmRc::from(TpmRcBase::Hash));
        };

        if cmd.duplicate.len() < hash_len {
            return Err(TpmRc::from(TpmRcBase::Size));
        }

        let (received_hmac, encrypted_sensitive) = cmd.duplicate.split_at(hash_len);

        macro_rules! verify_hmac {
            ($digest:ty) => {{
                let mut integrity_mac =
                    <hmac::Hmac<$digest> as hmac::Mac>::new_from_slice(&hmac_key).unwrap();
                integrity_mac.update(encrypted_sensitive);
                integrity_mac.update(&parent_name);
                integrity_mac.verify_slice(received_hmac).is_ok()
            }};
        }

        let hmac_ok = match parent_name_alg {
            TpmAlgId::Sha256 => verify_hmac!(Sha256),
            TpmAlgId::Sha384 => verify_hmac!(Sha384),
            TpmAlgId::Sha512 => verify_hmac!(Sha512),
            _ => false,
        };

        if !hmac_ok {
            return Err(TpmRc::from(TpmRcBase::Integrity));
        }

        let resp = TpmImportResponse {
            out_private: Tpm2bPrivate::default(),
        };
        Ok((
            TpmRc::from(TpmRcBase::Success),
            TpmResponseBody::Import(resp),
            TpmAuthResponses::default(),
        ))
    }

    fn load(&mut self, cmd: TpmLoadCommand) -> MockTpmResult {
        if !self.objects.contains_key(&cmd.parent_handle.0) {
            return Err(TpmRc::from(TpmRcBase::Handle));
        }

        let public = cmd.in_public.inner;
        let handle = self.next_handle;
        self.next_handle += 1;
        self.objects.insert(
            handle,
            MockTpmKey {
                public: public.clone(),
                private: None,
            },
        );

        let Ok(name_bytes) = crypto_make_name(&public) else {
            return Err(TpmRc::from(TpmRcBase::Hash));
        };
        let Ok(name) = Tpm2bName::try_from(name_bytes.as_slice()) else {
            return Err(TpmRc::from(TpmRcBase::Value));
        };

        let resp = TpmLoadResponse {
            object_handle: TpmTransient(handle),
            name,
        };

        Ok((
            TpmRc::from(TpmRcBase::Success),
            TpmResponseBody::Load(resp),
            TpmAuthResponses::default(),
        ))
    }

    fn read_public(&mut self, cmd: TpmReadPublicCommand) -> MockTpmResult {
        let Some(key) = self.objects.get(&cmd.object_handle.0) else {
            return Err(TpmRc::from(TpmRcBase::Handle));
        };
        let Ok(name_bytes) = crypto_make_name(&key.public) else {
            return Err(TpmRc::from(TpmRcBase::Hash));
        };
        let Ok(name) = Tpm2bName::try_from(name_bytes.as_slice()) else {
            return Err(TpmRc::from(TpmRcBase::Value));
        };
        let resp = TpmReadPublicResponse {
            out_public: Tpm2bPublic::from(key.public.clone()),
            name: name.clone(),
            qualified_name: name,
        };
        Ok((
            TpmRc::from(TpmRcBase::Success),
            TpmResponseBody::ReadPublic(resp),
            TpmAuthResponses::default(),
        ))
    }
}

fn mocktpm_build_response(response: MockTpmResult) -> Result<Vec<u8>, TpmErrorKind> {
    let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        match response {
            Ok((rc, response_body, auth_responses)) => {
                response_body.build(&mut writer, rc, &auth_responses)?;
            }
            Err(rc) => {
                tpm_build_response(&TpmFlushContextResponse {}, &[], rc, &mut writer)?;
            }
        }
        writer.len()
    };
    Ok(buf[..len].to_vec())
}

fn mocktpm_run(mut stream: UnixStream) {
    let mut state = MockTpm::new();

    loop {
        let mut header = [0u8; TPM_HEADER_SIZE];
        if stream.read_exact(&mut header).is_err() {
            break;
        }

        let Ok(size_bytes): Result<[u8; 4], _> = header[2..6].try_into() else {
            error!("Malformed header size");
            break;
        };
        let size = u32::from_be_bytes(size_bytes) as usize;

        if size < TPM_HEADER_SIZE || size > TPM_MAX_COMMAND_SIZE {
            error!("Invalid command size: {}", size);
            break;
        }

        let mut command_buf = header.to_vec();
        command_buf.resize(size, 0);

        if let Err(e) = stream.read_exact(&mut command_buf[TPM_HEADER_SIZE..]) {
            error!("{e}");
            break;
        }

        let response = state.parse(&command_buf);
        let response = match mocktpm_build_response(response) {
            Ok(response) => response,
            Err(e) => {
                error!("{e}");
                break;
            }
        };

        if stream.write_all(&response).is_err() || stream.flush().is_err() {
            error!("no response");
            break;
        }
    }
}

fn run() -> Result<(), String> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

    let mut parser = lexopt::Parser::from_env();
    let mut cache_path: Option<PathBuf> = None;

    while let Some(arg) = parser
        .next()
        .map_err(|e| format!("Argument parsing error: {e}"))?
    {
        match arg {
            Long("cache-path") => {
                let value = parser
                    .value()
                    .map_err(|e| format!("Missing value for --cache-path: {e}"))?;
                let path_str = value
                    .string()
                    .map_err(|_| "Value for --cache-path is not valid UTF-8".to_string())?;
                cache_path = Some(PathBuf::from(path_str));
            }
            Long("help") => {
                eprintln!("Usage: mocktpm [--cache-path <PATH>]");
                return Ok(());
            }
            _ => {
                return Err(format!("Unexpected argument: {}", arg.unexpected()));
            }
        }
    }

    let cache_path = cache_path.unwrap_or_else(|| {
        directories::ProjectDirs::from("org", "puavo", "tpm2sh")
            .map(|d| d.cache_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/tmp/tpm2sh"))
    });

    std::fs::create_dir_all(&cache_path).map_err(|e| format!("{}: {e}", cache_path.display()))?;

    let socket_path = cache_path.join(SOCKET_NAME);
    let path = Path::new(&socket_path);

    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != io::ErrorKind::NotFound {
            return Err(format!("{}: {e}", path.display()));
        }
    }

    let listener = UnixListener::bind(path).map_err(|e| format!("{}: {e}", path.display()))?;

    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)) {
        warn!("{}: {e}", path.display());
    }

    info!("Socket: {}", path.display());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                mocktpm_run(stream);
            }
            Err(e) => {
                error!("{e}");
            }
        }
    }

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        error!("{e}");
        exit(1);
    }
}

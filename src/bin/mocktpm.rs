// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use cli::{crypto_hmac_verify, crypto_kdfa, crypto_make_name};

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    process::exit,
};

use lexopt::prelude::*;
use log::{error, info, warn};
use rsa::{traits::PublicKeyParts, Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384, Sha512};
use tpm2_protocol::{
    data::{
        Tpm2bCreationData, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa, TpmAlgId,
        TpmCap, TpmCc, TpmRc, TpmRcBase, TpmRh, TpmaAlgorithm, TpmaCc, TpmlAlgProperty, TpmlCca,
        TpmlHandle, TpmsAlgProperty, TpmtPublic, TpmtTkCreation, TpmuCapabilities, TpmuPublicId,
        TpmuPublicParms,
    },
    message::{
        tpm_build_response, tpm_parse_command, TpmAuthResponses, TpmCommandBody,
        TpmContextLoadCommand, TpmContextLoadResponse, TpmContextSaveCommand,
        TpmContextSaveResponse, TpmCreatePrimaryCommand, TpmCreatePrimaryResponse,
        TpmFlushContextCommand, TpmFlushContextResponse, TpmGetCapabilityCommand,
        TpmGetCapabilityResponse, TpmImportCommand, TpmImportResponse, TpmLoadCommand,
        TpmLoadResponse, TpmReadPublicCommand, TpmReadPublicResponse, TpmResponseBody,
    },
    TpmBuffer, TpmErrorKind, TpmParse, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
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

/// `MockTPM` response trait
trait MockTpmResponse {
    fn build(
        &self,
        writer: &mut TpmWriter,
        rc: TpmRc,
        auth_responses: &TpmAuthResponses,
    ) -> Result<(), tpm2_protocol::TpmErrorKind>;
}

macro_rules! mocktpm_response {
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
                        TpmResponseBody::$variant(r) => tpm_build_response(r, auth_responses, rc, writer),
                    )*
                    _ => Err(tpm2_protocol::TpmErrorKind::Unreachable),
                }
            }
        }
    };
}

mocktpm_response!(
    ContextLoad,
    ContextSave,
    CreatePrimary,
    FlushContext,
    GetCapability,
    Import,
    Load,
    ReadPublic,
);

#[derive(Debug, Default)]
struct MockTpm {
    objects: HashMap<u32, MockTpmKey>,
    next_handle: u32,
}

macro_rules! mocktpm_command {
    ($state:ident, $cmd_body:ident, $($variant:ident => $handler:path),* $(,)?) => {
        match $cmd_body {
            $(
                TpmCommandBody::$variant(cmd) => $handler($state, &cmd),
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

    fn parse(&mut self, request_buf: &[u8]) -> MockTpmResult {
        let Ok((_handles, cmd_body, _sessions)) = tpm_parse_command(request_buf) else {
            return Err(TpmRc::from(TpmRcBase::BadTag));
        };

        mocktpm_command! {
            self, cmd_body,
            ContextLoad => mocktpm_context_load,
            ContextSave => mocktpm_context_save,
            CreatePrimary => mocktpm_create_primary,
            FlushContext => mocktpm_flush_context,
            GetCapability => mocktpm_get_capability,
            Import => mocktpm_import,
            Load => mocktpm_load,
            ReadPublic => mocktpm_read_public,
        }
    }
}

fn mocktpm_supported_commands() -> &'static [TpmCc] {
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

fn mocktpm_supported_algs() -> &'static [TpmsAlgProperty] {
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

#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
fn mocktpm_context_load(_tpm: &mut MockTpm, cmd: &TpmContextLoadCommand) -> MockTpmResult {
    let resp = TpmContextLoadResponse {
        loaded_handle: cmd.context.saved_handle,
    };
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::ContextLoad(resp),
        TpmAuthResponses::default(),
    ))
}

#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
fn mocktpm_context_save(_tpm: &mut MockTpm, cmd: &TpmContextSaveCommand) -> MockTpmResult {
    let resp = TpmContextSaveResponse {
        context: tpm2_protocol::data::TpmsContext {
            sequence: 1,
            saved_handle: cmd.save_handle,
            hierarchy: TpmRh::Owner,
            context_blob: TpmBuffer::default(),
        },
    };
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::ContextSave(resp),
        TpmAuthResponses::default(),
    ))
}

fn mocktpm_create_primary(tpm: &mut MockTpm, cmd: &TpmCreatePrimaryCommand) -> MockTpmResult {
    let mut public = cmd.in_public.inner.clone();
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

    let handle = tpm.next_handle;
    tpm.next_handle += 1;
    tpm.objects.insert(
        handle,
        MockTpmKey {
            public: public.clone(),
            private,
        },
    );

    let name_bytes = crypto_make_name(&public)?;
    let Ok(name) = Tpm2bName::try_from(name_bytes.as_slice()) else {
        return Err(TpmRc::from(TpmRcBase::Value));
    };
    let resp = TpmCreatePrimaryResponse {
        object_handle: TpmTransient(handle),
        out_public: Tpm2bPublic { inner: public },
        creation_data: Tpm2bCreationData::default(),
        creation_hash: TpmBuffer::default(),
        creation_ticket: TpmtTkCreation::default(),
        name,
    };
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::CreatePrimary(resp),
        TpmAuthResponses::default(),
    ))
}

#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
fn mocktpm_flush_context(_tpm: &mut MockTpm, _cmd: &TpmFlushContextCommand) -> MockTpmResult {
    let resp = TpmFlushContextResponse {};
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::FlushContext(resp),
        TpmAuthResponses::default(),
    ))
}

fn mocktpm_get_capability(tpm: &mut MockTpm, cmd: &TpmGetCapabilityCommand) -> MockTpmResult {
    let capability_data = match cmd.cap {
        TpmCap::Commands => {
            let all_cmds = mocktpm_supported_commands();
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
            let all_algs = mocktpm_supported_algs();
            let filtered_algs: Vec<TpmsAlgProperty> = all_algs
                .iter()
                .filter(|a| (a.alg as u32) >= cmd.property)
                .take(cmd.property_count as usize)
                .copied()
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
            if prop >= (TpmRh::TransientFirst as u32) && prop < (TpmRh::PersistentFirst as u32) {
                handles = tpm.objects.keys().copied().collect();
                handles.sort_unstable();
            }

            let mut list = TpmlHandle::new();
            for handle in handles {
                list.try_push(handle)
                    .map_err(|_| TpmRc::from(TpmRcBase::Failure))?;
            }
            TpmuCapabilities::Handles(list)
        }
        TpmCap::Pcrs => {
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

fn mocktpm_import(tpm: &mut MockTpm, cmd: &TpmImportCommand) -> MockTpmResult {
    let Some(parent_key) = tpm.objects.get(&cmd.parent_handle.0) else {
        return Err(TpmRc::from(TpmRcBase::Handle));
    };

    let Some(parent_private) = parent_key.private.as_ref() else {
        return Err(TpmRc::from(TpmRcBase::Key));
    };

    let parent_name_bytes = crypto_make_name(&parent_key.public)?;
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

    let hmac_key = crypto_kdfa(
        parent_name_alg,
        &seed,
        KDF_INTEGRITY,
        &parent_name,
        &[],
        integrity_key_bits,
    )?;

    let Some(hash_len) = tpm2_protocol::tpm_hash_size(&parent_name_alg) else {
        return Err(TpmRc::from(TpmRcBase::Hash));
    };

    if cmd.duplicate.len() < hash_len {
        return Err(TpmRc::from(TpmRcBase::Size));
    }

    let (received_hmac, encrypted_sensitive) = cmd.duplicate.split_at(hash_len);

    crypto_hmac_verify(
        parent_name_alg,
        &hmac_key,
        &[encrypted_sensitive, &parent_name],
        received_hmac,
    )?;

    let resp = TpmImportResponse {
        out_private: Tpm2bPrivate::default(),
    };
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::Import(resp),
        TpmAuthResponses::default(),
    ))
}

fn mocktpm_load(tpm: &mut MockTpm, cmd: &TpmLoadCommand) -> MockTpmResult {
    if !tpm.objects.contains_key(&cmd.parent_handle.0) {
        return Err(TpmRc::from(TpmRcBase::Handle));
    }

    let public = cmd.in_public.inner.clone();
    let handle = tpm.next_handle;
    tpm.next_handle += 1;
    tpm.objects.insert(
        handle,
        MockTpmKey {
            public: public.clone(),
            private: None,
        },
    );

    let name_bytes = crypto_make_name(&public)?;
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

#[allow(clippy::trivially_copy_pass_by_ref)]
fn mocktpm_read_public(tpm: &mut MockTpm, cmd: &TpmReadPublicCommand) -> MockTpmResult {
    let Some(key) = tpm.objects.get(&cmd.object_handle.0) else {
        return Err(TpmRc::from(TpmRcBase::Handle));
    };
    let name_bytes = crypto_make_name(&key.public)?;
    let Ok(name) = Tpm2bName::try_from(name_bytes.as_slice()) else {
        return Err(TpmRc::from(TpmRcBase::Value));
    };
    let resp = TpmReadPublicResponse {
        out_public: Tpm2bPublic::from(key.public.clone()),
        name,
        qualified_name: name,
    };
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::ReadPublic(resp),
        TpmAuthResponses::default(),
    ))
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

fn mocktpm_run<T: Read + Write>(mut stream: T, state: &mut MockTpm) {
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

        if !(TPM_HEADER_SIZE..=TPM_MAX_COMMAND_SIZE).contains(&size) {
            error!("Invalid command size: {size}");
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
        directories::ProjectDirs::from("org", "puavo", "tpm2sh").map_or_else(
            || PathBuf::from("/tmp/tpm2sh"),
            |d| d.cache_dir().to_path_buf(),
        )
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

    let mut state = MockTpm::new();
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                mocktpm_run(stream, &mut state);
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

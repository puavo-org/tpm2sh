// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

#![allow(clippy::all)]
#![allow(clippy::pedantic)]

use cli::{build_to_vec, TpmError};

use std::{
    collections::HashMap,
    io::{self, Read, Write},
    os::unix::fs::PermissionsExt,
    os::unix::net::{UnixListener, UnixStream},
    path::{Path, PathBuf},
    process::exit,
};

use lexopt::prelude::*;
use log::{error, info, warn};
use rsa::{traits::PublicKeyParts, RsaPrivateKey};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tpm2_protocol::{
    data::{
        Tpm2bName, Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa, TpmAlgId, TpmRc, TpmRcBase, TpmRh,
        TpmsAuthResponse, TpmtPublic, TpmuPublicId, TpmuPublicParms,
    },
    message::{
        tpm_build_response, tpm_parse_command, TpmCommandBody, TpmContextLoadResponse,
        TpmContextSaveResponse, TpmCreatePrimaryResponse, TpmFlushContextResponse,
        TpmImportResponse, TpmReadPublicResponse, TpmResponseBody,
    },
    TpmList, TpmTransient, TpmWriter, TPM_MAX_COMMAND_SIZE,
};

const TPM_HEADER_SIZE: usize = 10;
const SOCKET_NAME: &str = "mock-tpm.sock";
const AUTH_RESPONSE_MAX: usize = 3;

type TpmAuthResponses = TpmList<TpmsAuthResponse, AUTH_RESPONSE_MAX>;
type TpmResponse = Result<(TpmRc, TpmResponseBody, TpmAuthResponses), (TpmRc, TpmAuthResponses)>;

/// Trait to build mock responses without a large match statement.
trait MockTpmResponse {
    fn build(
        &self,
        writer: &mut TpmWriter,
        rc: TpmRc,
        auth_responses: &TpmAuthResponses,
    ) -> Result<(), tpm2_protocol::TpmErrorKind>;
}

impl MockTpmResponse for TpmResponseBody {
    fn build(
        &self,
        writer: &mut TpmWriter,
        rc: TpmRc,
        auth_responses: &TpmAuthResponses,
    ) -> Result<(), tpm2_protocol::TpmErrorKind> {
        match self {
            Self::CreatePrimary(r) => tpm_build_response(r, auth_responses, rc, writer),
            Self::ReadPublic(r) => tpm_build_response(r, auth_responses, rc, writer),
            Self::Import(r) => tpm_build_response(r, auth_responses, rc, writer),
            Self::ContextSave(r) => tpm_build_response(r, auth_responses, rc, writer),
            Self::ContextLoad(r) => tpm_build_response(r, auth_responses, rc, writer),
            Self::FlushContext(r) => tpm_build_response(r, auth_responses, rc, writer),
            _ => Err(tpm2_protocol::TpmErrorKind::Unreachable),
        }
    }
}

#[derive(Debug, Default)]
struct MockTpmState {
    transient_objects: HashMap<u32, TpmtPublic>,
    next_handle: u32,
}

fn calculate_name(public: &TpmtPublic) -> Result<Vec<u8>, TpmError> {
    let mut name_buf = Vec::new();
    let name_alg = public.name_alg;
    name_buf.extend_from_slice(&(name_alg as u16).to_be_bytes());
    let public_area_bytes = build_to_vec(public)?;
    let digest: Vec<u8> = match name_alg {
        TpmAlgId::Sha256 => Sha256::digest(&public_area_bytes).to_vec(),
        TpmAlgId::Sha384 => Sha384::digest(&public_area_bytes).to_vec(),
        TpmAlgId::Sha512 => Sha512::digest(&public_area_bytes).to_vec(),
        _ => {
            return Err(TpmError::Execution(format!(
                "Unsupported name algorithm: {name_alg}"
            )))
        }
    };
    name_buf.extend_from_slice(&digest);
    Ok(name_buf)
}

impl MockTpmState {
    fn new() -> Self {
        Self {
            next_handle: 0x8000_0000,
            ..Default::default()
        }
    }

    fn handle_command(&mut self, request_buf: &[u8]) -> TpmResponse {
        let Ok((_handles, cmd_body, _sessions)) = tpm_parse_command(request_buf) else {
            return Err((TpmRc::from(TpmRcBase::BadTag), TpmAuthResponses::default()));
        };

        let rc = TpmRc::from(TpmRcBase::Success);

        match cmd_body {
            TpmCommandBody::CreatePrimary(cmd) => {
                let mut public = cmd.in_public.inner;

                if public.object_type == TpmAlgId::Rsa {
                    let key_bits = if let TpmuPublicParms::Rsa(params) = public.parameters {
                        params.key_bits
                    } else {
                        return Err((TpmRc::from(TpmRcBase::Value), TpmAuthResponses::default()));
                    };

                    let Ok(rsa_key) = RsaPrivateKey::new(&mut rand::thread_rng(), key_bits.into())
                    else {
                        return Err((TpmRc::from(TpmRcBase::Failure), TpmAuthResponses::default()));
                    };
                    let modulus = rsa_key.n().to_bytes_be();
                    let Ok(unique_rsa) = Tpm2bPublicKeyRsa::try_from(modulus.as_slice()) else {
                        return Err((TpmRc::from(TpmRcBase::Value), TpmAuthResponses::default()));
                    };
                    public.unique = TpmuPublicId::Rsa(unique_rsa);
                }

                let handle = self.next_handle;
                self.next_handle += 1;
                self.transient_objects.insert(handle, public.clone());

                let Ok(name_bytes) = calculate_name(&public) else {
                    return Err((TpmRc::from(TpmRcBase::Hash), TpmAuthResponses::default()));
                };
                let Ok(name) = Tpm2bName::try_from(name_bytes.as_slice()) else {
                    return Err((TpmRc::from(TpmRcBase::Value), TpmAuthResponses::default()));
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
                    rc,
                    TpmResponseBody::CreatePrimary(resp),
                    TpmAuthResponses::default(),
                ))
            }
            TpmCommandBody::ReadPublic(cmd) => {
                let Some(public) = self.transient_objects.get(&cmd.object_handle.0) else {
                    return Err((TpmRc::from(TpmRcBase::Handle), TpmAuthResponses::default()));
                };
                let Ok(name_bytes) = calculate_name(public) else {
                    return Err((TpmRc::from(TpmRcBase::Hash), TpmAuthResponses::default()));
                };
                let Ok(name) = Tpm2bName::try_from(name_bytes.as_slice()) else {
                    return Err((TpmRc::from(TpmRcBase::Value), TpmAuthResponses::default()));
                };
                let resp = TpmReadPublicResponse {
                    out_public: Tpm2bPublic::from(public.clone()),
                    name: name.clone(),
                    qualified_name: name,
                };
                Ok((
                    rc,
                    TpmResponseBody::ReadPublic(resp),
                    TpmAuthResponses::default(),
                ))
            }
            TpmCommandBody::Import(cmd) => {
                if !self.transient_objects.contains_key(&cmd.parent_handle.0) {
                    return Err((TpmRc::from(TpmRcBase::Handle), TpmAuthResponses::default()));
                }

                match cmd.object_public.inner.object_type {
                    TpmAlgId::Rsa | TpmAlgId::Ecc => {}
                    _ => {
                        return Err((TpmRc::from(TpmRcBase::Value), TpmAuthResponses::default()));
                    }
                }

                let resp = TpmImportResponse {
                    out_private: Tpm2bPrivate::default(),
                };
                Ok((
                    rc,
                    TpmResponseBody::Import(resp),
                    TpmAuthResponses::default(),
                ))
            }
            TpmCommandBody::ContextSave(cmd) => {
                let resp = TpmContextSaveResponse {
                    context: tpm2_protocol::data::TpmsContext {
                        sequence: 1,
                        saved_handle: cmd.save_handle,
                        hierarchy: TpmRh::Owner,
                        context_blob: Default::default(),
                    },
                };
                Ok((
                    rc,
                    TpmResponseBody::ContextSave(resp),
                    TpmAuthResponses::default(),
                ))
            }
            TpmCommandBody::ContextLoad(cmd) => {
                let resp = TpmContextLoadResponse {
                    loaded_handle: cmd.context.saved_handle,
                };
                Ok((
                    rc,
                    TpmResponseBody::ContextLoad(resp),
                    TpmAuthResponses::default(),
                ))
            }
            TpmCommandBody::FlushContext(_cmd) => {
                let resp = TpmFlushContextResponse {};
                Ok((
                    rc,
                    TpmResponseBody::FlushContext(resp),
                    TpmAuthResponses::default(),
                ))
            }
            _ => Err((
                TpmRc::from(TpmRcBase::CommandCode),
                TpmAuthResponses::default(),
            )),
        }
    }
}

fn build_response_vec(response_result: TpmResponse) -> Result<Vec<u8>, TpmError> {
    let mut response_buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut response_buf);
        match response_result {
            Ok((rc, response_body, auth_responses)) => {
                response_body.build(&mut writer, rc, &auth_responses)?;
            }
            Err((rc, auth_responses)) => {
                tpm_build_response(
                    &TpmFlushContextResponse {},
                    &auth_responses,
                    rc,
                    &mut writer,
                )?;
            }
        }
        writer.len()
    };
    Ok(response_buf[..len].to_vec())
}

fn handle_client(mut stream: UnixStream) {
    let mut state = MockTpmState::new();

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

        let response_result = state.handle_command(&command_buf);
        let response = match build_response_vec(response_result) {
            Ok(vec) => vec,
            Err(e) => {
                error!("Failed to build response: {e}");
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
                info!("Usage: mock-tpm [--cache-path <PATH>]");
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

    info!("Listening on {}", path.display());

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                info!("Accepted connection");
                handle_client(stream);
                info!("Client disconnected");
            }
            Err(e) => {
                error!("Accepting connection failed: {e}");
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

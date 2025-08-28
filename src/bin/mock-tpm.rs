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
};

use lexopt::prelude::*;
use log::{error, info, warn};
use sha2::{Digest, Sha256, Sha384, Sha512};
use tpm2_protocol::{
    data::{
        Tpm2bName, Tpm2bPrivate, Tpm2bPublic, TpmAlgId, TpmRc, TpmRcBase, TpmRh, TpmsAuthResponse,
        TpmtPublic,
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
        let (_handles, cmd_body, _sessions) = match tpm_parse_command(request_buf) {
            Ok(result) => result,
            Err(_) => {
                return Err((TpmRc::from(TpmRcBase::BadTag), TpmAuthResponses::default()));
            }
        };

        let rc = TpmRc::try_from(TpmRcBase::Success as u32).unwrap();

        match cmd_body {
            TpmCommandBody::CreatePrimary(cmd) => {
                let handle = self.next_handle;
                self.next_handle += 1;
                self.transient_objects
                    .insert(handle, cmd.in_public.inner.clone());

                let name_bytes = match calculate_name(&cmd.in_public.inner) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Err((TpmRc::from(TpmRcBase::Hash), TpmAuthResponses::default()))
                    }
                };
                let name = match Tpm2bName::try_from(name_bytes.as_slice()) {
                    Ok(n) => n,
                    Err(_) => {
                        return Err((TpmRc::from(TpmRcBase::Value), TpmAuthResponses::default()))
                    }
                };
                let resp = TpmCreatePrimaryResponse {
                    object_handle: TpmTransient(handle),
                    out_public: cmd.in_public,
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
                let name_bytes = match calculate_name(public) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return Err((TpmRc::from(TpmRcBase::Hash), TpmAuthResponses::default()))
                    }
                };
                let name = match Tpm2bName::try_from(name_bytes.as_slice()) {
                    Ok(n) => n,
                    Err(_) => {
                        return Err((TpmRc::from(TpmRcBase::Value), TpmAuthResponses::default()))
                    }
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
            TpmCommandBody::Import(_cmd) => {
                let resp = TpmImportResponse {
                    out_private: Tpm2bPrivate::try_from(&[0u8; 64][..]).unwrap(),
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

fn handle_client(mut stream: UnixStream) {
    let mut state = MockTpmState::new();

    loop {
        let mut header = [0u8; TPM_HEADER_SIZE];
        if stream.read_exact(&mut header).is_err() {
            break;
        }

        let size_bytes: [u8; 4] = match header[2..6].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                error!("Malformed header size");
                break;
            }
        };
        let size = u32::from_be_bytes(size_bytes) as usize;

        if size < TPM_HEADER_SIZE || size > TPM_MAX_COMMAND_SIZE {
            error!("Invalid command size: {}", size);
            break;
        }

        let mut command_buf = header.to_vec();
        command_buf.resize(size, 0);

        if let Err(e) = stream.read_exact(&mut command_buf[TPM_HEADER_SIZE..]) {
            error!("{}", e);
            break;
        }

        let response = {
            let mut response_buf = [0u8; TPM_MAX_COMMAND_SIZE];
            let len = {
                let mut writer = TpmWriter::new(&mut response_buf);
                let response_result = state.handle_command(&command_buf);
                match response_result {
                    Ok((rc, response_body, auth_responses)) => match response_body {
                        TpmResponseBody::CreatePrimary(ref resp) => {
                            tpm_build_response(resp, &auth_responses, rc, &mut writer).unwrap()
                        }
                        TpmResponseBody::ReadPublic(ref resp) => {
                            tpm_build_response(resp, &auth_responses, rc, &mut writer).unwrap()
                        }
                        TpmResponseBody::Import(ref resp) => {
                            tpm_build_response(resp, &auth_responses, rc, &mut writer).unwrap()
                        }
                        TpmResponseBody::ContextSave(ref resp) => {
                            tpm_build_response(resp, &auth_responses, rc, &mut writer).unwrap()
                        }
                        TpmResponseBody::ContextLoad(ref resp) => {
                            tpm_build_response(resp, &auth_responses, rc, &mut writer).unwrap()
                        }
                        TpmResponseBody::FlushContext(ref resp) => {
                            tpm_build_response(resp, &auth_responses, rc, &mut writer).unwrap()
                        }
                        _ => (),
                    },
                    Err((rc, auth_responses)) => {
                        tpm_build_response(
                            &TpmFlushContextResponse {},
                            &auth_responses,
                            rc,
                            &mut writer,
                        )
                        .unwrap();
                    }
                }
                writer.len()
            };
            response_buf[..len].to_vec()
        };

        if stream.write_all(&response).is_err() || stream.flush().is_err() {
            error!("no response");
            break;
        }
    }
}

fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_micros()
        .init();

    let mut parser = lexopt::Parser::from_env();
    let mut cache_path: Option<PathBuf> = None;

    while let Some(arg) = parser.next().unwrap() {
        match arg {
            Long("cache-path") => {
                let path_str = parser.value().unwrap().string().unwrap();
                cache_path = Some(PathBuf::from(path_str));
            }
            Long("help") => {
                info!("Usage: mock-tpm [--cache-path <PATH>]");
                return;
            }
            _ => {
                error!("Unexpected argument: {:?}", arg);
                std::process::exit(1);
            }
        }
    }

    let cache_path = cache_path.unwrap_or_else(|| {
        directories::ProjectDirs::from("org", "puavo", "tpm2sh")
            .map(|d| d.cache_dir().to_path_buf())
            .unwrap_or_else(|| PathBuf::from("/tmp/tpm2sh"))
    });

    if let Err(e) = std::fs::create_dir_all(&cache_path) {
        error!("{}: {}", cache_path.display(), e);
        std::process::exit(1);
    }

    let socket_path = cache_path.join(SOCKET_NAME);
    let path = Path::new(&socket_path);

    if let Err(e) = std::fs::remove_file(path) {
        if e.kind() != io::ErrorKind::NotFound {
            error!("{}: {}", path.display(), e);
            std::process::exit(1);
        }
    }

    let listener = match UnixListener::bind(path) {
        Ok(l) => l,
        Err(e) => {
            error!("{}: {}", path.display(), e);
            std::process::exit(1);
        }
    };

    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o777)) {
        warn!("{}: {}", path.display(), e);
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
                error!("Accepting connection failed: {}", e);
            }
        }
    }
}

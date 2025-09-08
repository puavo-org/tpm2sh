// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

#![deny(clippy::all)]
#![deny(clippy::pedantic)]

use crate::{
    crypto::{
        crypto_hmac, crypto_hmac_verify, crypto_kdfa, crypto_make_name, PrivateKey,
        KDF_LABEL_DUPLICATE, KDF_LABEL_INTEGRITY, KDF_LABEL_STORAGE,
    },
    device::TpmTransport,
    transport::{Endpoint, EndpointGuard, EndpointState, Transport},
};
use aes::Aes128;
use cfb_mode::{Decryptor, Encryptor};
use cipher::{AsyncStreamCipher, KeyIvInit};
use log::error;
use pkcs8::{DecodePrivateKey, EncodePrivateKey};
use rsa::{traits::PublicKeyParts, Oaep, RsaPrivateKey};
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Condvar, Mutex},
};
use tpm2_protocol::{
    self,
    data::{
        Tpm2bCreationData, Tpm2bDigest, Tpm2bName, Tpm2bPrivate, Tpm2bPublic, Tpm2bPublicKeyRsa,
        Tpm2bSensitiveData, TpmAlgId, TpmCap, TpmCc, TpmEccCurve, TpmRc, TpmRcBase, TpmRh,
        TpmaAlgorithm, TpmaCc, TpmlAlgProperty, TpmlCca, TpmlDigest, TpmlEccCurve, TpmlHandle,
        TpmlPcrSelection, TpmlTaggedTpmProperty, TpmsAlgProperty, TpmsAlgorithmDetailEcc,
        TpmsAuthCommand, TpmsCapabilityData, TpmsContext, TpmsPcrSelection, TpmtPublic,
        TpmtPublicParms, TpmtSensitive, TpmtTkCreation, TpmuCapabilities, TpmuPublicId,
        TpmuPublicParms, TPM_RH_PERSISTENT_FIRST, TPM_RH_TRANSIENT_FIRST,
    },
    message::{
        tpm_build_response, tpm_parse_command, TpmAuthResponses, TpmCommandBody,
        TpmContextLoadCommand, TpmContextLoadResponse, TpmContextSaveCommand,
        TpmContextSaveResponse, TpmCreateCommand, TpmCreatePrimaryCommand,
        TpmCreatePrimaryResponse, TpmCreateResponse, TpmEccParametersCommand,
        TpmEccParametersResponse, TpmEvictControlCommand, TpmEvictControlResponse,
        TpmFlushContextCommand, TpmFlushContextResponse, TpmGetCapabilityCommand,
        TpmGetCapabilityResponse, TpmImportCommand, TpmImportResponse, TpmLoadCommand,
        TpmLoadResponse, TpmPcrEventCommand, TpmPcrEventResponse, TpmPcrReadCommand,
        TpmPcrReadResponse, TpmPolicyGetDigestCommand, TpmPolicyGetDigestResponse,
        TpmPolicyPcrCommand, TpmPolicyPcrResponse, TpmReadPublicCommand, TpmReadPublicResponse,
        TpmResponseBody, TpmStartAuthSessionCommand, TpmStartAuthSessionResponse,
        TpmTestParmsCommand, TpmTestParmsResponse, TpmUnsealCommand, TpmUnsealResponse,
    },
    TpmBuffer, TpmBuild, TpmErrorKind, TpmParse, TpmSession, TpmTransient, TpmWriter,
    TPM_MAX_COMMAND_SIZE,
};

const TPM_HEADER_SIZE: usize = 10;
const PCR_COUNT: usize = 24;

type MockTpmResult = Result<(TpmRc, TpmResponseBody, TpmAuthResponses), TpmRc>;

/// Converts `TpmErrorKind` to `TpmRc`.
trait TpmErrorKindExt {
    fn to_tpm_rc(self) -> TpmRc;
}

/// The first approximation of mapping. This should really be revisited against
/// TCG specifications some day.
impl TpmErrorKindExt for TpmErrorKind {
    fn to_tpm_rc(self) -> TpmRc {
        let base = match self {
            TpmErrorKind::AuthMissing => TpmRcBase::AuthMissing,
            TpmErrorKind::InvalidMagic { .. } | TpmErrorKind::InvalidTag { .. } => {
                TpmRcBase::BadTag
            }
            TpmErrorKind::BuildCapacity
            | TpmErrorKind::ParseCapacity
            | TpmErrorKind::InvalidValue
            | TpmErrorKind::NotDiscriminant(..) => TpmRcBase::Value,
            TpmErrorKind::BuildOverflow
            | TpmErrorKind::ParseUnderflow
            | TpmErrorKind::TrailingData => TpmRcBase::Size,
            TpmErrorKind::Unreachable => TpmRcBase::Failure,
        };
        TpmRc::from(base)
    }
}

/// A helper to build a `TpmBuild` type into a `Vec<u8>`.
///
/// # Errors
///
/// Returns a `TpmRc` if the object cannot be serialized.
fn build_to_vec<T: TpmBuild>(obj: &T) -> Result<Vec<u8>, TpmRc> {
    let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        obj.build(&mut writer).map_err(TpmErrorKindExt::to_tpm_rc)?;
        writer.len()
    };
    Ok(buf[..len].to_vec())
}

#[derive(Debug, Clone, Default)]
struct MockSession {
    policy_digest: Tpm2bDigest,
}

#[derive(Debug, Clone)]
struct MockTpmKey {
    public: TpmtPublic,
    private: Option<PrivateKey>,
    seed_value: Vec<u8>,
    sensitive_data: Tpm2bSensitiveData,
}

impl MockTpmKey {
    /// Serializes the key to bytes for file storage.
    fn to_bytes(&self) -> Result<Vec<u8>, TpmRc> {
        let mut bytes = Vec::new();
        let pub_bytes = build_to_vec(&self.public)?;
        bytes.extend_from_slice(
            &u16::try_from(pub_bytes.len())
                .map_err(|_| TpmRc::from(TpmRcBase::Memory))?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&pub_bytes);

        bytes.extend_from_slice(
            &u16::try_from(self.seed_value.len())
                .map_err(|_| TpmRc::from(TpmRcBase::Memory))?
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&self.seed_value);

        if let Some(private) = &self.private {
            bytes.push(1);
            let priv_bytes = match private {
                PrivateKey::Rsa(k) => k
                    .to_pkcs8_der()
                    .map_err(|_| TpmRc::from(TpmRcBase::Value))?
                    .as_bytes()
                    .to_vec(),
                PrivateKey::Ecc(k) => k
                    .to_pkcs8_der()
                    .map_err(|_| TpmRc::from(TpmRcBase::Value))?
                    .as_bytes()
                    .to_vec(),
            };
            bytes.extend_from_slice(
                &u16::try_from(priv_bytes.len())
                    .map_err(|_| TpmRc::from(TpmRcBase::Memory))?
                    .to_be_bytes(),
            );
            bytes.extend_from_slice(&priv_bytes);
        } else {
            bytes.push(0);
        }
        Ok(bytes)
    }

    /// Deserializes a key from bytes.
    fn from_bytes(bytes: &[u8]) -> Result<Self, TpmRc> {
        let (pub_len_bytes, remainder) = bytes.split_at(std::mem::size_of::<u16>());
        let pub_len = u16::from_be_bytes(pub_len_bytes.try_into().unwrap()) as usize;

        let (pub_bytes, remainder) = remainder.split_at(pub_len);
        let (public, _) = TpmtPublic::parse(pub_bytes).map_err(TpmErrorKindExt::to_tpm_rc)?;

        let (seed_len_bytes, remainder) = remainder.split_at(std::mem::size_of::<u16>());
        let seed_len = u16::from_be_bytes(seed_len_bytes.try_into().unwrap()) as usize;

        let (seed_value_bytes, remainder) = remainder.split_at(seed_len);
        let seed_value = seed_value_bytes.to_vec();

        let (priv_present_byte, remainder) = remainder.split_at(1);
        let private = if priv_present_byte[0] == 1 {
            let (priv_len_bytes, priv_remainder) = remainder.split_at(std::mem::size_of::<u16>());
            let priv_len = u16::from_be_bytes(priv_len_bytes.try_into().unwrap()) as usize;
            let (priv_bytes, _) = priv_remainder.split_at(priv_len);

            let private_key = match public.object_type {
                TpmAlgId::Rsa => PrivateKey::Rsa(Box::new(
                    RsaPrivateKey::from_pkcs8_der(priv_bytes)
                        .map_err(|_| TpmRc::from(TpmRcBase::Value))?,
                )),
                TpmAlgId::Ecc => PrivateKey::Ecc(
                    p256::SecretKey::from_pkcs8_der(priv_bytes)
                        .map_err(|_| TpmRc::from(TpmRcBase::Value))?,
                ),
                _ => return Err(TpmRc::from(TpmRcBase::Value)),
            };
            Some(private_key)
        } else {
            None
        };

        Ok(Self {
            public,
            private,
            seed_value,
            sensitive_data: Tpm2bSensitiveData::default(),
        })
    }
}
trait MockTpmResponse {
    fn build(
        &self,
        writer: &mut TpmWriter,
        rc: TpmRc,
        auth_responses: &TpmAuthResponses,
    ) -> Result<(), TpmRc>;
}

macro_rules! mocktpm_response {
    ($($variant:ident),* $(,)?) => {
        impl MockTpmResponse for TpmResponseBody {
            fn build(
                &self,
                writer: &mut TpmWriter,
                rc: TpmRc,
                auth_responses: &TpmAuthResponses,
            ) -> Result<(), TpmRc> {
                match self {
                    $(
                        TpmResponseBody::$variant(r) => {
                            let result = tpm_build_response(r, auth_responses, rc, writer);
                            result.map_err(TpmErrorKindExt::to_tpm_rc)
                        }
                    )*
                    _ => Err(TpmErrorKind::Unreachable.to_tpm_rc()),
                }
            }
        }
    };
}

mocktpm_response!(
    ContextLoad,
    ContextSave,
    Create,
    CreatePrimary,
    EccParameters,
    EvictControl,
    FlushContext,
    GetCapability,
    Import,
    Load,
    PcrEvent,
    PcrRead,
    PolicyGetDigest,
    PolicyPcr,
    ReadPublic,
    StartAuthSession,
    TestParms,
    Unseal,
);

#[derive(Debug, Default)]
struct MockTpm {
    objects: HashMap<u32, MockTpmKey>,
    sessions: HashMap<u32, MockSession>,
    pcrs: HashMap<TpmAlgId, Vec<Vec<u8>>>,
    next_transient_handle: u32,
    next_session_handle: u32,
    nvram_path: Option<PathBuf>,
}

macro_rules! mocktpm_command {
    ($state:ident, $cmd_body:ident, $sessions:ident, $($variant:ident => $handler:path),* $(,)?) => {
        match $cmd_body {
            $(
                TpmCommandBody::$variant(cmd) => $handler($state, &cmd, &$sessions),
            )*
            _ => Err(
                TpmRc::from(TpmRcBase::CommandCode),
            ),
        }
    };
}

impl MockTpm {
    fn new(nvram_path: Option<&Path>) -> Self {
        let path = nvram_path.map(|p| {
            assert!(p.is_dir(), "Persistence path must be a directory");
            p.to_path_buf()
        });

        let mut pcrs = HashMap::new();
        pcrs.insert(TpmAlgId::Sha256, vec![vec![0; 32]; PCR_COUNT]);
        pcrs.insert(TpmAlgId::Sha1, vec![vec![0; 20]; PCR_COUNT]);

        Self {
            next_transient_handle: 0x8000_0000,
            next_session_handle: 0x0300_0000,
            nvram_path: path,
            pcrs,
            ..Default::default()
        }
    }

    fn load_persistent_if_needed(&mut self, handle: u32) -> Result<(), TpmRc> {
        if handle < TPM_RH_PERSISTENT_FIRST {
            return Ok(());
        }
        if self.objects.contains_key(&handle) {
            return Ok(());
        }

        let path = self
            .nvram_path
            .as_ref()
            .ok_or(TpmRc::from(TpmRcBase::Handle))?;
        let key_path = path.join(format!("{handle:#010x}.dat"));

        let key_bytes = fs::read(key_path).map_err(|_| TpmRc::from(TpmRcBase::Handle))?;
        let key = MockTpmKey::from_bytes(&key_bytes)?;
        self.objects.insert(handle, key);
        Ok(())
    }

    fn parse(&mut self, request_buf: &[u8]) -> MockTpmResult {
        let (handles, cmd_body, sessions) =
            tpm_parse_command(request_buf).map_err(TpmErrorKindExt::to_tpm_rc)?;

        for handle in handles.iter().copied() {
            self.load_persistent_if_needed(handle)?;
        }

        mocktpm_command! {
            self, cmd_body, sessions,
            ContextLoad => mocktpm_context_load,
            ContextSave => mocktpm_context_save,
            Create => mocktpm_create,
            CreatePrimary => mocktpm_create_primary,
            EccParameters => mocktpm_ecc_parameters,
            EvictControl => mocktpm_evict_control,
            FlushContext => mocktpm_flush_context,
            GetCapability => mocktpm_get_capability,
            Import => mocktpm_import,
            Load => mocktpm_load,
            PcrEvent => mocktpm_pcr_event,
            PcrRead => mocktpm_pcr_read,
            PolicyGetDigest => mocktpm_policy_get_digest,
            PolicyPcr => mocktpm_policy_pcr,
            ReadPublic => mocktpm_read_public,
            StartAuthSession => mocktpm_start_auth_session,
            TestParms => mocktpm_test_parms,
            Unseal => mocktpm_unseal,
        }
    }
}

#[must_use]
pub fn start(nvram_path: Option<&Path>) -> (std::thread::JoinHandle<()>, impl TpmTransport) {
    let from_server = Arc::new(EndpointGuard {
        state: Mutex::new(EndpointState {
            buffer: VecDeque::new(),
            writer_dropped: false,
        }),
        cvar: Condvar::new(),
    });
    let from_client = Arc::new(EndpointGuard {
        state: Mutex::new(EndpointState {
            buffer: VecDeque::new(),
            writer_dropped: false,
        }),
        cvar: Condvar::new(),
    });

    let server = Transport(Endpoint(from_client.clone()), Endpoint(from_server.clone()));
    let client = Transport(Endpoint(from_server), Endpoint(from_client));

    let path_buf = nvram_path.map(PathBuf::from);
    let handle = std::thread::spawn(move || {
        let mut state = MockTpm::new(path_buf.as_deref());
        mocktpm_run(server, &mut state);
    });

    (handle, client)
}

fn mocktpm_supported_commands() -> &'static [TpmCc] {
    &[
        TpmCc::ContextLoad,
        TpmCc::ContextSave,
        TpmCc::Create,
        TpmCc::CreatePrimary,
        TpmCc::EccParameters,
        TpmCc::EvictControl,
        TpmCc::FlushContext,
        TpmCc::GetCapability,
        TpmCc::Import,
        TpmCc::Load,
        TpmCc::PcrEvent,
        TpmCc::PcrRead,
        TpmCc::PolicyGetDigest,
        TpmCc::PolicyPcr,
        TpmCc::ReadPublic,
        TpmCc::StartAuthSession,
        TpmCc::TestParms,
        TpmCc::Unseal,
    ]
}

fn mocktpm_supported_algs() -> &'static [TpmsAlgProperty] {
    const ASYMMETRIC_OBJECT_ATTRS: TpmaAlgorithm = TpmaAlgorithm::from_bits_truncate(
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
            alg_properties: ASYMMETRIC_OBJECT_ATTRS,
        },
        TpmsAlgProperty {
            alg: TpmAlgId::Ecc,
            alg_properties: ASYMMETRIC_OBJECT_ATTRS,
        },
        TpmsAlgProperty {
            alg: TpmAlgId::KeyedHash,
            alg_properties: TpmaAlgorithm::OBJECT,
        },
    ]
}

#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
fn mocktpm_context_load(
    _tpm: &mut MockTpm,
    cmd: &TpmContextLoadCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
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
fn mocktpm_context_save(
    _tpm: &mut MockTpm,
    cmd: &TpmContextSaveCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let resp = TpmContextSaveResponse {
        context: TpmsContext {
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

fn mocktpm_create(
    tpm: &mut MockTpm,
    cmd: &TpmCreateCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    if !tpm.objects.contains_key(&cmd.parent_handle.0) {
        return Err(TpmRc::from(TpmRcBase::Handle));
    }

    let public = cmd.in_public.inner.clone();
    let handle = tpm.next_transient_handle;
    tpm.next_transient_handle += 1;

    tpm.objects.insert(
        handle,
        MockTpmKey {
            public: public.clone(),
            private: None,
            seed_value: Vec::new(),
            sensitive_data: cmd.in_sensitive.inner.data,
        },
    );

    let name_bytes = crypto_make_name(&public)?;
    let Ok(_name) = Tpm2bName::try_from(name_bytes.as_slice()) else {
        return Err(TpmRc::from(TpmRcBase::Value));
    };

    let resp = TpmCreateResponse {
        out_private: Tpm2bPrivate::default(),
        out_public: Tpm2bPublic { inner: public },
        creation_data: Tpm2bCreationData::default(),
        creation_hash: TpmBuffer::default(),
        creation_ticket: TpmtTkCreation::default(),
    };

    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::Create(resp),
        TpmAuthResponses::default(),
    ))
}

fn mocktpm_create_primary(
    tpm: &mut MockTpm,
    cmd: &TpmCreatePrimaryCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
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
        private = Some(PrivateKey::Rsa(Box::new(rsa_key.clone())));
        let modulus = rsa_key.n().to_bytes_be();
        let Ok(unique_rsa) = Tpm2bPublicKeyRsa::try_from(modulus.as_slice()) else {
            return Err(TpmRc::from(TpmRcBase::Value));
        };
        public.unique = TpmuPublicId::Rsa(unique_rsa);
    }

    let handle = tpm.next_transient_handle;
    tpm.next_transient_handle += 1;

    let public_bytes = build_to_vec(&public)?;
    let seed_value = Sha256::digest(&public_bytes).to_vec();

    tpm.objects.insert(
        handle,
        MockTpmKey {
            public: public.clone(),
            private,
            seed_value,
            sensitive_data: Tpm2bSensitiveData::default(),
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
fn mocktpm_ecc_parameters(
    _tpm: &mut MockTpm,
    cmd: &TpmEccParametersCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let supported_curves = [
        TpmEccCurve::NistP256,
        TpmEccCurve::NistP384,
        TpmEccCurve::NistP521,
    ];
    if supported_curves.contains(&cmd.curve_id) {
        let resp = TpmEccParametersResponse {
            parameters: TpmsAlgorithmDetailEcc::default(),
        };
        return Ok((
            TpmRc::from(TpmRcBase::Success),
            TpmResponseBody::EccParameters(resp),
            TpmAuthResponses::default(),
        ));
    }
    Err(TpmRc::from(TpmRcBase::Curve))
}

#[allow(clippy::unnecessary_wraps)]
fn mocktpm_evict_control(
    tpm: &mut MockTpm,
    cmd: &TpmEvictControlCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let Some(nvram_path) = tpm.nvram_path.as_ref() else {
        return Err(TpmRc::from(TpmRcBase::NvUnavailable));
    };

    let persistent_handle = cmd.persistent_handle.0;
    let object_handle = cmd.object_handle.0;

    if object_handle >= TPM_RH_TRANSIENT_FIRST {
        let key_to_persist = tpm
            .objects
            .get(&object_handle)
            .ok_or(TpmRc::from(TpmRcBase::Handle))?
            .clone();
        let key_bytes = key_to_persist.to_bytes()?;

        let file_path = nvram_path.join(format!("{persistent_handle:#010x}.dat"));
        fs::write(file_path, key_bytes).map_err(|_| TpmRc::from(TpmRcBase::NvUnavailable))?;
    } else if object_handle >= TPM_RH_PERSISTENT_FIRST {
        if object_handle != persistent_handle {
            return Err(TpmRc::from(TpmRcBase::Handle));
        }
        let file_path = nvram_path.join(format!("{persistent_handle:#010x}.dat"));
        if fs::remove_file(file_path).is_ok() {
            tpm.objects.remove(&persistent_handle);
        }
    } else {
        return Err(TpmRc::from(TpmRcBase::Handle));
    }

    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::EvictControl(TpmEvictControlResponse {}),
        TpmAuthResponses::default(),
    ))
}

#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
fn mocktpm_flush_context(
    _tpm: &mut MockTpm,
    _cmd: &TpmFlushContextCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let resp = TpmFlushContextResponse {};
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::FlushContext(resp),
        TpmAuthResponses::default(),
    ))
}

fn mocktpm_get_capability(
    tpm: &mut MockTpm,
    cmd: &TpmGetCapabilityCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
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
            if (TPM_RH_TRANSIENT_FIRST..TPM_RH_PERSISTENT_FIRST).contains(&prop) {
                handles = tpm.objects.keys().copied().collect();
                handles.sort_unstable();
            }

            let mut list = TpmlHandle::new();
            for handle in handles.iter().copied() {
                list.try_push(handle)
                    .map_err(|_| TpmRc::from(TpmRcBase::Failure))?;
            }
            TpmuCapabilities::Handles(list)
        }
        TpmCap::EccCurves => {
            let mut list = TpmlEccCurve::new();
            list.try_push(TpmEccCurve::NistP256).unwrap();
            list.try_push(TpmEccCurve::NistP384).unwrap();
            list.try_push(TpmEccCurve::NistP521).unwrap();
            TpmuCapabilities::EccCurves(list)
        }
        TpmCap::TpmProperties => {
            let list = TpmlTaggedTpmProperty::new();
            TpmuCapabilities::TpmProperties(list)
        }
        TpmCap::Pcrs => {
            let mut pcr_selection = TpmlPcrSelection::new();
            for (alg, pcr_bank) in &tpm.pcrs {
                let mut pcr_select = vec![0; pcr_bank.len() / 8];
                for i in 0..pcr_bank.len() {
                    pcr_select[i / 8] |= 1 << (i % 8);
                }
                pcr_selection
                    .try_push(TpmsPcrSelection {
                        hash: *alg,
                        pcr_select: TpmBuffer::try_from(pcr_select.as_slice())
                            .map_err(|_| TpmRc::from(TpmRcBase::Failure))?,
                    })
                    .map_err(|_| TpmRc::from(TpmRcBase::Failure))?;
            }
            TpmuCapabilities::Pcrs(pcr_selection)
        }
    };

    let resp = TpmGetCapabilityResponse {
        more_data: false.into(),
        capability_data: TpmsCapabilityData {
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

#[allow(clippy::too_many_lines)]
fn mocktpm_import(
    tpm: &mut MockTpm,
    cmd: &TpmImportCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let Some(parent_key) = tpm.objects.get(&cmd.parent_handle.0) else {
        return Err(TpmRc::from(TpmRcBase::Handle));
    };

    let Some(parent_private) = parent_key.private.as_ref() else {
        return Err(TpmRc::from(TpmRcBase::Key));
    };

    let parent_name_bytes = crypto_make_name(&parent_key.public)?;
    let Ok(parent_name) = Tpm2bName::try_from(parent_name_bytes.as_slice()) else {
        return Err(TpmRc::from(TpmRcBase::Value));
    };

    let seed = match (parent_private, &parent_key.public) {
        (PrivateKey::Rsa(rsa_priv), TpmtPublic { name_alg, .. }) => {
            let decrypt_result = match name_alg {
                TpmAlgId::Sha1 => rsa_priv.decrypt(
                    Oaep::new_with_label::<Sha1, _>(KDF_LABEL_DUPLICATE),
                    &cmd.in_sym_seed,
                ),
                TpmAlgId::Sha256 => rsa_priv.decrypt(
                    Oaep::new_with_label::<Sha256, _>(KDF_LABEL_DUPLICATE),
                    &cmd.in_sym_seed,
                ),
                TpmAlgId::Sha384 => rsa_priv.decrypt(
                    Oaep::new_with_label::<Sha384, _>(KDF_LABEL_DUPLICATE),
                    &cmd.in_sym_seed,
                ),
                TpmAlgId::Sha512 => rsa_priv.decrypt(
                    Oaep::new_with_label::<Sha512, _>(KDF_LABEL_DUPLICATE),
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
        _ => {
            return Err(TpmRc::from(TpmRcBase::Key));
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
        KDF_LABEL_INTEGRITY,
        &[],
        &[],
        integrity_key_bits,
    )?;

    let (hmac_struct, encrypted_sensitive) =
        Tpm2bDigest::parse(&cmd.duplicate).map_err(TpmErrorKindExt::to_tpm_rc)?;
    let received_hmac = &hmac_struct;

    crypto_hmac_verify(
        parent_name_alg,
        &hmac_key,
        &[encrypted_sensitive, &parent_name],
        received_hmac,
    )?;

    let object_name = crypto_make_name(&cmd.object_public.inner)?;
    let sym_key = crypto_kdfa(
        parent_name_alg,
        &seed,
        KDF_LABEL_STORAGE,
        &object_name,
        &parent_name,
        128,
    )?;

    let iv = [0u8; 16];
    let mut sensitive_data = encrypted_sensitive.to_vec();
    let cipher = Decryptor::<Aes128>::new(sym_key.as_slice().into(), &iv.into());
    cipher.decrypt(&mut sensitive_data);

    let (sensitive_struct, _) =
        TpmtSensitive::parse(&sensitive_data).map_err(TpmErrorKindExt::to_tpm_rc)?;

    let sym_key_rewrap = crypto_kdfa(
        parent_key.public.name_alg,
        &parent_key.seed_value,
        KDF_LABEL_STORAGE,
        &object_name,
        &parent_name,
        128,
    )?;
    let hmac_key_rewrap = crypto_kdfa(
        parent_key.public.name_alg,
        &parent_key.seed_value,
        KDF_LABEL_INTEGRITY,
        &[],
        &[],
        integrity_key_bits,
    )?;

    let sensitive_bytes = build_to_vec(&sensitive_struct)?;
    let mut encrypted_sensitive_rewrap = sensitive_bytes;
    let cipher_rewrap = Encryptor::<Aes128>::new(sym_key_rewrap.as_slice().into(), &iv.into());
    cipher_rewrap.encrypt(&mut encrypted_sensitive_rewrap);

    let final_mac = crypto_hmac(
        parent_key.public.name_alg,
        &hmac_key_rewrap,
        &[&encrypted_sensitive_rewrap, &object_name],
    )?;

    let mut final_private_blob = Vec::new();
    final_private_blob.extend_from_slice(&final_mac);
    final_private_blob.extend_from_slice(&encrypted_sensitive_rewrap);

    let out_private = Tpm2bPrivate::try_from(final_private_blob.as_slice())
        .map_err(TpmErrorKindExt::to_tpm_rc)?;

    let resp = TpmImportResponse { out_private };
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::Import(resp),
        TpmAuthResponses::default(),
    ))
}

fn mocktpm_load(
    tpm: &mut MockTpm,
    cmd: &TpmLoadCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    if !tpm.objects.contains_key(&cmd.parent_handle.0) {
        return Err(TpmRc::from(TpmRcBase::Handle));
    }

    let public = cmd.in_public.inner.clone();
    let handle = tpm.next_transient_handle;
    tpm.next_transient_handle += 1;
    tpm.objects.insert(
        handle,
        MockTpmKey {
            public: public.clone(),
            private: None,
            seed_value: Vec::new(),
            sensitive_data: Tpm2bSensitiveData::default(),
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

#[allow(clippy::unnecessary_wraps)]
fn mocktpm_pcr_event(
    tpm: &mut MockTpm,
    cmd: &TpmPcrEventCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    if cmd.pcr_handle >= u32::try_from(PCR_COUNT).unwrap() {
        return Err(TpmRc::from(TpmRcBase::Handle));
    }
    let pcr_index = cmd.pcr_handle as usize;

    for (alg, pcr_bank) in &mut tpm.pcrs {
        let old_val = &pcr_bank[pcr_index];
        let new_val = match alg {
            TpmAlgId::Sha1 => {
                let event_digest = Sha1::digest(cmd.event_data.as_ref());
                let mut combined = Vec::with_capacity(old_val.len() + event_digest.len());
                combined.extend_from_slice(old_val);
                combined.extend_from_slice(&event_digest);
                Sha1::digest(&combined).to_vec()
            }
            TpmAlgId::Sha256 => {
                let event_digest = Sha256::digest(cmd.event_data.as_ref());
                let mut combined = Vec::with_capacity(old_val.len() + event_digest.len());
                combined.extend_from_slice(old_val);
                combined.extend_from_slice(&event_digest);
                Sha256::digest(&combined).to_vec()
            }
            _ => continue,
        };
        pcr_bank[pcr_index] = new_val;
    }

    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::PcrEvent(TpmPcrEventResponse::default()),
        TpmAuthResponses::default(),
    ))
}

fn mocktpm_pcr_read(
    tpm: &mut MockTpm,
    cmd: &TpmPcrReadCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let mut pcr_values = TpmlDigest::new();
    let mut pcr_selection_out = TpmlPcrSelection::new();

    for selection in cmd.pcr_selection_in.iter() {
        if let Some(pcr_bank) = tpm.pcrs.get(&selection.hash) {
            for (byte_idx, &byte) in selection.pcr_select.iter().enumerate() {
                for bit_idx in 0..8 {
                    if (byte >> bit_idx) & 1 == 1 {
                        let pcr_index = byte_idx * 8 + bit_idx;
                        if pcr_index < pcr_bank.len() {
                            let digest = Tpm2bDigest::try_from(pcr_bank[pcr_index].as_slice())
                                .map_err(|_| TpmRc::from(TpmRcBase::Value))?;
                            pcr_values
                                .try_push(digest)
                                .map_err(|_| TpmRc::from(TpmRcBase::Memory))?;
                        }
                    }
                }
            }
            pcr_selection_out
                .try_push(*selection)
                .map_err(|_| TpmRc::from(TpmRcBase::Memory))?;
        }
    }

    let resp = TpmPcrReadResponse {
        pcr_update_counter: 1,
        pcr_selection_out,
        pcr_values,
    };

    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::PcrRead(resp),
        TpmAuthResponses::default(),
    ))
}

#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
fn mocktpm_policy_get_digest(
    tpm: &mut MockTpm,
    cmd: &TpmPolicyGetDigestCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let session = tpm
        .sessions
        .get(&cmd.policy_session.0)
        .ok_or(TpmRc::from(TpmRcBase::Handle))?;
    let resp = TpmPolicyGetDigestResponse {
        policy_digest: session.policy_digest,
    };
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::PolicyGetDigest(resp),
        TpmAuthResponses::default(),
    ))
}

#[allow(clippy::unnecessary_wraps)]
fn mocktpm_policy_pcr(
    tpm: &mut MockTpm,
    cmd: &TpmPolicyPcrCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let session = tpm
        .sessions
        .get_mut(&cmd.policy_session.0)
        .ok_or(TpmRc::from(TpmRcBase::Handle))?;
    session.policy_digest = cmd.pcr_digest;
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::PolicyPcr(TpmPolicyPcrResponse {}),
        TpmAuthResponses::default(),
    ))
}

#[allow(clippy::trivially_copy_pass_by_ref)]
fn mocktpm_read_public(
    tpm: &mut MockTpm,
    cmd: &TpmReadPublicCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
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

#[allow(clippy::unnecessary_wraps)]
fn mocktpm_start_auth_session(
    tpm: &mut MockTpm,
    _cmd: &TpmStartAuthSessionCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let handle = tpm.next_session_handle;
    tpm.next_session_handle += 1;
    tpm.sessions.insert(handle, MockSession::default());

    let resp = TpmStartAuthSessionResponse {
        session_handle: TpmSession(handle),
        nonce_tpm: TpmBuffer::default(),
    };
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::StartAuthSession(resp),
        TpmAuthResponses::default(),
    ))
}

#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
fn mocktpm_test_parms(
    _tpm: &mut MockTpm,
    cmd: &TpmTestParmsCommand,
    _sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    if let TpmtPublicParms {
        object_type: TpmAlgId::Rsa,
        parameters: TpmuPublicParms::Rsa(params),
    } = cmd.parameters
    {
        if params.key_bits == 2048 {
            let resp = TpmTestParmsResponse {};
            return Ok((
                TpmRc::from(TpmRcBase::Success),
                TpmResponseBody::TestParms(resp),
                TpmAuthResponses::default(),
            ));
        }
    }
    Err(TpmRc::from(TpmRcBase::Value))
}

#[allow(clippy::unnecessary_wraps, clippy::trivially_copy_pass_by_ref)]
fn mocktpm_unseal(
    tpm: &mut MockTpm,
    cmd: &TpmUnsealCommand,
    sessions: &[TpmsAuthCommand],
) -> MockTpmResult {
    let object = tpm
        .objects
        .get(&cmd.item_handle.0)
        .ok_or(TpmRc::from(TpmRcBase::Handle))?;

    if !object.public.auth_policy.is_empty() {
        let auth_session = sessions
            .first()
            .ok_or(TpmRc::from(TpmRcBase::AuthMissing))?;
        let session_state = tpm
            .sessions
            .get(&auth_session.session_handle.0)
            .ok_or(TpmRc::from(TpmRcBase::Handle))?;
        if session_state.policy_digest != object.public.auth_policy {
            return Err(TpmRc::from(TpmRcBase::AuthFail));
        }
    }

    let resp = TpmUnsealResponse {
        out_data: object.sensitive_data,
    };
    Ok((
        TpmRc::from(TpmRcBase::Success),
        TpmResponseBody::Unseal(resp),
        TpmAuthResponses::default(),
    ))
}

fn mocktpm_build_response(response: MockTpmResult) -> Result<Vec<u8>, TpmRc> {
    let mut buf = [0u8; TPM_MAX_COMMAND_SIZE];
    let len = {
        let mut writer = TpmWriter::new(&mut buf);
        match response {
            Ok((rc, response_body, auth_responses)) => {
                response_body.build(&mut writer, rc, &auth_responses)?;
            }
            Err(rc) => {
                tpm_build_response(&TpmFlushContextResponse {}, &[], rc, &mut writer)
                    .map_err(TpmErrorKindExt::to_tpm_rc)?;
            }
        }
        writer.len()
    };
    Ok(buf[..len].to_vec())
}

fn mocktpm_run(mut stream: impl Read + Write, state: &mut MockTpm) {
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

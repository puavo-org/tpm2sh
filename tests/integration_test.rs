// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use cli::{
    cli::{Cli, Commands, LogFormat},
    command::{
        algorithms::Algorithms, context::Context, create_primary::CreatePrimary, import::Import,
        objects::Objects, seal::Seal, start_session::StartSession, unseal::Unseal,
    },
    device::TpmDevice,
    error::CliError,
    parser::PolicyExpr,
    session::AuthSession,
    uri::Uri,
    Command,
};
use sha2::{Digest, Sha256};
use std::{
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use pkcs8::EncodePrivateKey;
use rstest::{fixture, rstest};
use tempfile::{tempdir, TempDir};
use tpm2_protocol::{
    data::{
        Tpm2bAuth, Tpm2bDigest, Tpm2bNonce, Tpm2bPrivate, Tpm2bPublic, TpmaSession,
        TpmlPcrSelection, TpmsAuthCommand,
    },
    message::{TpmLoadCommand, TpmPolicyPcrCommand},
    TpmParse, TpmSession,
};

struct TestFixture {
    _handle: JoinHandle<()>,
    device: Arc<Mutex<TpmDevice>>,
    cli: Cli,
    _temp_dir: TempDir,
}

#[fixture]
fn test_context() -> TestFixture {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
        .format_timestamp_micros()
        .try_init();
    let temp_dir = tempdir().unwrap();
    let (handle, transport) = cli::mocktpm::mocktpm_start(Some(temp_dir.path()));
    let mut cli = Cli::default();
    cli.log_format = LogFormat::Pretty;

    let device = Arc::new(Mutex::new(TpmDevice::new(transport, cli.log_format)));

    TestFixture {
        _handle: handle,
        device,
        cli,
        _temp_dir: temp_dir,
    }
}

#[rstest]
fn test_subcommand_algorithms(test_context: TestFixture) {
    let algorithms_cmd = Commands::Algorithms(Algorithms);
    let mut out_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut out_buf);
    algorithms_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();
    let output = String::from_utf8(out_buf).unwrap();

    let mut results: Vec<String> = output.lines().map(String::from).collect();
    results.sort();

    let mut expected = vec![
        "rsa:2048:sha256",
        "rsa:2048:sha384",
        "rsa:2048:sha512",
        "ecc:nist-p256:sha256",
        "ecc:nist-p256:sha384",
        "ecc:nist-p256:sha512",
        "ecc:nist-p384:sha256",
        "ecc:nist-p384:sha384",
        "ecc:nist-p384:sha512",
        "ecc:nist-p521:sha256",
        "ecc:nist-p521:sha384",
        "ecc:nist-p521:sha512",
        "keyedhash:sha256",
        "keyedhash:sha384",
        "keyedhash:sha512",
    ];
    expected.sort();

    assert_eq!(results, expected);
}

#[rstest]
fn test_subcommand_create_primary(test_context: TestFixture) {
    let create_cmd = Commands::CreatePrimary(CreatePrimary {
        algorithm: "keyedhash:sha256".parse().unwrap(),
        ..Default::default()
    });

    let mut context_uri_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut context_uri_buf);
    create_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();
    let context_uri_str = String::from_utf8(context_uri_buf).unwrap();
    let context_uri: Uri = context_uri_str.trim().parse().unwrap();

    let mut device = test_context.device.lock().unwrap();
    let mut dummy_writer = Vec::new();
    let mut verification_context = Context::new(&test_context.cli, &mut dummy_writer);

    let handle = verification_context
        .load(&mut device, &context_uri)
        .unwrap();
    let (_rc, public, _name) = device.read_public(handle).unwrap();

    assert!(
        public
            .object_attributes
            .contains(tpm2_protocol::data::TpmaObject::SIGN_ENCRYPT),
        "KeyedHash primary key must have the SIGN_ENCRYPT attribute set"
    );
}

#[rstest]
fn test_subcommand_import(test_context: TestFixture) {
    let parent_context_uri = "tpm://0x81000001".to_string();

    let create_cmd = Commands::CreatePrimary(CreatePrimary {
        algorithm: "rsa:2048:sha256".parse().unwrap(),
        handle: Some(parent_context_uri.parse().unwrap()),
        ..Default::default()
    });

    let mut parent_context_uri_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut parent_context_uri_buf);
    create_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();
    let returned_parent_uri = String::from_utf8(parent_context_uri_buf)
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(returned_parent_uri, parent_context_uri);

    let key_dir = tempdir().unwrap();
    let key_path = key_dir.path().join("import-key.pem");
    let rsa_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pem_doc = rsa_key.to_pkcs8_pem(Default::default()).unwrap();
    std::fs::write(&key_path, pem_doc.as_bytes()).unwrap();

    let import_cmd = Commands::Import(Import {
        parent: parent_context_uri.parse().unwrap(),
        key: format!("file://{}", key_path.to_str().unwrap())
            .parse()
            .unwrap(),
    });
    let mut import_output_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut import_output_buf);
    import_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();
    let output_text = String::from_utf8(import_output_buf).unwrap();
    let lines: Vec<&str> = output_text.trim().lines().collect();

    assert_eq!(lines.len(), 2, "Expected two lines of output");
    assert!(
        lines[0].starts_with("data://base64,"),
        "Public part should be a base64 data URI"
    );
    assert!(
        lines[1].starts_with("data://base64,"),
        "Private part should be a base64 data URI"
    );
}

#[rstest]
fn test_subcommand_objects(test_context: TestFixture) {
    let create_cmd = Commands::CreatePrimary(CreatePrimary {
        algorithm: "rsa:2048:sha256".parse().unwrap(),
        ..Default::default()
    });

    let mut dummy_writer = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut dummy_writer);
    create_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();
    create_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();

    let objects_cmd = Commands::Objects(Objects);
    let mut out_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut out_buf);
    objects_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();
    let output = String::from_utf8(out_buf).unwrap();

    let mut handles: Vec<u32> = output
        .lines()
        .filter_map(|line| line.strip_prefix("tpm://0x"))
        .filter_map(|hex| u32::from_str_radix(hex, 16).ok())
        .collect();
    handles.sort();

    assert_eq!(handles, vec![0x8000_0000, 0x8000_0001]);
}

#[ignore]
fn _test_subcommand_seal_load_unseal(test_context: TestFixture) -> Result<(), CliError> {
    let create_cmd = Commands::CreatePrimary(CreatePrimary {
        algorithm: "keyedhash:sha256".parse().unwrap(),
        ..Default::default()
    });
    let mut parent_context_uri_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut parent_context_uri_buf);
    create_cmd.run(Some(test_context.device.clone()), &mut context)?;
    let parent_uri: Uri = String::from_utf8(parent_context_uri_buf)
        .unwrap()
        .trim()
        .parse()
        .unwrap();

    let secret = "KEKKONEN";
    let policy_digest = Sha256::digest(b"pcr policy digest").to_vec();

    let seal_cmd = Commands::Seal(Seal {
        parent: parent_uri,
        data: format!("data://utf8,{secret}").parse().unwrap(),
        policy: Some(hex::encode(&policy_digest)),
        ..Default::default()
    });
    let mut sealed_blobs_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut sealed_blobs_buf);
    seal_cmd.run(Some(test_context.device.clone()), &mut context)?;
    let sealed_blobs_str = String::from_utf8(sealed_blobs_buf).unwrap();
    let mut lines = sealed_blobs_str.lines();
    let public_uri: Uri = lines.next().unwrap().parse().unwrap();
    let private_uri: Uri = lines.next().unwrap().parse().unwrap();

    let (in_public, _) = Tpm2bPublic::parse(&public_uri.to_bytes()?)?;
    let (in_private, _) = Tpm2bPrivate::parse(&private_uri.to_bytes()?)?;
    let load_cmd = TpmLoadCommand {
        parent_handle: 0x8000_0000.into(),
        in_private,
        in_public,
    };
    let (_rc, resp, _) = test_context
        .device
        .lock()
        .unwrap()
        .execute(&load_cmd, &[])?;
    let load_resp = resp.Load().unwrap();
    let loaded_handle = load_resp.object_handle.0;

    let start_session_cmd = Commands::StartSession(StartSession::default());
    let mut session_uri_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut session_uri_buf);
    start_session_cmd.run(Some(test_context.device.clone()), &mut context)?;
    let session_uri: Uri = String::from_utf8(session_uri_buf)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let session = if let PolicyExpr::Session {
        handle,
        nonce,
        attrs,
        key,
        alg,
    } = session_uri.ast()
    {
        Ok(AuthSession {
            handle: TpmSession(*handle),
            nonce_tpm: Tpm2bNonce::try_from(nonce.as_slice()).unwrap(),
            attributes: TpmaSession::from_bits_truncate(*attrs),
            hmac_key: Tpm2bAuth::try_from(key.as_slice()).unwrap(),
            auth_hash: cli::key::tpm_alg_id_from_str(alg).unwrap(),
        })
    } else {
        Err(CliError::Execution(
            "Failed to parse session URI".to_string(),
        ))
    }?;

    let policy_pcr_cmd = TpmPolicyPcrCommand {
        policy_session: session.handle.0.into(),
        pcr_digest: Tpm2bDigest::try_from(policy_digest.as_slice()).unwrap(),
        pcrs: TpmlPcrSelection::default(),
    };
    let policy_session_auth = TpmsAuthCommand {
        session_handle: session.handle,
        ..Default::default()
    };
    let _ = test_context
        .device
        .lock()
        .unwrap()
        .execute(&policy_pcr_cmd, &[policy_session_auth])?;

    let unseal_cmd = Commands::Unseal(Unseal {
        handle: format!("tpm://{loaded_handle:#010x}").parse().unwrap(),
    });
    let cli_for_unseal = Cli {
        session: Some(session_uri),
        ..Default::default()
    };
    let mut unsealed_data_buf = Vec::new();
    let mut context = Context::new(&cli_for_unseal, &mut unsealed_data_buf);
    unseal_cmd.run(Some(test_context.device.clone()), &mut context)?;
    let unsealed_secret = String::from_utf8(unsealed_data_buf).unwrap();

    assert_eq!(unsealed_secret, secret);

    Ok(())
}

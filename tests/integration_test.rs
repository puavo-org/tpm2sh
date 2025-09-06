// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy
// Copyright (c) 2024-2025 Jarkko Sakkinen

use cli::{
    cli::{Cli, Commands},
    command::{
        context::Context, create_primary::CreatePrimary, list::List, load::Load,
        pcr_event::PcrEvent, pcr_read::PcrRead, seal::Seal, start_session::StartSession,
        unseal::Unseal,
    },
    device::TpmDevice,
    error::{CliError, ParseError},
    policy::Expression,
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
    data::{Tpm2bDigest, TpmlPcrSelection},
    message::TpmPolicyPcrCommand,
    TpmSession,
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
    let cli = Cli::default();

    let device = Arc::new(Mutex::new(TpmDevice::new(transport, cli.log_format)));

    TestFixture {
        _handle: handle,
        device,
        cli,
        _temp_dir: temp_dir,
    }
}

#[rstest]
fn test_subcommand_list_algorithms(test_context: TestFixture) {
    let list_cmd = Commands::List(List {
        list_type: "algorithm".parse().unwrap(),
    });
    let mut out_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut out_buf);
    list_cmd
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
fn test_subcommand_load_import(test_context: TestFixture) {
    let parent_context_uri = "tpm://0x81000001".to_string();

    let create_cmd = Commands::CreatePrimary(CreatePrimary {
        algorithm: "rsa:2048:sha256".parse().unwrap(),
        output: Some(parent_context_uri.parse().unwrap()),
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

    let load_cmd = Commands::Load(Load {
        parent: parent_context_uri.parse().unwrap(),
        input: format!("file://{}", key_path.to_str().unwrap())
            .parse()
            .unwrap(),
        output: None,
    });
    let mut load_output_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut load_output_buf);
    load_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();
    let output_text = String::from_utf8(load_output_buf).unwrap();

    assert!(
        output_text.trim().starts_with("data://base64,"),
        "Expected output to be a single data URI for the saved context"
    );
}

#[rstest]
fn test_subcommand_list_objects(test_context: TestFixture) {
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

    let list_cmd = Commands::List(List {
        list_type: "transient".parse().unwrap(),
    });
    let mut out_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut out_buf);
    list_cmd
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

#[rstest]
fn test_subcommand_pcr_event(test_context: TestFixture) {
    let event_data = hex::decode("deadbeef").unwrap();
    let pcr_event_cmd = Commands::PcrEvent(PcrEvent {
        pcr_selection: "sha256:7".to_string(),
        data: "data://hex,deadbeef".parse().unwrap(),
    });
    let mut out_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut out_buf);
    pcr_event_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();

    let event_digest = Sha256::digest(&event_data);
    let mut pcr_hasher = Sha256::new();
    pcr_hasher.update(&[0u8; 32]);
    pcr_hasher.update(&event_digest);
    let new_pcr_value = pcr_hasher.finalize();

    let expected_composite_digest = Sha256::digest(&new_pcr_value);
    let pcr_read_cmd = Commands::PcrRead(PcrRead {
        expression: "pcr(sha256:7)".to_string(),
    });
    let mut out_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut out_buf);
    pcr_read_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();

    let output = String::from_utf8(out_buf).unwrap();
    let expected = format!("pcr(sha256:7, {})", hex::encode(expected_composite_digest));
    assert_eq!(output.trim(), expected);
}

#[rstest]
fn test_subcommand_pcr_read(test_context: TestFixture) {
    let pcr_read_cmd = Commands::PcrRead(PcrRead {
        expression: "pcr(sha256:0,7)".to_string(),
    });
    let mut out_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut out_buf);
    pcr_read_cmd
        .run(Some(test_context.device.clone()), &mut context)
        .unwrap();

    let composite_data = [[0u8; 32].as_slice(), [0u8; 32].as_slice()].concat();
    let expected_digest = Sha256::digest(composite_data);
    let output = String::from_utf8(out_buf).unwrap();
    let expected = format!("pcr(sha256:0,7, {})", hex::encode(expected_digest));

    assert_eq!(output.trim(), expected);
}

#[rstest]
fn test_subcommand_seal_policy_unseal(test_context: TestFixture) -> Result<(), CliError> {
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
        parent: parent_uri.clone(),
        data: format!("data://utf8,{secret}").parse().unwrap(),
        policy: Some(hex::encode(&policy_digest)),
        password: None,
        output: None,
    });
    let mut sealed_key_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut sealed_key_buf);
    seal_cmd.run(Some(test_context.device.clone()), &mut context)?;
    let sealed_key_pem = String::from_utf8(sealed_key_buf).unwrap();

    let key_dir = tempdir().unwrap();
    let sealed_key_path = key_dir.path().join("sealed.key");
    std::fs::write(&sealed_key_path, &sealed_key_pem)?;
    let sealed_key_uri: Uri = format!("file://{}", sealed_key_path.to_str().unwrap())
        .parse()
        .unwrap();

    let start_session_cmd = Commands::StartSession(StartSession::default());
    let mut session_uri_buf = Vec::new();
    let mut context = Context::new(&test_context.cli, &mut session_uri_buf);
    start_session_cmd.run(Some(test_context.device.clone()), &mut context)?;
    let session_uri: Uri = String::from_utf8(session_uri_buf)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let session = if let Expression::Session { handle, .. } = session_uri.ast() {
        Ok(TpmSession(*handle))
    } else {
        Err(CliError::Parse(ParseError::Custom(
            "Failed to parse session URI".to_string(),
        )))
    }?;

    let policy_pcr_cmd = TpmPolicyPcrCommand {
        policy_session: session.0.into(),
        pcr_digest: Tpm2bDigest::try_from(policy_digest.as_slice()).unwrap(),
        pcrs: TpmlPcrSelection::default(),
    };
    let _ = test_context
        .device
        .lock()
        .unwrap()
        .execute(&policy_pcr_cmd, &[])?;

    let unseal_cmd = Commands::Unseal(Unseal {
        uri: sealed_key_uri,
        parent: Some(parent_uri.clone()),
        password: None,
    });

    let cli_for_unseal = Cli {
        session: Some(session_uri),
        ..Default::default()
    };
    let mut unsealed_data_buf = Vec::new();
    let mut context = Context::new(&cli_for_unseal, &mut unsealed_data_buf);
    unseal_cmd.run(Some(test_context.device.clone()), &mut context)?;
    let unsealed_output = String::from_utf8(unsealed_data_buf).unwrap();
    let expected_output = format!("data://utf8,{secret}");

    assert_eq!(unsealed_output.trim(), expected_output);

    Ok(())
}

// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use cli::{
    cli::{Algorithms, Cli, Commands, CreatePrimary, Import, LogFormat, Objects, ParentArgs},
    device::TpmDevice,
    key, Command,
};
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
    thread::JoinHandle,
};

use pkcs8::EncodePrivateKey;
use rstest::{fixture, rstest};
use tempfile::tempdir;
use tpm2_protocol::data::TpmAlgId;

struct TestFixture {
    _handle: JoinHandle<()>,
    device: Arc<Mutex<TpmDevice>>,
    cli: Cli,
}

#[fixture]
fn test_context() -> TestFixture {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
        .format_timestamp_micros()
        .try_init();
    let (handle, transport) = cli::mocktpm::mocktpm_start();
    let mut cli = Cli::default();
    cli.log_format = LogFormat::Pretty;

    let device = Arc::new(Mutex::new(TpmDevice::new(transport, cli.log_format)));

    TestFixture {
        _handle: handle,
        device,
        cli,
    }
}

#[rstest]
fn test_subcommand_algorithms(test_context: TestFixture) {
    let algorithms_cmd = Commands::Algorithms(Algorithms { filter: None });
    let mut out_buf = Vec::new();
    algorithms_cmd
        .run(
            &test_context.cli,
            Some(test_context.device.clone()),
            &mut out_buf,
        )
        .unwrap();
    let output = String::from_utf8(out_buf).unwrap();

    let mut results: Vec<String> = output.lines().map(String::from).collect();
    results.sort();

    let supported_tpm_algs: HashSet<TpmAlgId> =
        [TpmAlgId::Rsa, TpmAlgId::Ecc].into_iter().collect();

    let mut expected: Vec<String> = key::enumerate_all()
        .filter(|alg| supported_tpm_algs.contains(&alg.object_type))
        .map(|alg| alg.name)
        .collect();
    expected.sort();

    assert_eq!(results, expected);

    let filtered_cmd = Commands::Algorithms(Algorithms {
        filter: Some("rsa:2048".to_string()),
    });
    let mut out_buf = Vec::new();
    filtered_cmd
        .run(
            &test_context.cli,
            Some(test_context.device.clone()),
            &mut out_buf,
        )
        .unwrap();
    let filtered_output = String::from_utf8(out_buf).unwrap();
    let filtered_results: Vec<String> = filtered_output.lines().map(String::from).collect();

    assert!(filtered_results
        .iter()
        .all(|line| line.starts_with("rsa:2048")));
    assert_eq!(filtered_results.len(), 3);
}

#[rstest]
fn test_subcommand_objects(test_context: TestFixture) {
    let create_cmd = Commands::CreatePrimary(CreatePrimary {
        algorithm: "rsa:2048:sha256".parse().unwrap(),
        ..Default::default()
    });

    create_cmd
        .run(
            &test_context.cli,
            Some(test_context.device.clone()),
            &mut Vec::new(),
        )
        .unwrap();
    create_cmd
        .run(
            &test_context.cli,
            Some(test_context.device.clone()),
            &mut Vec::new(),
        )
        .unwrap();

    let objects_cmd = Commands::Objects(Objects);
    let mut out_buf = Vec::new();
    objects_cmd
        .run(
            &test_context.cli,
            Some(test_context.device.clone()),
            &mut out_buf,
        )
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
fn test_subcommand_import(test_context: TestFixture) {
    let parent_context_uri = "tpm://0x81000001".to_string();

    let create_cmd = Commands::CreatePrimary(CreatePrimary {
        algorithm: "rsa:2048:sha256".parse().unwrap(),
        handle_uri: Some(parent_context_uri.parse().unwrap()),
        ..Default::default()
    });

    let mut parent_context_uri_buf = Vec::new();
    create_cmd
        .run(
            &test_context.cli,
            Some(test_context.device.clone()),
            &mut parent_context_uri_buf,
        )
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
        parent: ParentArgs {
            parent: parent_context_uri.parse().unwrap(),
        },
        key_uri: format!("file://{}", key_path.to_str().unwrap())
            .parse()
            .unwrap(),
    });
    let mut import_output_buf = Vec::new();
    import_cmd
        .run(
            &test_context.cli,
            Some(test_context.device.clone()),
            &mut import_output_buf,
        )
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

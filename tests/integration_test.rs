// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use cli::{
    cli::{Algorithms, Cli, Commands, CreatePrimary, Import, LogFormat, Objects},
    device::TpmDevice,
    key::{self, JsonTpmKey},
    Command, LOG_FORMAT,
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
}

fn setup_logging() {
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace"))
        .format_timestamp_micros()
        .try_init();

    let _ = LOG_FORMAT.set(LogFormat::Pretty);
}

#[fixture]
fn tpm_device() -> TestFixture {
    setup_logging();

    let (handle, transport) = cli::mocktpm::mocktpm_start();
    let device = Arc::new(Mutex::new(TpmDevice::new(transport)));

    TestFixture {
        _handle: handle,
        device,
    }
}

#[rstest]
fn test_subcommand_algorithms(tpm_device: TestFixture) {
    let algorithms_cmd = Commands::Algorithms(Algorithms { filter: None });
    let mut out_buf = Vec::new();
    algorithms_cmd
        .run(
            &Cli::default(),
            Some(tpm_device.device.clone()),
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
            &Cli::default(),
            Some(tpm_device.device.clone()),
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
fn test_subcommand_objects(tpm_device: TestFixture) {
    let create_cmd = Commands::CreatePrimary(CreatePrimary {
        algorithm: "rsa:2048:sha256".parse().unwrap(),
        ..Default::default()
    });

    create_cmd
        .run(
            &Cli::default(),
            Some(tpm_device.device.clone()),
            &mut Vec::new(),
        )
        .unwrap();
    create_cmd
        .run(
            &Cli::default(),
            Some(tpm_device.device.clone()),
            &mut Vec::new(),
        )
        .unwrap();

    let objects_cmd = Commands::Objects(Objects);
    let mut out_buf = Vec::new();
    objects_cmd
        .run(
            &Cli::default(),
            Some(tpm_device.device.clone()),
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
fn test_subcommand_import(tpm_device: TestFixture) {
    let create_cmd = Commands::CreatePrimary(CreatePrimary {
        algorithm: "rsa:2048:sha256".parse().unwrap(),
        ..Default::default()
    });
    let mut parent_context_uri_buf = Vec::new();
    create_cmd
        .run(
            &Cli::default(),
            Some(tpm_device.device.clone()),
            &mut parent_context_uri_buf,
        )
        .unwrap();
    let parent_context_uri = String::from_utf8(parent_context_uri_buf)
        .unwrap()
        .trim()
        .to_string();

    let key_dir = tempdir().unwrap();
    let key_path = key_dir.path().join("import-key.pem");
    let rsa_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pem_doc = rsa_key.to_pkcs8_pem(Default::default()).unwrap();
    std::fs::write(&key_path, pem_doc.as_bytes()).unwrap();

    let import_cmd = Commands::Import(Import {
        key_uri: format!("file://{}", key_path.to_str().unwrap()),
    });
    let cli_with_parent = Cli {
        parent: Some(parent_context_uri),
        ..Default::default()
    };
    let mut import_output_buf = Vec::new();
    import_cmd
        .run(
            &cli_with_parent,
            Some(tpm_device.device.clone()),
            &mut import_output_buf,
        )
        .unwrap();
    let output_json = String::from_utf8(import_output_buf).unwrap();

    let key: JsonTpmKey =
        serde_json::from_str(&output_json).expect("Import command did not output valid JSON");
    assert!(
        key.public.starts_with("data://base64,"),
        "Public part should be a base64 data URI"
    );
    assert!(
        key.private.starts_with("data://base64,"),
        "Private part should be a base64 data URI"
    );
}

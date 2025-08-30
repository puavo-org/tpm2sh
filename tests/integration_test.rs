// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use cli::{
    cli::{Algorithms, Commands, CreatePrimary, Import, Objects},
    pipeline::{CommandIo, Entry as PipelineEntry, Key, Pipeline},
    CliError, Command, TpmDevice, LOG_FORMAT,
};

use std::{
    collections::HashSet,
    io::Cursor,
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

#[fixture]
fn tpm_device() -> TestFixture {
    let _ = LOG_FORMAT.set(cli::cli::LogFormat::Plain);

    let (handle, transport) = cli::mocktpm::mocktpm_start();
    let device = Arc::new(Mutex::new(TpmDevice::new(transport)));

    TestFixture {
        _handle: handle,
        device,
    }
}

fn run_command(
    cmd: &Commands,
    input: &str,
    device: Option<Arc<Mutex<TpmDevice>>>,
) -> Result<String, CliError> {
    let mut input_cursor = Cursor::new(input.as_bytes());
    let mut output_buf = Vec::new();
    let mut io = CommandIo::new(&mut input_cursor, &mut output_buf, false);
    cmd.run(&mut io, device)?;
    io.finalize()?;
    Ok(String::from_utf8(output_buf).unwrap())
}

#[rstest]
fn test_subcommand_algorithms(tpm_device: TestFixture) {
    let algorithms_cmd = Commands::Algorithms(Algorithms { filter: None });
    let output = run_command(&algorithms_cmd, "", Some(tpm_device.device.clone())).unwrap();
    let mut results: Vec<String> = output.lines().map(String::from).collect();
    results.sort();

    let supported_tpm_algs: HashSet<TpmAlgId> = [
        TpmAlgId::Rsa,
        TpmAlgId::Ecc,
        TpmAlgId::Sha256,
        TpmAlgId::Sha384,
        TpmAlgId::Sha512,
    ]
    .into_iter()
    .collect();

    let mut expected: Vec<String> = cli::enumerate_all()
        .filter(|alg| supported_tpm_algs.contains(&alg.object_type))
        .map(|alg| alg.name)
        .collect();
    expected.sort();

    assert_eq!(results, expected);

    let filtered_cmd = Commands::Algorithms(Algorithms {
        filter: Some("rsa:2048".to_string()),
    });
    let filtered_output = run_command(&filtered_cmd, "", Some(tpm_device.device.clone())).unwrap();
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

    run_command(&create_cmd, "", Some(tpm_device.device.clone())).unwrap();
    run_command(&create_cmd, "", Some(tpm_device.device.clone())).unwrap();

    let objects_cmd = Commands::Objects(Objects);
    let output_json = run_command(&objects_cmd, "", Some(tpm_device.device.clone())).unwrap();

    let pipeline: Pipeline = serde_json::from_str(&output_json).unwrap();
    let mut handles: Vec<u32> = pipeline
        .objects
        .iter()
        .filter_map(|obj| {
            if let PipelineEntry::Tpm(tpm) = obj {
                tpm.context
                    .strip_prefix("tpm://0x")
                    .and_then(|hex| u32::from_str_radix(hex, 16).ok())
            } else {
                None
            }
        })
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
    let output_json = run_command(&create_cmd, "", Some(tpm_device.device.clone())).unwrap();
    let pipeline: Pipeline = serde_json::from_str(&output_json).unwrap();
    let parent_obj = pipeline
        .objects
        .into_iter()
        .find_map(|obj| match obj {
            PipelineEntry::Tpm(tpm) => Some(tpm),
            _ => None,
        })
        .expect("TPM2_CreatePrimary failed");
    let key_dir = tempdir().unwrap();
    let key_path = key_dir.path().join("import-key.pem");
    let rsa_key = rsa::RsaPrivateKey::new(&mut rand::thread_rng(), 2048).unwrap();
    let pem_doc = rsa_key.to_pkcs8_pem(Default::default()).unwrap();
    std::fs::write(&key_path, pem_doc.as_bytes()).unwrap();
    let input_pipeline = Pipeline {
        version: 1,
        objects: vec![PipelineEntry::Tpm(parent_obj)],
    };
    let input_json = serde_json::to_string(&input_pipeline).unwrap();
    let import_cmd = Commands::Import(Import {
        key_uri: Some(format!("file://{}", key_path.to_str().unwrap())),
        parent_password: Default::default(),
    });
    let output_json =
        run_command(&import_cmd, &input_json, Some(tpm_device.device.clone())).unwrap();
    let output_pipeline: Pipeline = serde_json::from_str(&output_json).unwrap();
    assert_eq!(
        output_pipeline.objects.len(),
        2,
        "The number of objects must be two"
    );
    let key_count = output_pipeline
        .objects
        .iter()
        .filter(|o| matches!(o, PipelineEntry::Key(_)))
        .count();
    assert_eq!(key_count, 1, "The number of objects must be one");
    assert!(
        matches!(
            output_pipeline.objects.last(),
            Some(PipelineEntry::Key(Key { .. }))
        ),
        "The last object must be the imported key"
    );
}

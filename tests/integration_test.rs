// SPDX-License-Identifier: GPL-3-0-or-later
// Copyright (c) 2025 Opinsys Oy

use cli::{
    cli::{Commands, CreatePrimary, Import},
    schema::{Key, Pipeline, PipelineObject},
    Command, CommandIo, TpmDevice, TpmError, LOG_FORMAT,
};

use std::{
    env,
    io::Cursor,
    os::unix::net::UnixStream,
    process::{Child, Command as ProcessCommand, Stdio},
    sync::{Arc, Mutex},
};

use pkcs8::EncodePrivateKey;
use rstest::{fixture, rstest};
use tempfile::tempdir;

struct TestFixture {
    child: Child,
    socket_path: std::path::PathBuf,
    device: Arc<Mutex<TpmDevice>>,
}

impl Drop for TestFixture {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = std::fs::remove_file(&self.socket_path);
    }
}

#[fixture]
fn tpm_device() -> TestFixture {
    let mock_tpm_path = env!("CARGO_BIN_EXE_mock-tpm");
    let cache_dir = tempdir().unwrap();
    let socket_path = cache_dir.path().join("mock-tpm.sock");
    eprintln!("");
    let child = ProcessCommand::new(mock_tpm_path)
        .arg("--cache-path")
        .arg(cache_dir.path())
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn mock-tpm binary");
    std::thread::sleep(std::time::Duration::from_millis(100));
    let stream = UnixStream::connect(&socket_path).expect("Failed to connect to mock-tpm socket");
    let device = Arc::new(Mutex::new(TpmDevice::new(stream)));
    LOG_FORMAT
        .set(cli::cli::LogFormat::Plain)
        .expect("Failed to set LOG_FORMAT global");
    TestFixture {
        child,
        socket_path,
        device,
    }
}

fn run_command(
    cmd: &Commands,
    input: &str,
    device: Option<Arc<Mutex<TpmDevice>>>,
) -> Result<String, TpmError> {
    let mut input_cursor = Cursor::new(input.as_bytes());
    let mut output_buf = Vec::new();
    let mut io = CommandIo::new(&mut input_cursor, &mut output_buf, false);
    cmd.run(&mut io, device)?;
    io.finalize()?;
    Ok(String::from_utf8(output_buf).unwrap())
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
            PipelineObject::Tpm(tpm) => Some(tpm),
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
        objects: vec![PipelineObject::Tpm(parent_obj)],
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
        .filter(|o| matches!(o, PipelineObject::Key(_)))
        .count();
    assert_eq!(key_count, 1, "The number of objects must be one");
    assert!(
        matches!(
            output_pipeline.objects.last(),
            Some(PipelineObject::Key(Key { .. }))
        ),
        "The last object must be the imported key"
    );
}

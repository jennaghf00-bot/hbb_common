use hbb_common::config::identity::IdentityStore;
use std::{
    fs,
    path::PathBuf,
    process::{Command, Stdio},
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .join(".tmp/identity-process")
}

#[test]
#[ignore]
fn identity_worker() {
    let path = PathBuf::from(std::env::var_os("RUSTDESK_IDENTITY_TEST_PATH").unwrap());
    assert!(path.starts_with(root()));
    let pair = IdentityStore::new(path, b"isolated-test-machine".to_vec())
        .load_or_create()
        .unwrap();
    println!("IDENTITY_PUBLIC={:?}", pair.1);
}

#[test]
fn identity_concurrent_processes_persist_one_identity() {
    let path = root()
        .join(uuid::Uuid::new_v4().to_string())
        .join("RustDesk.toml");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut children = Vec::new();
    for _ in 0..8 {
        children.push(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "identity_worker", "--ignored", "--nocapture"])
                .env("RUSTDESK_IDENTITY_TEST_PATH", &path)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let mut fingerprints = Vec::new();
    for child in children {
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "worker failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        fingerprints.push(
            String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .find(|line| line.starts_with("IDENTITY_PUBLIC="))
                .unwrap()
                .to_owned(),
        );
    }
    assert!(fingerprints.iter().all(|pk| pk == &fingerprints[0]));
    let pair = IdentityStore::new(path, b"isolated-test-machine".to_vec())
        .load_or_create()
        .unwrap();
    assert_eq!(fingerprints[0], format!("IDENTITY_PUBLIC={:?}", pair.1));
}

#[test]
fn identity_primary_write_failure_does_not_return_identity() {
    let dir = root().join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&dir).unwrap();
    // A directory in place of the main file must never be treated as a fresh install.
    let path = dir.join("RustDesk.toml");
    fs::create_dir(&path).unwrap();
    assert!(IdentityStore::new(path, b"isolated-test-machine".to_vec())
        .load_or_create()
        .is_err());
}

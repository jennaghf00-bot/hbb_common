use super::*;
use std::process::Command;

fn test_root() -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .join(".tmp/shared-config-tests");
    fs::create_dir_all(&root).unwrap();
    root.canonicalize().unwrap()
}

#[test]
#[ignore]
fn private_service_identity_worker() {
    let profile = PathBuf::from(std::env::var_os("RUSTDESK_TEST_CONFIG_ROOT").unwrap());
    assert!(profile.starts_with(test_root()));
    assert!(
        Config::file().starts_with(&profile),
        "test config must be isolated before access"
    );
    Config::enable_private_service_identity();
    Config::prepare_private_identity().unwrap();
    let request = provision::ProvisionRequest {
        remote_id: "ZBX-SERVICE-TEST".into(),
        unattended_password: "fixture-unattended-only".into(),
        settings_password: "fixture-settings-only".into(),
        hbbs_address: "127.0.0.1:21116".into(),
        hbbr_address: "127.0.0.1:21117".into(),
        api_base: "http://127.0.0.1:3000".into(),
        server_key: base64::encode(&[7u8; 32], base64::Variant::Original),
        authorization: String::new(),
    };
    Config::apply_private_provision(&request, true).unwrap();
    // A preset from a different GUI/profile must not become the service's actual ID.
    LocalConfig::set_option("private-forced-remote-id".into(), "DISPLAY-ONLY".into());
    assert_eq!(Config::get_id(), request.remote_id);
    assert!(Config::matches_permanent_password_plain(
        &request.unattended_password
    ));
    let (context, persisted) = Config::private_binding_identity().unwrap();
    assert!(persisted);
    println!(
        "SERVICE_RESULT={}",
        serde_json::json!({
            "id": context.actual_id, "generation": context.generation,
            "publicFingerprint": context.public_fingerprint,
        })
    );
}

fn run_worker(profile: &Path) -> serde_json::Value {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "config::service_identity_tests::private_service_identity_worker",
            "--ignored",
            "--nocapture",
        ])
        .env("RUSTDESK_TEST_CONFIG_ROOT", profile)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "service worker failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    serde_json::from_str(
        stdout
            .lines()
            .find_map(|line| line.strip_prefix("SERVICE_RESULT="))
            .unwrap(),
    )
    .unwrap()
}

#[test]
fn service_identity_survives_new_process_and_primary_config_corruption() {
    let profile = test_root().join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&profile).unwrap();
    let first = run_worker(&profile);
    let main = profile.join("RustDesk.toml");
    let second = run_worker(&profile);
    assert_eq!(
        first, second,
        "reopening must not replace the identity or generation"
    );
    fs::write(&main, "truncated = [").unwrap();
    let recovered = run_worker(&profile);
    assert_eq!(
        first, recovered,
        "recovery must restore the exact service identity"
    );
}

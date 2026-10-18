use super::{
    identity::IdentityStore,
    provision::{ProvisionRequest, ProvisionStore},
};
use std::{fs, path::PathBuf};

fn fixture() -> (ProvisionStore, ProvisionRequest) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .join(".tmp/provision-tests")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&root).unwrap();
    let main = root.join("RustDesk.toml");
    IdentityStore::new(main.clone(), b"fixture-machine".to_vec())
        .load_or_create()
        .unwrap();
    let store = ProvisionStore::new(main, b"fixture-machine".to_vec());
    let request = ProvisionRequest {
        remote_id: "ZBX-TEST".into(),
        unattended_password: "fixture-unattended-only".into(),
        settings_password: "fixture-settings-only".into(),
        hbbs_address: "127.0.0.1:21116".into(),
        hbbr_address: "127.0.0.1:21117".into(),
        server_key: sodiumoxide::base64::encode(&[7u8; 32], sodiumoxide::base64::Variant::Original),
        api_base: "http://127.0.0.1:3000".into(),
        authorization: String::new(),
    };
    (store, request)
}

#[test]
fn provision_reapply_is_noop_and_keeps_identity_and_password_salt() {
    let (store, request) = fixture();
    let pair = store.identity().load_or_create().unwrap();
    let first = store.apply(&request, false).unwrap();
    let main = fs::read(store.main_path()).unwrap();
    let options = fs::read(store.options_path()).unwrap();
    let local = fs::read(store.local_path()).unwrap();
    let second = store.apply(&request, false).unwrap();
    assert_eq!(first.generation, second.generation);
    assert!(!second.changed);
    assert_eq!(main, fs::read(store.main_path()).unwrap());
    assert_eq!(options, fs::read(store.options_path()).unwrap());
    assert_eq!(local, fs::read(store.local_path()).unwrap());
    assert_eq!(pair, store.identity().load_or_create().unwrap());
    assert!(store.is_complete().unwrap());
}

#[test]
fn provision_change_requires_existing_settings_authorization() {
    let (store, mut request) = fixture();
    store.apply(&request, false).unwrap();
    request.remote_id = "ZBX-OTHER".into();
    assert_eq!(
        store.apply(&request, false).unwrap_err().to_string(),
        "provision_authorization_required"
    );
    request.authorization = "wrong".into();
    assert!(store.apply(&request, false).is_err());
    request.authorization = request.settings_password.clone();
    assert!(store.apply(&request, false).is_ok());
}

#[test]
fn provision_partial_failure_remains_incomplete_and_retry_keeps_pair() {
    let (store, request) = fixture();
    let pair = store.identity().load_or_create().unwrap();
    fs::write(store.local_path(), "[options]\n").unwrap();
    let mut permissions = fs::metadata(store.local_path()).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(store.local_path(), permissions.clone()).unwrap();
    assert!(store.apply(&request, false).is_err());
    assert!(!store.is_complete().unwrap());
    let partial: toml::Value =
        toml::from_str(&fs::read_to_string(store.main_path()).unwrap()).unwrap();
    assert_eq!(partial["id"].as_str(), Some("ZBX-TEST"));
    permissions.set_readonly(false);
    fs::set_permissions(store.local_path(), permissions).unwrap();
    assert!(store.apply(&request, false).is_ok());
    assert_eq!(pair, store.identity().load_or_create().unwrap());
    assert!(store.is_complete().unwrap());
}

#[test]
fn provision_empty_or_bad_values_never_write_a_completion_marker() {
    let (store, mut request) = fixture();
    request.server_key = "not-a-public-key".into();
    assert!(store.apply(&request, false).is_err());
    assert!(!store.is_complete().unwrap());
}

#[test]
fn provision_does_not_reset_existing_salt_or_unrelated_preferences() {
    let (store, request) = fixture();
    let mut raw: toml::Value =
        toml::from_str(&fs::read_to_string(store.main_path()).unwrap()).unwrap();
    raw.as_table_mut().unwrap().insert(
        "salt".into(),
        toml::Value::String("stable-existing-salt".into()),
    );
    raw.as_table_mut()
        .unwrap()
        .insert("unrelated".into(), toml::Value::Integer(42));
    store.identity().persist(&raw).unwrap();
    store.apply(&request, false).unwrap();
    let applied: toml::Value =
        toml::from_str(&fs::read_to_string(store.main_path()).unwrap()).unwrap();
    assert_eq!(applied["salt"].as_str(), Some("stable-existing-salt"));
    assert_eq!(applied["unrelated"].as_integer(), Some(42));
    let h1 =
        super::compute_permanent_password_h1(&request.unattended_password, "stable-existing-salt");
    assert_eq!(
        super::decode_permanent_password_h1_from_storage(applied["password"].as_str().unwrap()),
        Some(h1)
    );
}

#[test]
fn provision_restart_does_not_replay_already_consumed_installed_payload() {
    let (store, original) = fixture();
    store.apply(&original, true).unwrap();
    let mut changed = original.clone();
    changed.remote_id = "ZBX-CHANGED".into();
    changed.authorization = original.settings_password.clone();
    store.apply(&changed, false).unwrap();
    let reopened = store.apply(&original, true).unwrap();
    assert!(!reopened.changed);
    let main: toml::Value =
        toml::from_str(&fs::read_to_string(store.main_path()).unwrap()).unwrap();
    assert_eq!(main["id"].as_str(), Some("ZBX-CHANGED"));
}

#[test]
fn provision_completion_requires_the_committed_options_not_just_a_marker() {
    let (store, request) = fixture();
    store.apply(&request, false).unwrap();
    fs::write(store.options_path(), "[options]\nkey = 'changed'\n").unwrap();
    assert!(!store.is_complete().unwrap());
    assert!(!store.registration_allowed());
    assert!(store.completed_generation().unwrap().is_none());
}

#[test]
fn provision_completion_rejects_actual_main_id_drift() {
    let (store, request) = fixture();
    store.apply(&request, false).unwrap();
    let mut main: toml::Value =
        toml::from_str(&fs::read_to_string(store.main_path()).unwrap()).unwrap();
    main["id"] = toml::Value::String("WRONG-ACTUAL-ID".into());
    store.identity().persist(&main).unwrap();
    assert!(!store.is_complete().unwrap());
}

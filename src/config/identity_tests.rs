use super::identity::IdentityStore;
use sodiumoxide::crypto::sign;
use std::{fs, path::PathBuf};

fn fixture() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../..")
        .join(".tmp/identity-tests")
        .join(uuid::Uuid::new_v4().to_string());
    fs::create_dir_all(&dir).unwrap();
    dir.join("RustDesk.toml")
}

fn write_existing(path: &std::path::Path) -> (Vec<u8>, Vec<u8>) {
    sodiumoxide::init().unwrap();
    let (pk, sk) = sign::gen_keypair();
    let pair = (sk.0.to_vec(), pk.0.to_vec());
    let mut value = toml::map::Map::new();
    value.insert("id".into(), toml::Value::String("ZBX-TEST".into()));
    value.insert(
        "salt".into(),
        toml::Value::String("keep-existing-salt".into()),
    );
    value.insert("key_pair".into(), toml::Value::try_from(&pair).unwrap());
    value.insert(
        "unrelated".into(),
        toml::Value::String("preserve-me".into()),
    );
    fs::write(path, toml::to_string(&value).unwrap()).unwrap();
    pair
}

#[test]
fn identity_preserves_existing_pair_and_fields() {
    let path = fixture();
    let expected = write_existing(&path);
    let store = IdentityStore::new(path.clone(), b"fixture-machine".to_vec());
    assert_eq!(store.load_or_create().unwrap(), expected);
    assert_eq!(store.load_or_create().unwrap(), expected);
    let raw: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(raw["unrelated"].as_str(), Some("preserve-me"));
    assert_eq!(raw["salt"].as_str(), Some("keep-existing-salt"));
}

#[test]
fn identity_corrupt_primary_without_backup_never_rotates_keys() {
    let path = fixture();
    fs::write(&path, "key_pair = [corrupt").unwrap();
    let store = IdentityStore::new(path.clone(), b"fixture-machine".to_vec());
    assert_eq!(
        store.load_or_create().unwrap_err().to_string(),
        "identity_recovery_required"
    );
    assert_eq!(fs::read_to_string(path).unwrap(), "key_pair = [corrupt");
}

#[test]
fn identity_bound_primary_without_keys_never_generates_replacement() {
    let path = fixture();
    fs::write(&path, "id = 'ZBX-TEST'\npassword = 'old-storage'\n").unwrap();
    let store = IdentityStore::new(path, b"fixture-machine".to_vec());
    assert_eq!(
        store.load_or_create().unwrap_err().to_string(),
        "identity_recovery_required"
    );
}

#[test]
fn identity_recovers_exact_pair_and_password_salt_from_backup() {
    let path = fixture();
    let expected = write_existing(&path);
    let store = IdentityStore::new(path.clone(), b"fixture-machine".to_vec());
    assert_eq!(store.load_or_create().unwrap(), expected);
    fs::write(&path, "truncated = [").unwrap();
    assert_eq!(store.load_or_create().unwrap(), expected);
    let raw: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(raw["id"].as_str(), Some("ZBX-TEST"));
    assert_eq!(raw["salt"].as_str(), Some("keep-existing-salt"));
}

#[test]
fn identity_rejects_backup_from_another_machine() {
    let path = fixture();
    write_existing(&path);
    IdentityStore::new(path.clone(), b"original-machine".to_vec())
        .load_or_create()
        .unwrap();
    fs::write(&path, "truncated = [").unwrap();
    let store = IdentityStore::new(path, b"different-machine".to_vec());
    assert_eq!(
        store.load_or_create().unwrap_err().to_string(),
        "identity_recovery_required"
    );
}

#[test]
fn identity_rejects_silent_key_replacement() {
    let path = fixture();
    write_existing(&path);
    let store = IdentityStore::new(path.clone(), b"fixture-machine".to_vec());
    store.load_or_create().unwrap();
    let replacement = write_existing(&path);
    assert_eq!(
        store.load_or_create().unwrap_err().to_string(),
        "identity_conflict"
    );
    let raw: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(raw["key_pair"], toml::Value::try_from(replacement).unwrap());
}

#[test]
fn identity_rejects_malformed_key_pair_even_with_correct_lengths() {
    let path = fixture();
    write_existing(&path);
    let mut raw: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    raw["key_pair"] = toml::Value::try_from((vec![1u8; 64], vec![2u8; 32])).unwrap();
    fs::write(&path, toml::to_string(&raw).unwrap()).unwrap();
    assert_eq!(
        IdentityStore::new(path, b"fixture-machine".to_vec())
            .load_or_create()
            .unwrap_err()
            .to_string(),
        "identity_recovery_required"
    );
}

#[test]
fn identity_not_exposed_if_backup_cannot_be_persisted() {
    let path = fixture();
    let store = IdentityStore::new(path.clone(), b"fixture-machine".to_vec());
    fs::create_dir_all(store.backup_path()).unwrap();
    assert!(store.load_or_create().is_err());
}

#[test]
fn identity_persist_updates_recovery_snapshot_without_changing_keys() {
    let path = fixture();
    let expected = write_existing(&path);
    let store = IdentityStore::new(path.clone(), b"fixture-machine".to_vec());
    store.load_or_create().unwrap();
    let mut raw: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    raw.as_table_mut().unwrap().insert(
        "password".into(),
        toml::Value::String("new-hashed-storage".into()),
    );
    store.persist(&raw).unwrap();
    fs::write(&path, "truncated = [").unwrap();
    assert_eq!(store.load_or_create().unwrap(), expected);
    let recovered: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(recovered["password"].as_str(), Some("new-hashed-storage"));
}

#[test]
fn identity_partial_update_preserves_unknown_fields() {
    let path = fixture();
    write_existing(&path);
    let store = IdentityStore::new(path.clone(), b"fixture-machine".to_vec());
    let pair = store.load_or_create().unwrap();
    let mut update = toml::map::Map::new();
    update.insert("key_pair".into(), toml::Value::try_from(pair).unwrap());
    update.insert("password".into(), toml::Value::String("updated".into()));
    store.persist(&toml::Value::Table(update)).unwrap();
    let raw: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(
        raw.get("unrelated").and_then(toml::Value::as_str),
        Some("preserve-me")
    );
}

#[test]
fn identity_encrypted_update_removes_stale_plaintext_id() {
    let path = fixture();
    write_existing(&path);
    let store = IdentityStore::new(path.clone(), b"fixture-machine".to_vec());
    let pair = store.load_or_create().unwrap();
    let mut update = toml::map::Map::new();
    update.insert("key_pair".into(), toml::Value::try_from(pair).unwrap());
    update.insert(
        "enc_id".into(),
        toml::Value::String("encrypted-fixture".into()),
    );
    store.persist(&toml::Value::Table(update)).unwrap();
    let raw: toml::Value = toml::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert!(raw.get("id").is_none());
}

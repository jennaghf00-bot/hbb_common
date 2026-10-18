use super::{
    compute_permanent_password_h1, encode_permanent_password_storage_from_h1,
    identity::{self, IdentityStore},
    Config,
};
use crate::ResultType;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{fs, io, path::PathBuf};

// No Debug: these inputs contain credentials and must never enter IPC diagnostics.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProvisionRequest {
    pub remote_id: String,
    pub unattended_password: String,
    #[serde(default)]
    pub settings_password: String,
    pub hbbs_address: String,
    #[serde(default)]
    pub hbbr_address: String,
    pub server_key: String,
    #[serde(default)]
    pub api_base: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authorization: String,
}

impl std::fmt::Debug for ProvisionRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ProvisionRequest(<redacted>)")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ProvisionOutcome {
    pub generation: String,
    pub changed: bool,
}

#[derive(Serialize, Deserialize)]
struct Generation {
    version: u32,
    generation: String,
    request_hash: Vec<u8>,
    complete: bool,
    remote_id: String,
    #[serde(default)]
    installed_hash: Vec<u8>,
    #[serde(default)]
    committed_hash: Vec<u8>,
}

pub struct ProvisionStore {
    main: PathBuf,
    machine: Vec<u8>,
}

impl ProvisionStore {
    pub fn new(main: PathBuf, machine: Vec<u8>) -> Self {
        Self { main, machine }
    }
    pub fn identity(&self) -> IdentityStore {
        IdentityStore::new(self.main.clone(), self.machine.clone())
    }
    pub fn main_path(&self) -> PathBuf {
        self.main.clone()
    }
    fn sibling(&self, suffix: &str) -> PathBuf {
        let stem = self.main.file_stem().unwrap_or_default().to_string_lossy();
        self.main.with_file_name(format!("{stem}{suffix}"))
    }
    pub fn options_path(&self) -> PathBuf {
        self.sibling("2.toml")
    }
    pub fn local_path(&self) -> PathBuf {
        self.sibling("_local.toml")
    }
    fn marker_path(&self) -> PathBuf {
        self.sibling(".private-binding")
    }

    fn marker(&self) -> ResultType<Option<Generation>> {
        match fs::read_to_string(self.marker_path()) {
            Ok(content) => {
                let marker: Generation = toml::from_str(&content)
                    .map_err(|_| anyhow::anyhow!("provision_recovery_required"))?;
                anyhow::ensure!(marker.version == 1, "provision_version_unsupported");
                Ok(Some(marker))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(_) => anyhow::bail!("provision_read_failed"),
        }
    }

    pub fn is_complete(&self) -> ResultType<bool> {
        match self.marker()? {
            Some(marker) if marker.complete => Ok(marker.committed_hash == self.current_hash()?),
            _ => Ok(false),
        }
    }

    fn current_hash(&self) -> ResultType<Vec<u8>> {
        Ok(configuration_hash(
            &read_table(self.main_path())?,
            &read_table(self.options_path())?,
            &read_table(self.local_path())?,
            &self.machine,
        ))
    }

    pub fn registration_allowed(&self) -> bool {
        // Legacy installations have no generation marker. A started transaction must finish.
        self.marker()
            .and_then(|m| {
                if m.is_some() {
                    self.is_complete()
                } else {
                    Ok(true)
                }
            })
            .unwrap_or(false)
    }

    pub fn completed_generation(&self) -> ResultType<Option<(String, String)>> {
        Ok(self
            .marker()?
            .filter(|m| {
                m.complete
                    && self
                        .current_hash()
                        .map(|hash| hash == m.committed_hash)
                        .unwrap_or(false)
            })
            .map(|m| (m.generation, m.remote_id)))
    }

    pub fn apply(
        &self,
        request: &ProvisionRequest,
        installed_admin: bool,
    ) -> ResultType<ProvisionOutcome> {
        validate(request)?;
        let identity = self.identity();
        let _guard = identity.lock()?;
        let (mut main, _) = identity.load_locked()?;
        let mut options = read_table(self.options_path())?;
        let mut local = read_table(self.local_path())?;
        let mut normalized = request.clone();
        normalized.authorization.clear();
        let request_hash = Sha256::digest(serde_json::to_vec(&normalized)?).to_vec();
        let previous = self.marker()?;
        let matching = matches_config(&main, &options, &local, request, &self.machine);
        if let Some(marker) = &previous {
            if installed_admin && marker.complete && marker.installed_hash == request_hash {
                anyhow::ensure!(
                    marker.committed_hash
                        == configuration_hash(&main, &options, &local, &self.machine),
                    "provision_recovery_required"
                );
                return Ok(ProvisionOutcome {
                    generation: marker.generation.clone(),
                    changed: false,
                });
            }
            if marker.complete && marker.request_hash == request_hash && matching {
                return Ok(ProvisionOutcome {
                    generation: marker.generation.clone(),
                    changed: false,
                });
            }
        }
        let continuing = previous
            .as_ref()
            .map(|m| !m.complete && m.request_hash == request_hash)
            .unwrap_or(false);
        let existing_id = option(&local, "private-forced-remote-id");
        let owned =
            !existing_id.is_empty() || previous.as_ref().map(|m| m.complete).unwrap_or(false);
        if owned && !matching && !continuing && !installed_admin {
            let settings = option(&local, "private-settings-password");
            anyhow::ensure!(
                !settings.is_empty()
                    && sodiumoxide::utils::memcmp(
                        settings.as_bytes(),
                        request.authorization.as_bytes()
                    ),
                "provision_authorization_required"
            );
        }
        let generation = if continuing {
            previous
                .as_ref()
                .map(|m| m.generation.clone())
                .unwrap_or_default()
        } else {
            uuid::Uuid::new_v4().to_string()
        };
        let installed_hash = if installed_admin {
            request_hash.clone()
        } else {
            previous
                .as_ref()
                .map(|m| m.installed_hash.clone())
                .unwrap_or_default()
        };
        let mut marker = Generation {
            version: 1,
            generation: generation.clone(),
            request_hash,
            complete: false,
            remote_id: request.remote_id.clone(),
            installed_hash,
            committed_hash: Vec::new(),
        };
        identity::save(&self.marker_path(), &marker)?;

        let salt = main
            .get("salt")
            .and_then(toml::Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| Config::get_auto_password(32));
        let fields = main
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("provision_config_invalid"))?;
        fields.insert("id".into(), toml::Value::String(request.remote_id.clone()));
        fields.insert("enc_id".into(), toml::Value::String(String::new()));
        fields.insert("salt".into(), toml::Value::String(salt.clone()));
        fields.insert(
            "password".into(),
            toml::Value::String(encode_permanent_password_storage_from_h1(
                &compute_permanent_password_h1(&request.unattended_password, &salt),
            )),
        );
        fields.insert("key_confirmed".into(), toml::Value::Boolean(false));
        fields.insert(
            "keys_confirmed".into(),
            toml::Value::Table(Default::default()),
        );
        for (key, value) in desired_options(request) {
            set_option(&mut options, key, value)?;
        }
        set_option(&mut local, "private-forced-remote-id", &request.remote_id)?;
        set_option(
            &mut local,
            "private-settings-password",
            &request.settings_password,
        )?;
        set_option(&mut local, "private-client-mode", "controlled")?;
        identity.persist_locked(&main)?;
        identity::save(&self.options_path(), &options)?;
        identity::save(&self.local_path(), &local)?;
        marker.complete = true;
        marker.committed_hash = configuration_hash(&main, &options, &local, &self.machine);
        identity::save(&self.marker_path(), &marker)?;
        Ok(ProvisionOutcome {
            generation,
            changed: true,
        })
    }
}

pub fn validate(request: &ProvisionRequest) -> ResultType<()> {
    anyhow::ensure!(
        crate::is_valid_custom_id(&request.remote_id),
        "provision_invalid_id"
    );
    anyhow::ensure!(
        !request.unattended_password.is_empty()
            && request.unattended_password.chars().count() <= super::ENCRYPT_MAX_LEN,
        "provision_invalid_password"
    );
    anyhow::ensure!(
        request.settings_password.chars().count() <= super::ENCRYPT_MAX_LEN,
        "provision_invalid_settings_password"
    );
    for address in [&request.hbbs_address, &request.hbbr_address] {
        anyhow::ensure!(
            !address.is_empty()
                && !address.chars().any(char::is_whitespace)
                && !address.contains('/'),
            "provision_invalid_address"
        );
        let (_, port) = address
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("provision_invalid_address"))?;
        anyhow::ensure!(
            port.parse::<u16>().map(|p| p > 0).unwrap_or(false),
            "provision_invalid_address"
        );
    }
    let key = sodiumoxide::base64::decode(
        request.server_key.as_bytes(),
        sodiumoxide::base64::Variant::Original,
    )
    .map_err(|_| anyhow::anyhow!("provision_invalid_server_key"))?;
    anyhow::ensure!(key.len() == 32, "provision_invalid_server_key");
    Ok(())
}

fn read_table(path: PathBuf) -> ResultType<toml::Value> {
    match fs::read_to_string(path) {
        Ok(content) => {
            toml::from_str(&content).map_err(|_| anyhow::anyhow!("provision_config_invalid"))
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(toml::Value::Table(Default::default())),
        Err(_) => anyhow::bail!("provision_read_failed"),
    }
}

fn option<'a>(raw: &'a toml::Value, key: &str) -> &'a str {
    raw.get("options")
        .and_then(|v| v.get(key))
        .and_then(toml::Value::as_str)
        .unwrap_or("")
}

fn set_option(raw: &mut toml::Value, key: &str, value: &str) -> ResultType<()> {
    let table = raw
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("provision_config_invalid"))?;
    let options = table
        .entry("options".to_owned())
        .or_insert_with(|| toml::Value::Table(Default::default()));
    options
        .as_table_mut()
        .ok_or_else(|| anyhow::anyhow!("provision_config_invalid"))?
        .insert(key.into(), toml::Value::String(value.into()));
    Ok(())
}

pub(super) fn desired_options(request: &ProvisionRequest) -> Vec<(&str, &str)> {
    vec![
        ("private-management-api", &request.api_base),
        ("custom-rendezvous-server", &request.hbbs_address),
        ("relay-server", &request.hbbr_address),
        ("key", &request.server_key),
        ("enable-privacy-mode", "N"),
        ("approve-mode", "password"),
        ("stop-service", "N"),
        ("verification-method", "use-permanent-password"),
    ]
}

fn matches_config(
    main: &toml::Value,
    options: &toml::Value,
    local: &toml::Value,
    request: &ProvisionRequest,
    machine: &[u8],
) -> bool {
    let salt = main.get("salt").and_then(toml::Value::as_str).unwrap_or("");
    let storage = main
        .get("password")
        .and_then(toml::Value::as_str)
        .unwrap_or("");
    raw_id(main, machine).as_deref() == Some(request.remote_id.as_str())
        && !salt.is_empty()
        && storage
            == encode_permanent_password_storage_from_h1(&compute_permanent_password_h1(
                &request.unattended_password,
                salt,
            ))
        && option(local, "private-forced-remote-id") == request.remote_id
        && option(local, "private-settings-password") == request.settings_password
        && desired_options(request)
            .iter()
            .all(|(key, value)| option(options, key) == *value)
}

fn configuration_hash(
    main: &toml::Value,
    options: &toml::Value,
    local: &toml::Value,
    machine: &[u8],
) -> Vec<u8> {
    let mut values: Vec<String> = ["password", "salt", "key_pair"]
        .iter()
        .map(|key| {
            main.get(key)
                .map(toml::Value::to_string)
                .unwrap_or_default()
        })
        .collect();
    for key in [
        "private-management-api",
        "custom-rendezvous-server",
        "relay-server",
        "key",
        "approve-mode",
        "verification-method",
    ] {
        values.push(option(options, key).to_owned());
    }
    values.push(option(local, "private-settings-password").to_owned());
    values.push(raw_id(main, machine).unwrap_or_default());
    // Excludes UI display presets and runtime stop-service flags: neither is device identity.
    let mut hash = Sha256::new();
    for value in values {
        hash.update((value.len() as u64).to_le_bytes());
        hash.update(value.as_bytes());
    }
    hash.finalize().to_vec()
}

fn raw_id(main: &toml::Value, machine: &[u8]) -> Option<String> {
    use sodiumoxide::{base64, crypto::secretbox};
    let encrypted = main
        .get("enc_id")
        .and_then(toml::Value::as_str)
        .unwrap_or("");
    if encrypted.is_empty() {
        return main
            .get("id")
            .and_then(toml::Value::as_str)
            .map(str::to_owned);
    }
    let data = base64::decode(
        encrypted.strip_prefix("00")?.as_bytes(),
        base64::Variant::Original,
    )
    .ok()?;
    // Same format as password_security::symmetric_crypt, but supplied material avoids lock reentry.
    let pair: (Vec<u8>, Vec<u8>) = main.get("key_pair")?.clone().try_into().ok()?;
    for mut material in [machine.to_vec(), pair.1] {
        material.resize(secretbox::KEYBYTES, 0);
        let key = secretbox::Key::from_slice(&material)?;
        if let Ok(plain) =
            secretbox::open(&data, &secretbox::Nonce([0; secretbox::NONCEBYTES]), &key)
        {
            return String::from_utf8(plain).ok();
        }
    }
    None
}

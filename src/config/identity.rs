//! Raw identity persistence. Never call Config/KEY_PAIR/password migration under its file lock.
use crate::ResultType;
use serde_derive::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sodiumoxide::crypto::sign;
use std::{
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

type KeyPair = (Vec<u8>, Vec<u8>);

pub struct IdentityStore {
    path: PathBuf,
    machine: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Backup {
    version: u32,
    machine: Vec<u8>,
    config: String,
}

#[derive(Serialize, Deserialize)]
struct SealedBackup {
    version: u32,
    data: Vec<u8>,
}

impl IdentityStore {
    pub fn new(path: PathBuf, machine: Vec<u8>) -> Self {
        Self { path, machine }
    }

    pub fn backup_path(&self) -> PathBuf {
        self.path.with_extension("identity-backup")
    }

    pub fn load_or_create(&self) -> ResultType<KeyPair> {
        let _guard = self.lock()?;
        self.load_locked().map(|(_, pair)| pair)
    }

    pub fn persist(&self, raw: &toml::Value) -> ResultType<()> {
        let _guard = self.lock()?;
        self.persist_locked(raw)
    }

    pub(super) fn persist_locked(&self, raw: &toml::Value) -> ResultType<()> {
        let (mut existing, current) = self.load_locked()?;
        if key_pair(raw).as_ref() != Some(&current) {
            anyhow::bail!("identity_conflict");
        }
        // Recover the newest completed main configuration, including its password salt.
        let fields = raw
            .as_table()
            .ok_or_else(|| anyhow::anyhow!("identity_config_invalid"))?;
        existing
            .as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("identity_config_invalid"))?
            .extend(fields.clone());
        if raw
            .get("enc_id")
            .and_then(toml::Value::as_str)
            .map(|id| !id.is_empty())
            .unwrap_or(false)
            && raw.get("id").is_none()
        {
            if let Some(table) = existing.as_table_mut() {
                table.remove("id");
            }
        }
        self.save_backup(&existing)?;
        save(&self.path, &existing)
    }

    pub(super) fn lock(&self) -> ResultType<FileLock> {
        if self.machine.is_empty() {
            anyhow::bail!("identity_machine_unavailable");
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("identity_path_invalid"))?;
        fs::create_dir_all(parent).map_err(|_| anyhow::anyhow!("identity_persist_failed"))?;
        FileLock::acquire(&self.path.with_extension("identity-lock"))
    }

    pub(super) fn load_locked(&self) -> ResultType<(toml::Value, KeyPair)> {
        let primary = read_raw(&self.path);
        let backup = self.read_backup()?;
        if let Ok(Some(raw)) = &primary {
            if let Some(pair) = key_pair(raw) {
                if let Some(saved) = &backup {
                    if key_pair(saved).as_ref() != Some(&pair) {
                        anyhow::bail!("identity_conflict");
                    }
                } else {
                    self.save_backup(raw)?;
                }
                return Ok((raw.clone(), pair));
            }
        }
        if let Some(raw) = backup {
            let pair =
                key_pair(&raw).ok_or_else(|| anyhow::anyhow!("identity_recovery_required"))?;
            save(&self.path, &raw)?;
            return Ok((raw, pair));
        }
        // A pre-existing ID/password or malformed file is not a new installation.
        let mut raw = match primary {
            Ok(None) => toml::Value::Table(Default::default()),
            Ok(Some(raw)) if is_uninitialized(&raw) => raw,
            _ => anyhow::bail!("identity_recovery_required"),
        };
        sodiumoxide::init().map_err(|_| anyhow::anyhow!("identity_crypto_unavailable"))?;
        let (pk, sk) = sign::gen_keypair();
        let pair = (sk.0.to_vec(), pk.0.to_vec());
        raw.as_table_mut()
            .ok_or_else(|| anyhow::anyhow!("identity_recovery_required"))?
            .insert("key_pair".into(), toml::Value::try_from(&pair)?);
        self.save_backup(&raw)?;
        save(&self.path, &raw)?;
        Ok((raw, pair))
    }

    fn read_backup(&self) -> ResultType<Option<toml::Value>> {
        let content = match fs::read_to_string(self.backup_path()) {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(_) => anyhow::bail!("identity_recovery_required"),
        };
        let decode = || -> ResultType<toml::Value> {
            let sealed: SealedBackup = toml::from_str(&content)?;
            anyhow::ensure!(sealed.version == 1, "backup_version");
            let bytes = unseal(&sealed.data)?;
            let backup: Backup = serde_json::from_slice(&bytes)?;
            anyhow::ensure!(backup.version == 1, "backup_version");
            anyhow::ensure!(
                backup.machine == Sha256::digest(&self.machine).to_vec(),
                "backup_machine"
            );
            let raw: toml::Value = toml::from_str(&backup.config)?;
            anyhow::ensure!(key_pair(&raw).is_some(), "backup_identity");
            Ok(raw)
        };
        decode()
            .map(Some)
            .map_err(|_| anyhow::anyhow!("identity_recovery_required"))
    }

    fn save_backup(&self, raw: &toml::Value) -> ResultType<()> {
        let backup = Backup {
            version: 1,
            machine: Sha256::digest(&self.machine).to_vec(),
            config: toml::to_string(raw)?,
        };
        let sealed = SealedBackup {
            version: 1,
            data: seal(&serde_json::to_vec(&backup)?)?,
        };
        save(&self.backup_path(), &sealed)
    }
}

fn read_raw(path: &Path) -> ResultType<Option<toml::Value>> {
    match fs::read_to_string(path) {
        Ok(content) => toml::from_str(&content)
            .map(Some)
            .map_err(|_| anyhow::anyhow!("identity_recovery_required")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => anyhow::bail!("identity_read_failed"),
    }
}

fn is_uninitialized(raw: &toml::Value) -> bool {
    ["id", "enc_id", "password", "salt"]
        .iter()
        .all(|k| raw.get(k).map(|v| v.as_str() == Some("")).unwrap_or(true))
        && raw
            .get("key_pair")
            .map(|v| {
                v.clone()
                    .try_into::<KeyPair>()
                    .map(|p| p.0.is_empty() && p.1.is_empty())
                    .unwrap_or(false)
            })
            .unwrap_or(true)
}

fn key_pair(raw: &toml::Value) -> Option<KeyPair> {
    let pair: KeyPair = raw.get("key_pair")?.clone().try_into().ok()?;
    let sk = sign::SecretKey::from_slice(&pair.0)?;
    let pk = sign::PublicKey::from_slice(&pair.1)?;
    sodiumoxide::init().ok()?;
    let proof = sign::sign_detached(b"RustDesk identity validation v1", &sk);
    sign::verify_detached(&proof, b"RustDesk identity validation v1", &pk).then_some(pair)
}

pub(super) fn save(path: &Path, value: &impl serde::Serialize) -> ResultType<()> {
    // confy uses a same-directory temporary file and rename. Add an explicit durable flush.
    super::store_path(path.to_path_buf(), value)
        .map_err(|_| anyhow::anyhow!("identity_persist_failed"))?;
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.sync_all())
        .map_err(|_| anyhow::anyhow!("identity_persist_failed"))?;
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|file| file.sync_all())
            .map_err(|_| anyhow::anyhow!("identity_persist_failed"))?;
    }
    Ok(())
}

pub(super) struct FileLock(File);

impl FileLock {
    fn acquire(path: &Path) -> ResultType<Self> {
        let start = Instant::now();
        loop {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            #[cfg(windows)]
            {
                use std::os::windows::fs::OpenOptionsExt;
                options.share_mode(0);
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(path) {
                Ok(file) => {
                    #[cfg(unix)]
                    {
                        use std::os::unix::io::AsRawFd;
                        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) }
                            != 0
                        {
                            if start.elapsed() >= Duration::from_secs(10) {
                                anyhow::bail!("identity_lock_timeout");
                            }
                            std::thread::sleep(Duration::from_millis(20));
                            continue;
                        }
                    }
                    return Ok(Self(file));
                }
                #[cfg(windows)]
                Err(e) if e.raw_os_error() == Some(32) => {}
                Err(_) => anyhow::bail!("identity_lock_failed"),
            }
            if start.elapsed() >= Duration::from_secs(10) {
                anyhow::bail!("identity_lock_timeout");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
            }
        }
        // The open handle is the lock on Windows. Never unlink the shared pathname.
        let _ = &self.0;
    }
}

#[cfg(windows)]
fn protect(bytes: &[u8], encrypt: bool) -> ResultType<Vec<u8>> {
    use std::ptr::{null, null_mut};
    use winapi::um::{
        dpapi::{CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN},
        winbase::LocalFree,
        wincrypt::DATA_BLOB,
    };
    let mut input = DATA_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr() as *mut u8,
    };
    let mut output = DATA_BLOB {
        cbData: 0,
        pbData: null_mut(),
    };
    let ok = unsafe {
        if encrypt {
            CryptProtectData(
                &mut input,
                null(),
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        } else {
            CryptUnprotectData(
                &mut input,
                null_mut(),
                null_mut(),
                null_mut(),
                null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut output,
            )
        }
    };
    if ok == 0 {
        anyhow::bail!("identity_backup_protection_failed");
    }
    let result =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData as *mut _);
    }
    Ok(result)
}

fn seal(bytes: &[u8]) -> ResultType<Vec<u8>> {
    #[cfg(windows)]
    return protect(bytes, true);
    #[cfg(not(windows))]
    Ok(bytes.to_vec())
}

fn unseal(bytes: &[u8]) -> ResultType<Vec<u8>> {
    #[cfg(windows)]
    return protect(bytes, false);
    #[cfg(not(windows))]
    Ok(bytes.to_vec())
}

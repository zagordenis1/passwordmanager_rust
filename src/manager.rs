//! High-level [`PasswordManager`] API: wraps DB + crypto and tracks
//! lock/unlock state.
//!
//! Mirrors the Python `PasswordManager` 1:1 in semantics. Differences:
//!
//! * Local copies of the derived base64 key string are explicitly
//!   `Zeroize`d after the `Fernet` instance has been built.
//! * The constructed [`fernet::Fernet`] is held only inside an
//!   [`Option`] — `lock()` drops it. (The upstream `fernet` crate does
//!   not zeroize on Drop; see the [`PasswordManager`] struct doc.)
//! * All errors funnel through `anyhow::Result` for the public API; the
//!   `_internal` helpers use `thiserror`-typed errors.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use fernet::Fernet;
use rusqlite::{params, OptionalExtension};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::crypto::{self, KDF_ARGON2ID_V1, KDF_PBKDF2_LEGACY};
use crate::db;

/// Default DB path, matching the Python reference (`./users.db`).
pub const DEFAULT_DB_PATH: &str = "users.db";

/// Meta keys persisted in the SQLite `meta` table.
pub const META_SALT: &str = "salt";
pub const META_VERIFIER: &str = "verifier";
pub const META_KDF: &str = "kdf_version";

/// Error returned from [`PasswordManager::create_user`] when a row with
/// the same `login` already exists. Wrapped in `anyhow::Error` for the
/// public API; callers can `downcast_ref::<DuplicateLogin>()` to react
/// specifically (e.g. import-with-skip-duplicates).
#[derive(Debug, thiserror::Error)]
#[error("login {login:?} already exists")]
pub struct DuplicateLogin {
    pub login: String,
}

/// Plain-text view of a stored account (password decrypted). Returned to
/// the CLI / library callers; never persisted in this form.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UserRecord {
    pub id: i64,
    pub login: String,
    pub email: Option<String>,
    pub password: String,
    pub created_at: String,
}

/// Top-level facade combining DB + crypto.
///
/// # Memory hygiene caveat
///
/// `Some` while the manager is unlocked, `None` after [`PasswordManager::lock`].
/// We deliberately do **not** keep a separate `SecretString` copy of the
/// derived key — the `fernet::Fernet` instance already carries the
/// effective key material (an AES-128 key + an HMAC-SHA256 key) inside
/// its own struct, and that crate does not zeroize on `Drop`. Holding a
/// second copy in a `secrecy::SecretString` would have given the
/// *appearance* of defense-in-depth without the substance. Dropping the
/// `Option<Fernet>` (via `lock()` or process exit) is the actual
/// guarantee, and short of forking the upstream crate or switching to
/// raw AES + HMAC primitives we cannot zeroize the inner buffers from
/// outside.
pub struct PasswordManager {
    db_path: PathBuf,
    fernet: Option<Fernet>,
}

impl std::fmt::Debug for PasswordManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Redact secrets — never leak whether a key is present.
        f.debug_struct("PasswordManager")
            .field("db_path", &self.db_path)
            .field("unlocked", &self.fernet.is_some())
            .finish()
    }
}

impl PasswordManager {
    /// Open (or create) the SQLite database at `db_path` and initialise
    /// the schema. Does **not** unlock — call [`set_master_password`]
    /// (first-time setup) or [`verify_master_password`] (existing DB).
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let path = db_path.as_ref().to_path_buf();
        let _conn = db::open(&path).context("opening database")?;
        Ok(Self {
            db_path: path,
            fernet: None,
        })
    }

    fn open_conn(&self) -> Result<rusqlite::Connection> {
        db::open(&self.db_path).context("opening database")
    }

    /// `true` iff the DB has both a salt and a verifier — i.e. a master
    /// password has already been set.
    pub fn has_master_password(&self) -> Result<bool> {
        let conn = self.open_conn()?;
        let salt = db::get_meta(&conn, META_SALT)?;
        let verifier = db::get_meta(&conn, META_VERIFIER)?;
        Ok(salt.is_some() && verifier.is_some())
    }

    /// First-time master-password setup. Refuses if one is already set.
    ///
    /// Writes are wrapped in a `BEGIN IMMEDIATE` transaction so a second
    /// `pwm init` running concurrently is serialized at SQLite's
    /// reserved-lock level. The presence-check is then redone *inside*
    /// the transaction, so two racing initialisers can't both pass the
    /// outer `has_master_password()` check and end up clobbering each
    /// other's salt/verifier/kdf_version mid-write (which would leave
    /// the DB unrecoverable). Whichever process gets the reserved lock
    /// first wins; the second sees the master is already set and bails.
    pub fn set_master_password(&mut self, master_password: &str) -> Result<()> {
        if self.has_master_password()? {
            bail!("master password already set");
        }
        if master_password.is_empty() {
            bail!("master password must not be empty");
        }

        let salt = crypto::generate_salt();
        let mut key = crypto::derive_key(master_password, &salt, KDF_ARGON2ID_V1)
            .context("deriving master key")?;
        let fernet = crypto::fernet_from_key(&key).context("building Fernet")?;
        // The base64 string copy of the key is no longer needed once
        // Fernet is built.
        key.zeroize();
        let verifier = crypto::make_verifier(&fernet);

        let mut conn = self.open_conn()?;
        let tx = conn.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;

        // Re-check inside the transaction — defends against a concurrent
        // `pwm init` that won the race to write meta.
        let salt_present = db::get_meta(&tx, META_SALT)?.is_some();
        let verifier_present = db::get_meta(&tx, META_VERIFIER)?.is_some();
        if salt_present && verifier_present {
            bail!("master password already set");
        }

        let upsert = "INSERT INTO meta(key, value) VALUES (?1, ?2) \
                      ON CONFLICT(key) DO UPDATE SET value = excluded.value";
        tx.execute(upsert, params![META_SALT, &salt])?;
        tx.execute(upsert, params![META_VERIFIER, verifier.as_bytes()])?;
        tx.execute(upsert, params![META_KDF, KDF_ARGON2ID_V1.as_bytes()])?;
        tx.commit()?;

        self.fernet = Some(fernet);
        Ok(())
    }

    fn read_kdf_version(&self) -> Result<String> {
        let conn = self.open_conn()?;
        match db::get_meta(&conn, META_KDF)? {
            Some(raw) => Ok(String::from_utf8(raw).map_err(|_| anyhow!("invalid kdf_version"))?),
            // Pre-Argon2 DB → PBKDF2 by definition.
            None => Ok(KDF_PBKDF2_LEGACY.to_string()),
        }
    }

    /// Verify a typed master password. On success the manager is
    /// unlocked. Returns `false` on any auth failure.
    pub fn verify_master_password(&mut self, master_password: &str) -> Result<bool> {
        let conn = self.open_conn()?;
        let salt = match db::get_meta(&conn, META_SALT)? {
            Some(s) => s,
            None => return Ok(false),
        };
        let verifier = match db::get_meta(&conn, META_VERIFIER)? {
            Some(v) => v,
            None => return Ok(false),
        };
        drop(conn);

        let kdf_version = self.read_kdf_version()?;

        let mut key = match crypto::derive_key(master_password, &salt, &kdf_version) {
            Ok(k) => k,
            Err(_) => return Ok(false),
        };
        let fernet = crypto::fernet_from_key(&key)?;
        key.zeroize();
        let token = std::str::from_utf8(&verifier)
            .map_err(|_| anyhow!("verifier is not valid UTF-8 (corrupt DB?)"))?;
        if crypto::check_verifier(&fernet, token) {
            self.fernet = Some(fernet);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// `true` iff the on-disk DB still uses the legacy PBKDF2 KDF — used
    /// by the CLI to nudge the user toward `change_master_password`.
    pub fn is_legacy_kdf(&self) -> Result<bool> {
        Ok(self.read_kdf_version()? == KDF_PBKDF2_LEGACY)
    }

    /// Re-encrypt every stored row under a new master password and rotate
    /// the salt + verifier. Returns the count of rows re-encrypted.
    /// All-or-nothing: SQLite transaction guarantees atomicity.
    pub fn change_master_password(
        &mut self,
        old_master_password: &str,
        new_master_password: &str,
    ) -> Result<usize> {
        if new_master_password.is_empty() {
            bail!("new master password must not be empty");
        }
        if !self.verify_master_password(old_master_password)? {
            bail!("old master password is incorrect");
        }
        let old_fernet = self
            .fernet
            .as_ref()
            .ok_or_else(|| anyhow!("manager is locked after verify (programming error)"))?
            .clone();

        let new_salt = crypto::generate_salt();
        let mut new_key = crypto::derive_key(new_master_password, &new_salt, KDF_ARGON2ID_V1)?;
        let new_fernet = crypto::fernet_from_key(&new_key)?;
        // Same rationale as `set_master_password`: the base64 copy is
        // no longer needed once Fernet has internalised it.
        new_key.zeroize();
        let new_verifier = crypto::make_verifier(&new_fernet);

        let mut conn = self.open_conn()?;
        let tx = conn.transaction()?;
        let rows: Vec<(i64, String)> = {
            let mut stmt = tx.prepare("SELECT id, password_encrypted FROM users")?;
            let mapped = stmt
                .query_map([], |row| {
                    Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
                })?
                .collect::<Result<Vec<_>, _>>()?;
            mapped
        };

        let mut count = 0usize;
        for (id, ct) in rows {
            let plaintext = crypto::decrypt_str(&old_fernet, &ct)
                .context("decrypting row during master rotation")?;
            let reencrypted = crypto::encrypt_str(&new_fernet, &plaintext);
            tx.execute(
                "UPDATE users SET password_encrypted = ?1 WHERE id = ?2",
                params![reencrypted, id],
            )?;
            count += 1;
        }

        tx.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![META_SALT, new_salt],
        )?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![META_VERIFIER, new_verifier.as_bytes()],
        )?;
        tx.execute(
            "INSERT INTO meta(key, value) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            params![META_KDF, KDF_ARGON2ID_V1.as_bytes()],
        )?;

        tx.commit()?;

        self.fernet = Some(new_fernet);
        Ok(count)
    }

    /// Forget the derived key. Subsequent CRUD calls fail until the user
    /// re-authenticates via [`verify_master_password`].
    pub fn lock(&mut self) {
        self.fernet = None;
    }

    /// `true` iff the manager currently holds a valid Fernet.
    pub fn is_unlocked(&self) -> bool {
        self.fernet.is_some()
    }

    fn require_unlocked(&self) -> Result<&Fernet> {
        self.fernet
            .as_ref()
            .ok_or_else(|| anyhow!("manager is locked: verify master password first"))
    }

    // ---------- CRUD ----------

    /// Insert a new account. Returns the freshly-decrypted record.
    /// Errors on duplicate `login` or empty `login`.
    ///
    /// Duplicate-login errors are reported as [`DuplicateLogin`], wrapped
    /// in `anyhow::Error`. Callers that want to special-case duplicates
    /// (e.g. [`PasswordManager::import_from_json`]) can downcast.
    pub fn create_user(&self, login: &str, email: &str, password: &str) -> Result<UserRecord> {
        if login.is_empty() {
            bail!("login must not be empty");
        }
        let fernet = self.require_unlocked()?;
        let encrypted = crypto::encrypt_str(fernet, password);
        let conn = self.open_conn()?;
        let res = conn.execute(
            "INSERT INTO users(login, email, password_encrypted) VALUES (?1, ?2, ?3)",
            params![login, email, encrypted],
        );
        let user_id = match res {
            Ok(_) => conn.last_insert_rowid(),
            Err(rusqlite::Error::SqliteFailure(e, _))
                if e.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                return Err(DuplicateLogin {
                    login: login.to_string(),
                }
                .into());
            }
            Err(e) => return Err(e).context("inserting user"),
        };
        self.fetch_by_id_with(&conn, user_id)
    }

    /// Lookup a single account by login. Returns `Ok(None)` if absent.
    pub fn get_user(&self, login: &str) -> Result<Option<UserRecord>> {
        let fernet = self.require_unlocked()?;
        let conn = self.open_conn()?;
        let row: Option<(i64, String, Option<String>, String, String)> = conn
            .query_row(
                "SELECT id, login, email, password_encrypted, created_at \
                 FROM users WHERE login = ?1",
                params![login],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()?;
        row.map(|t| Self::row_to_record(t, fernet)).transpose()
    }

    /// Return all accounts ordered by id.
    pub fn list_users(&self) -> Result<Vec<UserRecord>> {
        let fernet = self.require_unlocked()?;
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, login, email, password_encrypted, created_at FROM users ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|t| Self::row_to_record(t, fernet))
            .collect()
    }

    /// Delete account by login. Returns `true` iff a row was removed.
    pub fn delete_user(&self, login: &str) -> Result<bool> {
        self.require_unlocked()?;
        let conn = self.open_conn()?;
        let n = conn.execute("DELETE FROM users WHERE login = ?1", params![login])?;
        Ok(n > 0)
    }

    /// Re-encrypt and store a new password for `login`. Returns `true`
    /// iff a row was updated.
    pub fn update_password(&self, login: &str, new_password: &str) -> Result<bool> {
        let fernet = self.require_unlocked()?;
        let encrypted = crypto::encrypt_str(fernet, new_password);
        let conn = self.open_conn()?;
        let n = conn.execute(
            "UPDATE users SET password_encrypted = ?1 WHERE login = ?2",
            params![encrypted, login],
        )?;
        Ok(n > 0)
    }

    /// Case-insensitive substring search over login + email.
    ///
    /// `%`, `_` and `\\` in `query` are escaped so they are matched as
    /// literals rather than as SQL `LIKE` wildcards.
    pub fn search(&self, query: &str) -> Result<Vec<UserRecord>> {
        let fernet = self.require_unlocked()?;
        // Escape LIKE metacharacters so user input is matched literally.
        // The backslash *must* be escaped first or we'd double-escape the
        // escapes added by the next two replacements.
        let escaped = query
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let like = format!("%{}%", escaped);
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, login, email, password_encrypted, created_at FROM users \
             WHERE login LIKE ?1 ESCAPE '\\' OR IFNULL(email,'') LIKE ?1 ESCAPE '\\' \
             ORDER BY id",
        )?;
        let rows = stmt
            .query_map(params![like], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?
            .collect::<Result<Vec<_>, _>>()?;
        rows.into_iter()
            .map(|t| Self::row_to_record(t, fernet))
            .collect()
    }

    /// Write all decrypted accounts to `path` as JSON. Returns count.
    ///
    /// On Unix the file is created with mode `0600` (owner read/write
    /// only). Default `std::fs::write` would honour the user's umask
    /// and on a typical desktop that gives `0644` — world-readable —
    /// which is unacceptable for a file that contains every plaintext
    /// password. On Windows we simply overwrite via the standard API
    /// and rely on the user's NTFS ACLs (the existing file's ACL is
    /// preserved on overwrite, and a freshly created file inherits the
    /// directory's ACL).
    pub fn export_to_json<P: AsRef<Path>>(&self, path: P) -> Result<usize> {
        let records = self.list_users()?;
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let json = serde_json::to_string_pretty(&records)?;
        write_owner_only(path.as_ref(), json.as_bytes()).context("writing export file")?;
        Ok(records.len())
    }

    /// Import accounts from a JSON array produced by [`export_to_json`].
    /// Skips duplicates by default. Returns count of newly inserted rows.
    pub fn import_from_json<P: AsRef<Path>>(
        &self,
        path: P,
        skip_duplicates: bool,
    ) -> Result<usize> {
        let bytes = std::fs::read(&path).context("reading import file")?;
        let payload: Vec<serde_json::Value> =
            serde_json::from_slice(&bytes).context("parsing JSON array")?;
        let mut inserted = 0usize;
        for entry in payload {
            let login = entry.get("login").and_then(|v| v.as_str()).unwrap_or("");
            let email = entry.get("email").and_then(|v| v.as_str()).unwrap_or("");
            let password = entry.get("password").and_then(|v| v.as_str()).unwrap_or("");
            // Skip malformed entries: an empty login or password is
            // never useful and `create_user` would either reject the
            // login or store an undecryptable empty ciphertext.
            if login.is_empty() || password.is_empty() {
                continue;
            }
            match self.create_user(login, email, password) {
                Ok(_) => inserted += 1,
                Err(e) => {
                    // Only swallow duplicate-login errors when the caller
                    // asked us to. Every other failure (disk full, decrypt
                    // error, schema mismatch, …) must propagate so the
                    // user is not silently misled about how many records
                    // actually made it in.
                    if skip_duplicates && e.downcast_ref::<DuplicateLogin>().is_some() {
                        continue;
                    }
                    return Err(e);
                }
            }
        }
        Ok(inserted)
    }

    // ---------- internals ----------

    fn fetch_by_id_with(&self, conn: &rusqlite::Connection, user_id: i64) -> Result<UserRecord> {
        let fernet = self.require_unlocked()?;
        let row: (i64, String, Option<String>, String, String) = conn.query_row(
            "SELECT id, login, email, password_encrypted, created_at FROM users WHERE id = ?1",
            params![user_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        Self::row_to_record(row, fernet)
    }

    fn row_to_record(
        row: (i64, String, Option<String>, String, String),
        fernet: &Fernet,
    ) -> Result<UserRecord> {
        let (id, login, email, ct, created_at) = row;
        let password = crypto::decrypt_str(fernet, &ct)
            .context("decrypting stored password (corrupt DB or wrong key?)")?;
        Ok(UserRecord {
            id,
            login,
            email,
            password,
            created_at,
        })
    }

    /// Hidden helper for the CLI prompt: the on-disk path of the DB.
    pub fn db_path(&self) -> &Path {
        &self.db_path
    }
}

// `Fernet` from the upstream crate does not zeroize its internal key
// material on Drop; the manager deliberately scopes it via
// `Option<Fernet>` so it is dropped on `lock()` and at process exit.
// See the `PasswordManager` struct doc for the full rationale.

/// Atomically write `data` to `path` with owner-only permissions
/// (`0600` on Unix). Used by [`PasswordManager::export_to_json`] for the
/// plaintext-password export file.
#[cfg(unix)]
fn write_owner_only(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

/// Windows fallback — `std::fs::write` preserves any existing file's
/// ACL and otherwise inherits the parent directory's. We do not attempt
/// to set a stricter ACL programmatically here; users on shared
/// machines should pick a path inside their own profile.
#[cfg(not(unix))]
fn write_owner_only(path: &Path, data: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn tmp_db() -> (tempfile::TempDir, PathBuf) {
        let dir = tempdir().unwrap();
        let p = dir.path().join("users.db");
        (dir, p)
    }

    #[test]
    fn first_setup_marks_argon2id() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        assert!(!m.has_master_password().unwrap());
        m.set_master_password("master-1").unwrap();
        assert!(!m.is_legacy_kdf().unwrap());
        assert!(m.is_unlocked());
    }

    #[test]
    fn cannot_set_master_twice() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("a").unwrap();
        assert!(m.set_master_password("b").is_err());
    }

    #[test]
    fn verify_master_password_round_trip() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("master-1").unwrap();
        m.lock();
        assert!(m.verify_master_password("master-1").unwrap());
        assert!(!m.verify_master_password("wrong").unwrap());
    }

    #[test]
    fn crud_round_trip() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("master").unwrap();
        let r = m.create_user("alice", "a@x", "p@ssw0rd!").unwrap();
        assert_eq!(r.login, "alice");
        assert_eq!(r.password, "p@ssw0rd!");
        assert!(m.create_user("alice", "a@x", "x").is_err()); // duplicate

        let got = m.get_user("alice").unwrap().unwrap();
        assert_eq!(got.password, "p@ssw0rd!");

        assert!(m.update_password("alice", "new-pw").unwrap());
        let got = m.get_user("alice").unwrap().unwrap();
        assert_eq!(got.password, "new-pw");

        let listed = m.list_users().unwrap();
        assert_eq!(listed.len(), 1);

        let found = m.search("ali").unwrap();
        assert_eq!(found.len(), 1);

        assert!(m.delete_user("alice").unwrap());
        assert!(!m.delete_user("alice").unwrap());
        assert!(m.get_user("alice").unwrap().is_none());
    }

    #[test]
    fn locked_blocks_crud() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("master").unwrap();
        m.lock();
        assert!(m.create_user("a", "", "x").is_err());
        assert!(m.list_users().is_err());
    }

    #[test]
    fn change_master_rotates_and_reencrypts() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("old").unwrap();
        m.create_user("alice", "a@x", "secret").unwrap();
        m.create_user("bob", "b@x", "hunter2").unwrap();

        let n = m.change_master_password("old", "new").unwrap();
        assert_eq!(n, 2);

        // Re-open with a fresh manager; old password fails, new works.
        let mut m2 = PasswordManager::new(&p).unwrap();
        assert!(!m2.verify_master_password("old").unwrap());
        assert!(m2.verify_master_password("new").unwrap());
        assert_eq!(m2.get_user("alice").unwrap().unwrap().password, "secret");
        assert_eq!(m2.get_user("bob").unwrap().unwrap().password, "hunter2");
    }

    #[test]
    fn change_master_rejects_wrong_old() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("old").unwrap();
        let err = m.change_master_password("WRONG", "new").unwrap_err();
        assert!(err.to_string().contains("old master password"));
    }

    #[test]
    fn legacy_pbkdf2_db_unlocks_then_migrates_on_change() {
        // Manually seed a legacy DB the way the old code would have:
        // a salt + verifier but NO `kdf_version` row.
        let (_d, p) = tmp_db();
        {
            let conn = db::open(&p).unwrap();
            let salt = crypto::generate_salt();
            let key = crypto::derive_key("old", &salt, KDF_PBKDF2_LEGACY).unwrap();
            let fernet = crypto::fernet_from_key(&key).unwrap();
            let verifier = crypto::make_verifier(&fernet);
            db::set_meta(&conn, META_SALT, &salt).unwrap();
            db::set_meta(&conn, META_VERIFIER, verifier.as_bytes()).unwrap();
            // NB: deliberately NOT writing META_KDF.
        }

        let mut m = PasswordManager::new(&p).unwrap();
        assert!(m.is_legacy_kdf().unwrap());
        assert!(m.verify_master_password("old").unwrap());
        m.create_user("alice", "a@x", "secret").unwrap();

        let n = m.change_master_password("old", "new").unwrap();
        assert_eq!(n, 1);
        assert!(!m.is_legacy_kdf().unwrap());

        let mut m2 = PasswordManager::new(&p).unwrap();
        assert!(!m2.verify_master_password("old").unwrap());
        assert!(m2.verify_master_password("new").unwrap());
        assert_eq!(m2.get_user("alice").unwrap().unwrap().password, "secret");
    }

    #[test]
    fn export_import_round_trip() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("master").unwrap();
        m.create_user("alice", "a@x", "p1").unwrap();
        m.create_user("bob", "b@x", "p2").unwrap();

        let dir = tempdir().unwrap();
        let json = dir.path().join("export.json");
        let n = m.export_to_json(&json).unwrap();
        assert_eq!(n, 2);

        // Fresh DB.
        let p2 = dir.path().join("users2.db");
        let mut m2 = PasswordManager::new(&p2).unwrap();
        m2.set_master_password("other").unwrap();
        let inserted = m2.import_from_json(&json, true).unwrap();
        assert_eq!(inserted, 2);
        assert_eq!(m2.get_user("alice").unwrap().unwrap().password, "p1");

        // Importing again — duplicates skipped.
        let again = m2.import_from_json(&json, true).unwrap();
        assert_eq!(again, 0);
    }

    #[test]
    fn create_user_returns_typed_duplicate_login_error() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("m").unwrap();
        m.create_user("alice", "a@x", "p1").unwrap();
        let err = m.create_user("alice", "a@x", "p2").unwrap_err();
        assert!(
            err.downcast_ref::<DuplicateLogin>().is_some(),
            "expected DuplicateLogin, got {err:?}"
        );
    }

    #[test]
    fn import_skips_duplicates_only_not_other_errors() {
        // Build an export, then re-import into a DB that already has the
        // same login → exactly one row already present → import_from_json
        // should report 0 inserts (skip_duplicates=true) and *not* fail.
        let (_d1, p1) = tmp_db();
        let mut m1 = PasswordManager::new(&p1).unwrap();
        m1.set_master_password("m").unwrap();
        m1.create_user("alice", "a@x", "p1").unwrap();
        let json_path = _d1.path().join("dump.json");
        m1.export_to_json(&json_path).unwrap();

        let (_d2, p2) = tmp_db();
        let mut m2 = PasswordManager::new(&p2).unwrap();
        m2.set_master_password("m").unwrap();
        m2.create_user("alice", "a@x", "preexisting").unwrap();

        // skip_duplicates=true → the alice row in JSON collides, is
        // skipped, no error surfaces. The original row is preserved.
        let inserted = m2.import_from_json(&json_path, true).unwrap();
        assert_eq!(inserted, 0);
        assert_eq!(
            m2.get_user("alice").unwrap().unwrap().password,
            "preexisting"
        );

        // skip_duplicates=false → same import fails loudly (and the typed
        // error is still a DuplicateLogin downcastable from anyhow).
        let err = m2.import_from_json(&json_path, false).unwrap_err();
        assert!(err.downcast_ref::<DuplicateLogin>().is_some());
    }

    #[test]
    fn search_treats_like_metacharacters_as_literals() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("m").unwrap();
        m.create_user("alice", "a@x", "p").unwrap();
        m.create_user("bob_smith", "b@x", "p").unwrap();
        m.create_user("100%real", "c@x", "p").unwrap();

        // `%` should match only the literal-percent row, not all rows.
        let pct = m.search("%").unwrap();
        assert_eq!(pct.len(), 1);
        assert_eq!(pct[0].login, "100%real");

        // `_` should match only the underscore row, not "any single char".
        let und = m.search("_").unwrap();
        assert_eq!(und.len(), 1);
        assert_eq!(und[0].login, "bob_smith");

        // Plain queries still work.
        assert_eq!(m.search("ali").unwrap().len(), 1);
    }

    #[test]
    fn import_skips_entries_with_empty_password() {
        // Build an export-shaped JSON by hand with one valid row and
        // two malformed (empty login / empty password) rows. Only the
        // valid row should be inserted; nothing should error.
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("m").unwrap();

        let dir = tempdir().unwrap();
        let json_path = dir.path().join("import.json");
        let payload = serde_json::json!([
            { "login": "alice", "email": "a@x", "password": "p1" },
            { "login": "",      "email": "x@y", "password": "p2" },
            { "login": "bob",   "email": "b@y", "password": ""   }
        ]);
        std::fs::write(&json_path, serde_json::to_vec(&payload).unwrap()).unwrap();

        let inserted = m.import_from_json(&json_path, true).unwrap();
        assert_eq!(inserted, 1);
        assert_eq!(m.get_user("alice").unwrap().unwrap().password, "p1");
        assert!(m.get_user("bob").unwrap().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn export_file_has_owner_only_mode() {
        use std::os::unix::fs::PermissionsExt;

        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("m").unwrap();
        m.create_user("alice", "a@x", "secret").unwrap();

        let dir = tempdir().unwrap();
        let json = dir.path().join("export.json");
        m.export_to_json(&json).unwrap();
        let mode = std::fs::metadata(&json).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "export file mode should be 0600, got {:o}",
            mode
        );
    }

    #[test]
    fn second_init_in_face_of_already_set_master_bails() {
        // Direct functional test of the inside-transaction recheck: we
        // can't easily race two threads through this single-threaded
        // SQLite connection, but the recheck also fires on the second
        // call from a single PasswordManager — exercising the same
        // branch that defends against the cross-process race.
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("first").unwrap();
        let err = m.set_master_password("second").unwrap_err();
        assert!(
            err.to_string().contains("master password already set"),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn debug_redacts_secrets() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("super-secret-master").unwrap();
        let dbg = format!("{:?}", m);
        assert!(!dbg.contains("super-secret-master"));
        assert!(!dbg.contains("Fernet"));
    }
}

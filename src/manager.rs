//! High-level [`PasswordManager`] API: wraps DB + crypto and tracks
//! lock/unlock state.
//!
//! Mirrors the Python `PasswordManager` 1:1 in semantics. Differences:
//!
//! * The derived Fernet key (and the key string itself) is wrapped in
//!   [`secrecy::SecretString`] so [`Drop`] zeroizes it.
//! * The constructed [`fernet::Fernet`] is held only inside an
//!   [`Option`] — `lock()` drops it.
//! * All errors funnel through `anyhow::Result` for the public API; the
//!   `_internal` helpers use `thiserror`-typed errors.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use fernet::Fernet;
use rusqlite::{params, OptionalExtension};
#[cfg(test)]
use secrecy::ExposeSecret;
use secrecy::SecretString;
use serde::{Deserialize, Serialize};

use crate::crypto::{self, KDF_ARGON2ID_V1, KDF_PBKDF2_LEGACY};
use crate::db;

/// Default DB path, matching the Python reference (`./users.db`).
pub const DEFAULT_DB_PATH: &str = "users.db";

/// Meta keys persisted in the SQLite `meta` table.
pub const META_SALT: &str = "salt";
pub const META_VERIFIER: &str = "verifier";
pub const META_KDF: &str = "kdf_version";

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
pub struct PasswordManager {
    db_path: PathBuf,
    /// `Some` when the master password has been verified. Dropping this
    /// (via `lock()` or `Drop`) drops the underlying key — `secrecy` is
    /// applied to the key bytes too via [`SecretString`] inside `set` /
    /// `verify` paths.
    fernet: Option<Fernet>,
    /// Held in parallel to `fernet` so we can re-construct it after
    /// transient operations and rotate it on `change_master_password`.
    /// `secrecy::SecretString` clears it on drop.
    key: Option<SecretString>,
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
            key: None,
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
    pub fn set_master_password(&mut self, master_password: &str) -> Result<()> {
        if self.has_master_password()? {
            bail!("master password already set");
        }
        if master_password.is_empty() {
            bail!("master password must not be empty");
        }

        let salt = crypto::generate_salt();
        let key = crypto::derive_key(master_password, &salt, KDF_ARGON2ID_V1)
            .context("deriving master key")?;
        let fernet = crypto::fernet_from_key(&key).context("building Fernet")?;
        let verifier = crypto::make_verifier(&fernet);

        let conn = self.open_conn()?;
        db::set_meta(&conn, META_SALT, &salt)?;
        db::set_meta(&conn, META_VERIFIER, verifier.as_bytes())?;
        db::set_meta(&conn, META_KDF, KDF_ARGON2ID_V1.as_bytes())?;

        self.fernet = Some(fernet);
        self.key = Some(SecretString::new(key));
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

        let key = match crypto::derive_key(master_password, &salt, &kdf_version) {
            Ok(k) => k,
            Err(_) => return Ok(false),
        };
        let fernet = crypto::fernet_from_key(&key)?;
        let token = std::str::from_utf8(&verifier)
            .map_err(|_| anyhow!("verifier is not valid UTF-8 (corrupt DB?)"))?;
        if crypto::check_verifier(&fernet, token) {
            self.fernet = Some(fernet);
            self.key = Some(SecretString::new(key));
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
        let new_key = crypto::derive_key(new_master_password, &new_salt, KDF_ARGON2ID_V1)?;
        let new_fernet = crypto::fernet_from_key(&new_key)?;
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
        self.key = Some(SecretString::new(new_key));
        Ok(count)
    }

    /// Forget the derived key. Subsequent CRUD calls fail until the user
    /// re-authenticates via [`verify_master_password`].
    pub fn lock(&mut self) {
        self.fernet = None;
        self.key = None;
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
                bail!("login {:?} already exists", login)
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
    pub fn search(&self, query: &str) -> Result<Vec<UserRecord>> {
        let fernet = self.require_unlocked()?;
        let like = format!("%{}%", query);
        let conn = self.open_conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, login, email, password_encrypted, created_at FROM users \
             WHERE login LIKE ?1 OR IFNULL(email,'') LIKE ?1 \
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
    pub fn export_to_json<P: AsRef<Path>>(&self, path: P) -> Result<usize> {
        let records = self.list_users()?;
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).ok();
            }
        }
        let json = serde_json::to_string_pretty(&records)?;
        std::fs::write(&path, json).context("writing export file")?;
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
            let password = entry.get("password").and_then(|v| v.as_str());
            if login.is_empty() || password.is_none() {
                continue;
            }
            match self.create_user(login, email, password.unwrap()) {
                Ok(_) => inserted += 1,
                Err(e) => {
                    if !skip_duplicates {
                        return Err(e);
                    }
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

// Manual `Drop` only needed if we ever switch `key` away from
// `secrecy::SecretString`. SecretString already zeroizes on drop;
// dropping `Fernet` itself does not zero its internal key buffer, but
// the project deliberately scopes it via `Option<Fernet>` so it's
// dropped on `lock()` and at process exit.

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
    fn debug_redacts_secrets() {
        let (_d, p) = tmp_db();
        let mut m = PasswordManager::new(&p).unwrap();
        m.set_master_password("super-secret-master").unwrap();
        let dbg = format!("{:?}", m);
        assert!(!dbg.contains("super-secret-master"));
        assert!(!dbg.contains("Fernet"));
    }

    #[test]
    fn expose_secret_helper_works_when_used() {
        // Ensures we use `secrecy` crate properly — `expose_secret` returns
        // the backing string so we can construct Fernet from it later if
        // needed.
        let s = SecretString::new("hello".to_string());
        assert_eq!(s.expose_secret(), "hello");
    }
}

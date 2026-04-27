//! SQLite schema and low-level meta access.
//!
//! Schema (matches the Python reference byte-for-byte so a DB written by
//! either implementation is readable by the other):
//!
//! ```sql
//! CREATE TABLE meta (
//!     key   TEXT PRIMARY KEY,
//!     value BLOB NOT NULL
//! );
//!
//! CREATE TABLE users (
//!     id                 INTEGER PRIMARY KEY AUTOINCREMENT,
//!     login              TEXT    UNIQUE NOT NULL,
//!     email              TEXT,
//!     password_encrypted TEXT    NOT NULL,
//!     created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
//! );
//! CREATE INDEX idx_users_email ON users(email);
//! ```

use std::path::Path;

use rusqlite::{params, Connection, OptionalExtension};
use thiserror::Error;

/// Schema bootstrap script — idempotent (`IF NOT EXISTS` everywhere).
pub const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    login              TEXT    UNIQUE NOT NULL,
    email              TEXT,
    password_encrypted TEXT    NOT NULL,
    created_at         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
"#;

/// Errors returned by the DB layer. CRUD-level callers usually surface
/// these via `anyhow`.
#[derive(Debug, Error)]
pub enum DbError {
    /// Underlying `rusqlite` error.
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// Open a connection to `db_path` and ensure the schema is applied.
///
/// Tunes SQLite for a password store (durability over throughput):
///
/// * `journal_mode=WAL` — write-ahead-log avoids the rollback-journal
///   "delete the journal then rename the DB" dance whose mid-rename
///   crash window is famously corruption-prone. WAL also lets readers
///   and writers coexist, which the pwm CLI doesn't strictly need but
///   costs nothing.
/// * `synchronous=FULL` — fsync every commit. On a password store the
///   user always prefers "your last write definitely landed" over
///   throughput. The default `FULL` already matches what we want, but
///   we set it explicitly so a user-tweaked SQLite build cannot
///   downgrade us.
/// * `foreign_keys=ON` — schema doesn't currently use foreign keys, but
///   future migrations might; turning the check on here is the safe
///   default.
pub fn open(db_path: &Path) -> Result<Connection, DbError> {
    let conn = Connection::open(db_path)?;
    // pragma_update is the right rusqlite API for these — it goes
    // through a prepared statement so SQLite parses it properly.
    let _ = conn.pragma_update(None, "journal_mode", "WAL");
    let _ = conn.pragma_update(None, "synchronous", "FULL");
    let _ = conn.pragma_update(None, "foreign_keys", "ON");
    conn.execute_batch(SCHEMA)?;
    Ok(conn)
}

/// Read a `meta(value)` blob by key. Returns `Ok(None)` if absent.
pub fn get_meta(conn: &Connection, key: &str) -> Result<Option<Vec<u8>>, DbError> {
    let value = conn
        .query_row(
            "SELECT value FROM meta WHERE key = ?1",
            params![key],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?;
    Ok(value)
}

/// Upsert a `meta(key, value)` row.
pub fn set_meta(conn: &Connection, key: &str, value: &[u8]) -> Result<(), DbError> {
    conn.execute(
        "INSERT INTO meta(key, value) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        params![key, value],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn schema_is_idempotent() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("users.db");
        let _ = open(&path).unwrap();
        let _ = open(&path).unwrap(); // Re-running must not error.
    }

    #[test]
    fn meta_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("users.db");
        let conn = open(&path).unwrap();

        assert!(get_meta(&conn, "salt").unwrap().is_none());
        set_meta(&conn, "salt", b"\x01\x02\x03").unwrap();
        assert_eq!(
            get_meta(&conn, "salt").unwrap(),
            Some(b"\x01\x02\x03".to_vec())
        );

        // Upsert overwrites.
        set_meta(&conn, "salt", b"\xff\xee").unwrap();
        assert_eq!(get_meta(&conn, "salt").unwrap(), Some(b"\xff\xee".to_vec()));
    }
}

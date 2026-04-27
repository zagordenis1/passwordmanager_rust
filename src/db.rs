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
pub fn open(db_path: &Path) -> Result<Connection, DbError> {
    let conn = Connection::open(db_path)?;
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

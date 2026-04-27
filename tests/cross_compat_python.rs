//! Cross-compatibility tests: prove that the Rust implementation can
//! open a database produced by the Python reference (and vice versa).
//!
//! The test is skipped when:
//! * `python3` is not on `$PATH`, or
//! * the `cryptography` and `argon2-cffi` packages are not importable.
//!
//! On the canonical Linux CI runner both are installable in seconds via
//! `pip install cryptography argon2-cffi`. Locally, the `cross-compat`
//! workflow job in `.github/workflows/ci.yml` does this for you.

use std::path::Path;
use std::process::Command;

use passwordmanagerrs::PasswordManager;

fn python_available() -> bool {
    let out = Command::new("python3")
        .args(["-c", "import cryptography, argon2; print('ok')"])
        .output();
    matches!(out, Ok(o) if o.status.success())
}

fn run_python(script: &str, db_path: &Path) -> Result<(), String> {
    let out = Command::new("python3")
        .arg("-c")
        .arg(script)
        .env("PWM_DB", db_path.to_string_lossy().to_string())
        .output()
        .map_err(|e| format!("spawning python: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "python failed: {}\nstdout:\n{}\nstderr:\n{}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

const PY_CREATE_DB: &str = r#"
import os, base64, sqlite3
from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet

db = os.environ["PWM_DB"]
SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    email TEXT,
    password_encrypted TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
'''

VERIFIER = b"password_manager:verifier:v1"
salt = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
master = "py-created-master"
raw = hash_secret_raw(secret=master.encode(), salt=salt, time_cost=2, memory_cost=19456,
                     parallelism=1, hash_len=32, type=Type.ID)
key = base64.urlsafe_b64encode(raw)
f = Fernet(key)
verifier = f.encrypt(VERIFIER)
ct = f.encrypt(b"py-secret-payload").decode("utf-8")

con = sqlite3.connect(db)
con.executescript(SCHEMA)
con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES (?, ?)", ("salt", salt))
con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES (?, ?)", ("verifier", verifier))
con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES (?, ?)", ("kdf_version", b"argon2id-v1"))
con.execute("INSERT INTO users(login,email,password_encrypted) VALUES(?,?,?)",
            ("alice", "a@x", ct))
con.commit()
con.close()
"#;

const PY_READ_DB: &str = r#"
import os, base64, sqlite3
from argon2.low_level import Type, hash_secret_raw
from cryptography.fernet import Fernet

db = os.environ["PWM_DB"]
con = sqlite3.connect(db)
con.row_factory = sqlite3.Row

def get_meta(k):
    row = con.execute("SELECT value FROM meta WHERE key=?", (k,)).fetchone()
    return None if row is None else bytes(row["value"])

salt = get_meta("salt")
master = "rs-created-master"
raw = hash_secret_raw(secret=master.encode(), salt=salt, time_cost=2, memory_cost=19456,
                     parallelism=1, hash_len=32, type=Type.ID)
key = base64.urlsafe_b64encode(raw)
f = Fernet(key)
v = f.decrypt(get_meta("verifier").decode("utf-8") if isinstance(get_meta("verifier"), bytes) else get_meta("verifier"))
assert v == b"password_manager:verifier:v1", "verifier mismatch"
row = con.execute("SELECT password_encrypted FROM users WHERE login='alice'").fetchone()
ct = row["password_encrypted"]
plain = f.decrypt(ct).decode("utf-8")
assert plain == "rs-secret-payload", f"got {plain!r}"
print("ok")
"#;

#[test]
fn rust_reads_python_created_db() {
    if !python_available() {
        eprintln!("skipping: python3+cryptography+argon2 not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("users.db");
    run_python(PY_CREATE_DB, &db).expect("seed python DB");

    let mut m = PasswordManager::new(&db).expect("open python DB");
    assert!(
        m.verify_master_password("py-created-master").unwrap(),
        "rust must verify the python-set master password"
    );
    let alice = m.get_user("alice").unwrap().expect("alice exists");
    assert_eq!(alice.password, "py-secret-payload");
}

#[test]
fn python_reads_rust_created_db() {
    if !python_available() {
        eprintln!("skipping: python3+cryptography+argon2 not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("users.db");

    {
        let mut m = PasswordManager::new(&db).unwrap();
        m.set_master_password("rs-created-master").unwrap();
        m.create_user("alice", "a@x", "rs-secret-payload").unwrap();
    }

    run_python(PY_READ_DB, &db).expect("python must read rust-created DB");
}

#[test]
fn rust_reads_python_legacy_pbkdf2_db() {
    if !python_available() {
        eprintln!("skipping: python3+cryptography+argon2 not available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("users.db");

    // Construct a *legacy* DB the way pre-Argon2 Python releases would —
    // PBKDF2-HMAC-SHA256 480_000 iterations and NO `kdf_version` row.
    const PY_LEGACY: &str = r#"
import os, base64, sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

db = os.environ["PWM_DB"]
SCHEMA = '''
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value BLOB NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login TEXT UNIQUE NOT NULL,
    email TEXT,
    password_encrypted TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
'''
VERIFIER = b"password_manager:verifier:v1"
salt = b"\x10" * 16
master = "legacy-master"
kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480_000)
raw = kdf.derive(master.encode())
key = base64.urlsafe_b64encode(raw)
f = Fernet(key)
ver = f.encrypt(VERIFIER)
ct = f.encrypt(b"legacy-pw").decode()
con = sqlite3.connect(db)
con.executescript(SCHEMA)
con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES (?, ?)", ("salt", salt))
con.execute("INSERT OR REPLACE INTO meta(key,value) VALUES (?, ?)", ("verifier", ver))
# NB: deliberately no kdf_version row.
con.execute("INSERT INTO users(login,email,password_encrypted) VALUES(?,?,?)",
            ("legacy-user","l@x", ct))
con.commit(); con.close()
"#;
    run_python(PY_LEGACY, &db).expect("seed legacy DB");

    let mut m = PasswordManager::new(&db).unwrap();
    assert!(m.is_legacy_kdf().unwrap());
    assert!(m.verify_master_password("legacy-master").unwrap());
    let user = m.get_user("legacy-user").unwrap().expect("user exists");
    assert_eq!(user.password, "legacy-pw");
}

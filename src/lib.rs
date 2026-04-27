//! Library crate exposing the password-manager core for tests and
//! third-party callers. The `pwm` binary is a thin wrapper over these
//! modules.
//!
//! The architecture mirrors the original Python project:
//!
//! * [`crypto`] — Argon2id KDF (default) + PBKDF2 legacy fallback +
//!   Fernet helpers.
//! * [`db`]     — SQLite schema and low-level meta access.
//! * [`manager`] — high-level `PasswordManager` that combines crypto
//!   and DB into a CRUD API with master-password lifecycle.
//! * [`generator`] — secure password generator built on the OS CSPRNG.
//! * [`cli`]    — interactive Ukrainian-language menu and clap-based
//!   non-interactive subcommands.

pub mod crypto;
pub mod db;
pub mod generator;
pub mod manager;

pub mod cli;

pub use manager::{DuplicateLogin, PasswordManager, UserRecord, DEFAULT_DB_PATH};

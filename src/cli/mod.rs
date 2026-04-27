//! CLI entry point. Dispatches to either the interactive Ukrainian-language
//! menu or one of the non-interactive `clap` subcommands.

pub mod commands;
pub mod interactive;

use clap::{Parser, Subcommand};

use crate::manager::DEFAULT_DB_PATH;

/// `pwm` — Rust port of the Python CLI password manager.
///
/// Run with no subcommand to launch the interactive Ukrainian-language menu
/// (the same UX as the Python reference). Pass a subcommand for scripting.
#[derive(Debug, Parser)]
#[command(
    name = "pwm",
    version,
    about = "Rust port of the Python CLI password manager",
    long_about = None,
    propagate_version = true,
)]
pub struct Cli {
    /// Path to the SQLite DB. Defaults to `users.db` in the cwd.
    #[arg(long, global = true, default_value = DEFAULT_DB_PATH)]
    pub db: String,

    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Initialise the master password on a fresh DB.
    Init,
    /// Add a new account. Password is read from stdin (hidden) by default.
    Add {
        #[arg(long)]
        login: String,
        #[arg(long, default_value = "")]
        email: String,
        /// Read password from a single stdin line instead of a hidden prompt.
        /// Useful for piping in scripts.
        #[arg(long, default_value_t = false)]
        stdin: bool,
    },
    /// Print the password for `login` to stdout.
    Get {
        login: String,
        /// Show full record (login + email + password) instead of just the password.
        #[arg(long, default_value_t = false)]
        full: bool,
    },
    /// List all accounts.
    List {
        /// Output as JSON (passwords decrypted).
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Delete an account by login.
    Rm {
        login: String,
        /// Skip the y/N confirmation prompt.
        #[arg(long, default_value_t = false)]
        force: bool,
    },
    /// Change the master password (re-encrypts every row atomically).
    ChangeMaster,
    /// Generate a fresh password and print it.
    Gen {
        #[arg(long, default_value_t = crate::generator::DEFAULT_LENGTH)]
        length: usize,
        #[arg(long, default_value_t = false)]
        no_lower: bool,
        #[arg(long, default_value_t = false)]
        no_upper: bool,
        #[arg(long, default_value_t = false)]
        no_digits: bool,
        #[arg(long, default_value_t = false)]
        no_symbols: bool,
    },
    /// Search by login/email substring (case-insensitive).
    Search {
        query: String,
        /// Output as JSON (passwords decrypted).
        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Update the password for an existing login.
    Update {
        login: String,
        /// Read new password from a single stdin line (default: hidden prompt).
        #[arg(long, default_value_t = false)]
        stdin: bool,
    },
    /// Export every account to a JSON file.
    Export { path: String },
    /// Import accounts from a JSON file produced by `export`.
    Import {
        path: String,
        /// Fail on the first duplicate login instead of skipping it.
        #[arg(long, default_value_t = false)]
        no_skip_duplicates: bool,
    },
}

/// Process entry. Returns the desired exit code.
pub fn run() -> i32 {
    let cli = Cli::parse();
    match cli.command {
        None => match interactive::run(&cli.db) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("Помилка: {e:#}");
                1
            }
        },
        Some(cmd) => match commands::run(&cli.db, cmd) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("Помилка: {e:#}");
                1
            }
        },
    }
}

//! Non-interactive `clap` subcommands. Each subcommand owns its own
//! authentication flow (master password via hidden prompt) and exits with
//! a deterministic exit code.

use std::io::{self, IsTerminal, Write};

use anyhow::{anyhow, bail, Context, Result};

use crate::generator::{generate_password, PasswordPolicy};
use crate::manager::PasswordManager;

use super::Command;

fn read_master_for_existing(manager: &mut PasswordManager) -> Result<()> {
    if !manager.has_master_password()? {
        bail!("DB has no master password yet — run `pwm init` first");
    }
    let pw = read_password_hidden_or_stdin("Master password: ")?;
    if !manager.verify_master_password(&pw)? {
        bail!("invalid master password");
    }
    if manager.is_legacy_kdf().unwrap_or(false) {
        eprintln!(
            "Увага: ця БД використовує старий KDF (PBKDF2). Змініть master password \
             (`pwm change-master`) щоб мігрувати на Argon2id."
        );
    }
    Ok(())
}

/// If stdin is a TTY → hidden prompt via `rpassword`. Otherwise → read a
/// single line from stdin (useful for `echo pw | pwm get foo`).
fn read_password_hidden_or_stdin(prompt: &str) -> Result<String> {
    if io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).context("reading password")
    } else {
        let mut line = String::new();
        io::stdin()
            .read_line(&mut line)
            .context("reading password")?;
        Ok(line.trim_end_matches(['\n', '\r']).to_string())
    }
}

/// Dispatch a clap-parsed subcommand. Returns the desired exit code.
pub fn run(db_path: &str, cmd: Command) -> Result<i32> {
    let mut manager = PasswordManager::new(db_path).context("opening manager")?;
    match cmd {
        Command::Init => init(&mut manager),
        Command::Add {
            login,
            email,
            stdin,
        } => add(&mut manager, &login, &email, stdin),
        Command::Get { login, full } => get(&mut manager, &login, full),
        Command::List { json } => list(&mut manager, json),
        Command::Rm { login, force } => rm(&mut manager, &login, force),
        Command::ChangeMaster => change_master(&mut manager),
        Command::Gen {
            length,
            no_lower,
            no_upper,
            no_digits,
            no_symbols,
        } => gen(length, no_lower, no_upper, no_digits, no_symbols),
        Command::Search { query, json } => search(&mut manager, &query, json),
        Command::Update { login, stdin } => update(&mut manager, &login, stdin),
        Command::Export { path } => export(&mut manager, &path),
        Command::Import {
            path,
            no_skip_duplicates,
        } => import(&mut manager, &path, !no_skip_duplicates),
    }
}

fn init(manager: &mut PasswordManager) -> Result<i32> {
    if manager.has_master_password()? {
        bail!("master password already set");
    }
    let first = read_password_hidden_or_stdin("Новий master password: ")?;
    if first.is_empty() {
        bail!("master password must not be empty");
    }
    let second = read_password_hidden_or_stdin("Підтвердіть master password: ")?;
    if first != second {
        bail!("passwords do not match");
    }
    manager.set_master_password(&first)?;
    println!("Master password встановлено.");
    Ok(0)
}

fn add(manager: &mut PasswordManager, login: &str, email: &str, stdin: bool) -> Result<i32> {
    read_master_for_existing(manager)?;
    let password = if stdin {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim_end_matches(['\n', '\r']).to_string()
    } else {
        read_password_hidden_or_stdin("Password: ")?
    };
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let rec = manager.create_user(login, email, &password)?;
    println!(
        "Створено: id={} login={:?} email={:?}",
        rec.id,
        rec.login,
        rec.email.as_deref().unwrap_or("")
    );
    Ok(0)
}

fn get(manager: &mut PasswordManager, login: &str, full: bool) -> Result<i32> {
    read_master_for_existing(manager)?;
    match manager.get_user(login)? {
        None => {
            eprintln!("Не знайдено.");
            Ok(1)
        }
        Some(rec) => {
            if full {
                println!(
                    "id={} login={:?} email={:?} password={:?} created_at={}",
                    rec.id,
                    rec.login,
                    rec.email.as_deref().unwrap_or(""),
                    rec.password,
                    rec.created_at
                );
            } else {
                // Print just the password to stdout — friendly for `pwm get foo | pbcopy`.
                let mut out = io::stdout().lock();
                writeln!(out, "{}", rec.password)?;
            }
            Ok(0)
        }
    }
}

fn list(manager: &mut PasswordManager, json: bool) -> Result<i32> {
    read_master_for_existing(manager)?;
    let rs = manager.list_users()?;
    if json {
        let s = serde_json::to_string_pretty(&rs)?;
        println!("{}", s);
    } else if rs.is_empty() {
        println!("  (порожньо)");
    } else {
        for (i, r) in rs.iter().enumerate() {
            println!(
                "  [{}] id={} login={:?} email={:?} password={:?} created_at={}",
                i + 1,
                r.id,
                r.login,
                r.email.as_deref().unwrap_or(""),
                r.password,
                r.created_at,
            );
        }
    }
    Ok(0)
}

fn rm(manager: &mut PasswordManager, login: &str, force: bool) -> Result<i32> {
    read_master_for_existing(manager)?;
    if manager.get_user(login)?.is_none() {
        eprintln!("Не знайдено.");
        return Ok(1);
    }
    if !force {
        eprint!("Видалити акаунт {:?}? [y/N]: ", login);
        io::stderr().flush().ok();
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        let answer = line.trim().to_lowercase();
        if !matches!(answer.as_str(), "y" | "yes" | "т" | "так") {
            println!("Скасовано.");
            return Ok(0);
        }
    }
    if manager.delete_user(login)? {
        println!("Видалено.");
        Ok(0)
    } else {
        eprintln!("Не знайдено.");
        Ok(1)
    }
}

fn change_master(manager: &mut PasswordManager) -> Result<i32> {
    if !manager.has_master_password()? {
        bail!("DB has no master password yet — run `pwm init` first");
    }
    let old = read_password_hidden_or_stdin("Поточний master password: ")?;
    let new = read_password_hidden_or_stdin("Новий master password: ")?;
    if new.is_empty() {
        bail!("new master password must not be empty");
    }
    let confirm = read_password_hidden_or_stdin("Підтвердіть новий master password: ")?;
    if new != confirm {
        bail!("passwords do not match");
    }
    let count = manager.change_master_password(&old, &new)?;
    println!("Master password змінено. Перешифровано {count} акаунтів під новим ключем.");
    Ok(0)
}

fn gen(
    length: usize,
    no_lower: bool,
    no_upper: bool,
    no_digits: bool,
    no_symbols: bool,
) -> Result<i32> {
    let policy = PasswordPolicy {
        length,
        use_lower: !no_lower,
        use_upper: !no_upper,
        use_digits: !no_digits,
        use_symbols: !no_symbols,
        ..Default::default()
    };
    let pw = generate_password(&policy).map_err(|e| anyhow!("{e}"))?;
    println!("{pw}");
    Ok(0)
}

fn search(manager: &mut PasswordManager, query: &str, json: bool) -> Result<i32> {
    read_master_for_existing(manager)?;
    let rs = manager.search(query)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&rs)?);
    } else if rs.is_empty() {
        println!("  (порожньо)");
    } else {
        for (i, r) in rs.iter().enumerate() {
            println!(
                "  [{}] id={} login={:?} email={:?} password={:?} created_at={}",
                i + 1,
                r.id,
                r.login,
                r.email.as_deref().unwrap_or(""),
                r.password,
                r.created_at,
            );
        }
    }
    Ok(0)
}

fn update(manager: &mut PasswordManager, login: &str, stdin: bool) -> Result<i32> {
    read_master_for_existing(manager)?;
    if manager.get_user(login)?.is_none() {
        eprintln!("Не знайдено.");
        return Ok(1);
    }
    let new_pw = if stdin {
        let mut line = String::new();
        io::stdin().read_line(&mut line)?;
        line.trim_end_matches(['\n', '\r']).to_string()
    } else {
        read_password_hidden_or_stdin("Новий password: ")?
    };
    if new_pw.is_empty() {
        bail!("password must not be empty");
    }
    if manager.update_password(login, &new_pw)? {
        println!("Оновлено.");
        Ok(0)
    } else {
        eprintln!("Не вдалося оновити (можливо, акаунт видалений).");
        Ok(1)
    }
}

fn export(manager: &mut PasswordManager, path: &str) -> Result<i32> {
    read_master_for_existing(manager)?;
    let n = manager.export_to_json(path)?;
    println!("Експортовано {n} акаунтів у {path}.");
    if cfg!(unix) {
        eprintln!(
            "Увага: файл {path:?} містить ВСІ паролі у відкритому вигляді. \
             На Unix його створено з режимом 0600 (тільки власник). \
             Видаліть його після використання."
        );
    } else {
        eprintln!(
            "Увага: файл {path:?} містить ВСІ паролі у відкритому вигляді. \
             На цій ОС стандартний open() не виставляє жорсткіших ACL — \
             збережіть файл у каталозі вашого профілю та видаліть його \
             після використання."
        );
    }
    Ok(0)
}

fn import(manager: &mut PasswordManager, path: &str, skip_duplicates: bool) -> Result<i32> {
    read_master_for_existing(manager)?;
    let n = manager.import_from_json(path, skip_duplicates)?;
    if skip_duplicates {
        println!("Імпортовано {n} нових акаунтів (дублікати пропущено).");
    } else {
        println!("Імпортовано {n} нових акаунтів.");
    }
    Ok(0)
}

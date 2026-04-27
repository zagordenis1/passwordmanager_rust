//! Interactive Ukrainian-language menu — bug-for-bug compatible with the
//! Python reference.
//!
//! The 11-item menu, the prompt strings, the auto-lock semantics, and the
//! Ctrl+C / Ctrl+D handling all match `password_manager/cli.py`.

use std::env;
use std::io::{self, BufRead, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::generator::{generate_password, PasswordPolicy, DEFAULT_LENGTH, MAX_LENGTH, MIN_LENGTH};
use crate::manager::{PasswordManager, UserRecord};

const MENU: &str = r#"
=== Password Manager ===
1)  Додати акаунт
2)  Знайти акаунт
3)  Показати всі акаунти
4)  Видалити акаунт
5)  Оновити пароль
6)  Експорт у JSON
7)  Імпорт з JSON
8)  Пошук по login/email
9)  Вихід
10) Змінити master password
11) Згенерувати пароль
"#;

const DEFAULT_AUTO_LOCK_SECONDS: u64 = 300;
const AUTO_LOCK_ENV_VAR: &str = "PM_AUTO_LOCK_SECONDS";

/// Items that don't touch the encrypted DB and therefore neither require
/// a fresh master password after an idle period nor reset the idle timer.
const NO_AUTH_ACTIONS: &[&str] = &["11"];

/// Internal sentinel: a user-driven abort (EOF / Ctrl+D) that should
/// unwind cleanly into a "До побачення." exit.
struct UserAbort;

fn read_auto_lock_seconds() -> u64 {
    match env::var(AUTO_LOCK_ENV_VAR) {
        Ok(v) => match v.trim().parse::<i64>() {
            Ok(n) if n >= 0 => n as u64,
            _ => DEFAULT_AUTO_LOCK_SECONDS,
        },
        Err(_) => DEFAULT_AUTO_LOCK_SECONDS,
    }
}

fn prompt_line(text: &str) -> Result<String, UserAbort> {
    print!("{}", text);
    io::stdout().flush().ok();
    let stdin = io::stdin();
    let mut line = String::new();
    match stdin.lock().read_line(&mut line) {
        Ok(0) => Err(UserAbort), // EOF
        Ok(_) => Ok(line.trim_end_matches(['\n', '\r']).trim().to_string()),
        Err(_) => Err(UserAbort),
    }
}

fn prompt_password(text: &str) -> Result<String, UserAbort> {
    // `rpassword::prompt_password` uses `/dev/tty` on Unix when stdin
    // isn't a TTY. We want stdin-based fallback for piped tests, so
    // detect non-TTY and fall back to a plain read_line.
    use std::io::IsTerminal;
    if io::stdin().is_terminal() {
        match rpassword::prompt_password(text) {
            Ok(s) => Ok(s),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Err(UserAbort),
            Err(_) => Err(UserAbort),
        }
    } else {
        // Non-TTY: read a single line, no echo control.
        print!("{}", text);
        io::stdout().flush().ok();
        let stdin = io::stdin();
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) => Err(UserAbort),
            Ok(_) => Ok(line.trim_end_matches(['\n', '\r']).to_string()),
            Err(_) => Err(UserAbort),
        }
    }
}

fn print_record(rec: &UserRecord, index: Option<usize>) {
    let prefix = match index {
        Some(i) => format!("  [{}] ", i),
        None => "  ".to_string(),
    };
    println!(
        "{}id={} login={:?} email={:?} password={:?} created_at={}",
        prefix,
        rec.id,
        rec.login,
        rec.email.as_deref().unwrap_or(""),
        rec.password,
        rec.created_at,
    );
}

fn print_records(records: &[UserRecord]) {
    if records.is_empty() {
        println!("  (порожньо)");
        return;
    }
    for (i, r) in records.iter().enumerate() {
        print_record(r, Some(i + 1));
    }
}

fn setup_master(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    println!("Master password ще не задано. Створіть його зараз.");
    loop {
        let first = prompt_password("Новий master password: ")?;
        if first.is_empty() {
            println!("Master password не може бути порожнім.");
            continue;
        }
        let second = prompt_password("Підтвердіть master password: ")?;
        if first != second {
            println!("Не співпадає, спробуйте ще раз.");
            continue;
        }
        match manager.set_master_password(&first) {
            Ok(_) => {
                println!("Master password встановлено.");
                return Ok(());
            }
            Err(e) => {
                eprintln!("Помилка: {e:#}");
                return Ok(());
            }
        }
    }
}

fn login(manager: &mut PasswordManager, max_attempts: u32) -> Result<bool, UserAbort> {
    for attempt in 1..=max_attempts {
        let master = prompt_password("Master password: ")?;
        match manager.verify_master_password(&master) {
            Ok(true) => {
                if manager.is_legacy_kdf().unwrap_or(false) {
                    println!(
                        "Увага: ця БД використовує старий KDF (PBKDF2). \
                         Змініть master password (пункт 10) щоб мігрувати на \
                         Argon2id — нічого не доведеться вводити повторно."
                    );
                }
                return Ok(true);
            }
            Ok(false) => {
                let remaining = max_attempts - attempt;
                if remaining > 0 {
                    println!("Невірний пароль. Залишилось спроб: {remaining}.");
                }
            }
            Err(e) => {
                eprintln!("Несподівана помилка: {e:#}");
                return Ok(false);
            }
        }
    }
    println!("Перевищено кількість спроб.");
    Ok(false)
}

fn prompt_yesno(text: &str, default: bool) -> Result<bool, UserAbort> {
    let suffix = if default { " [Y/n]: " } else { " [y/N]: " };
    let raw = prompt_line(&format!("{text}{suffix}"))?.to_lowercase();
    if raw.is_empty() {
        return Ok(default);
    }
    Ok(matches!(raw.as_str(), "y" | "yes" | "т" | "так"))
}

fn interactive_generate() -> Result<Option<String>, UserAbort> {
    let raw_len = prompt_line(&format!("Довжина [{}]: ", DEFAULT_LENGTH))?;
    let length_str = if raw_len.is_empty() {
        DEFAULT_LENGTH.to_string()
    } else {
        raw_len.clone()
    };
    let length = match length_str.parse::<usize>() {
        Ok(n) => n,
        Err(_) => {
            println!("Невірна довжина: {raw_len:?}.");
            return Ok(None);
        }
    };

    let policy = PasswordPolicy {
        length,
        use_lower: prompt_yesno("Нижній регістр (a-z)?", true)?,
        use_upper: prompt_yesno("Верхній регістр (A-Z)?", true)?,
        use_digits: prompt_yesno("Цифри (0-9)?", true)?,
        use_symbols: prompt_yesno("Символи (!@#…)?", true)?,
        ..Default::default()
    };

    match generate_password(&policy) {
        Ok(pw) => {
            println!("Згенеровано: {pw}");
            Ok(Some(pw))
        }
        Err(e) => {
            println!("Помилка генератора: {e}");
            println!(
                "Підказка: довжина від {MIN_LENGTH} до {MAX_LENGTH}, хоча б один клас включений."
            );
            Ok(None)
        }
    }
}

fn prompt_password_or_generate(text: &str) -> Result<String, UserAbort> {
    loop {
        let raw = prompt_password(text)?;
        if raw == "g" {
            if let Some(pw) = interactive_generate()? {
                return Ok(pw);
            }
            continue;
        }
        if raw.is_empty() {
            println!("Password не може бути порожнім (або введіть 'g' — згенерувати).");
            continue;
        }
        return Ok(raw);
    }
}

fn add_account(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    let login = prompt_line("Login: ")?;
    if login.is_empty() {
        println!("Login обов'язковий.");
        return Ok(());
    }
    let email = prompt_line("Email: ")?;
    let password = prompt_password_or_generate("Password (або 'g' щоб згенерувати): ")?;
    match manager.create_user(&login, &email, &password) {
        Ok(rec) => {
            println!("Створено:");
            print_record(&rec, None);
        }
        Err(e) => println!("Помилка: {e}"),
    }
    Ok(())
}

fn find_account(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    let login = prompt_line("Login для пошуку: ")?;
    match manager.get_user(&login) {
        Ok(None) => println!("Не знайдено."),
        Ok(Some(r)) => print_record(&r, None),
        Err(e) => eprintln!("Несподівана помилка: {e:#}"),
    }
    Ok(())
}

fn list_accounts(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    match manager.list_users() {
        Ok(rs) => print_records(&rs),
        Err(e) => eprintln!("Несподівана помилка: {e:#}"),
    }
    Ok(())
}

fn delete_account(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    let login = prompt_line("Login для видалення: ")?;
    if login.is_empty() {
        println!("Login обов'язковий.");
        return Ok(());
    }
    match manager.get_user(&login) {
        Ok(None) => {
            println!("Не знайдено.");
            return Ok(());
        }
        Err(e) => {
            eprintln!("Несподівана помилка: {e:#}");
            return Ok(());
        }
        _ => {}
    }
    if !prompt_yesno(&format!("Видалити акаунт {:?}?", login), false)? {
        println!("Скасовано.");
        return Ok(());
    }
    match manager.delete_user(&login) {
        Ok(true) => println!("Видалено."),
        Ok(false) => println!("Не знайдено."),
        Err(e) => eprintln!("Несподівана помилка: {e:#}"),
    }
    Ok(())
}

fn update_password_action(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    let login = prompt_line("Login: ")?;
    match manager.get_user(&login) {
        Ok(None) => {
            println!("Не знайдено.");
            return Ok(());
        }
        Err(e) => {
            eprintln!("Несподівана помилка: {e:#}");
            return Ok(());
        }
        _ => {}
    }
    let new_password = prompt_password_or_generate("Новий password (або 'g' щоб згенерувати): ")?;
    match manager.update_password(&login, &new_password) {
        Ok(true) => println!("Оновлено."),
        Ok(false) => println!("Не вдалося оновити (можливо, акаунт видалений)."),
        Err(e) => eprintln!("Несподівана помилка: {e:#}"),
    }
    Ok(())
}

fn export_json(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    let raw = prompt_line("Шлях до файлу експорту [export.json]: ")?;
    let path = if raw.is_empty() {
        "export.json".to_string()
    } else {
        raw
    };
    match manager.export_to_json(&path) {
        Ok(n) => {
            println!("Експортовано {n} акаунтів у {path}.");
            println!(
                "Увага: файл містить ВСІ паролі у відкритому вигляді. \
                 На Unix його створено з режимом 0600 (тільки власник). \
                 Видаліть його після використання."
            );
        }
        Err(e) => println!("Помилка експорту: {e}"),
    }
    Ok(())
}

fn import_json(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    let path = prompt_line("Шлях до файлу імпорту: ")?;
    if path.is_empty() {
        println!("Шлях обов'язковий.");
        return Ok(());
    }
    match manager.import_from_json(&path, true) {
        Ok(n) => println!("Імпортовано {n} нових акаунтів (дублікати пропущено)."),
        Err(e) => println!("Помилка імпорту: {e}"),
    }
    Ok(())
}

fn search_action(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    let q = prompt_line("Пошуковий запит: ")?;
    if q.is_empty() {
        println!("Запит обов'язковий.");
        return Ok(());
    }
    match manager.search(&q) {
        Ok(rs) => print_records(&rs),
        Err(e) => eprintln!("Несподівана помилка: {e:#}"),
    }
    Ok(())
}

fn change_master(manager: &mut PasswordManager) -> Result<(), UserAbort> {
    let old = prompt_password("Поточний master password: ")?;
    let new = loop {
        let n = prompt_password("Новий master password: ")?;
        if n.is_empty() {
            println!("Новий master password не може бути порожнім.");
            return Ok(());
        }
        let confirm = prompt_password("Підтвердіть новий master password: ")?;
        if n != confirm {
            println!("Не співпадає, спробуйте ще раз.");
            continue;
        }
        break n;
    };
    match manager.change_master_password(&old, &new) {
        Ok(count) => {
            println!("Master password змінено. Перешифровано {count} акаунтів під новим ключем.")
        }
        Err(e) => println!("Помилка: {e}"),
    }
    Ok(())
}

fn generate_action(_manager: &mut PasswordManager) -> Result<(), UserAbort> {
    let _ = interactive_generate()?;
    Ok(())
}

/// Pure idle-window predicate: `true` iff the session is still considered
/// active and the caller does NOT need to re-authenticate.
///
/// `timeout_secs == 0` disables auto-lock entirely. Otherwise we use a
/// strict `<` against `Duration::from_secs(timeout_secs)` so the boundary
/// case (exactly `timeout_secs` elapsed) locks, matching the README's
/// "Lock after this many seconds of inactivity" wording.
fn within_idle_window(elapsed: Duration, timeout_secs: u64) -> bool {
    timeout_secs == 0 || elapsed < Duration::from_secs(timeout_secs)
}

fn ensure_unlocked(
    manager: &mut PasswordManager,
    last_activity: Instant,
    timeout_secs: u64,
    now: Instant,
) -> Result<bool, UserAbort> {
    if within_idle_window(now.duration_since(last_activity), timeout_secs) {
        return Ok(true);
    }
    manager.lock();
    println!(
        "\nСесію заблоковано через бездіяльність (>{timeout_secs} с). Введіть master password."
    );
    login(manager, 5)
}

/// Run the interactive menu. `db_path` is passed straight to
/// [`PasswordManager::new`].
pub fn run(db_path: &str) -> Result<i32> {
    let mut manager = PasswordManager::new(db_path).context("opening manager")?;
    let timeout_secs = read_auto_lock_seconds();

    // Inner closure so the EOF / Ctrl+D path can short-circuit cleanly.
    let mut inner = || -> Result<i32, UserAbort> {
        if !manager.has_master_password().unwrap_or(false) {
            setup_master(&mut manager)?;
        } else if !login(&mut manager, 5)? {
            return Ok(1);
        }

        let mut last_activity = Instant::now();
        loop {
            print!("{}", MENU);
            io::stdout().flush().ok();
            let choice = prompt_line("Виберіть пункт: ")?;
            if choice == "9" {
                println!("До побачення.");
                return Ok(0);
            }

            type Action = fn(&mut PasswordManager) -> Result<(), UserAbort>;
            let action: Option<Action> = match choice.as_str() {
                "1" => Some(add_account),
                "2" => Some(find_account),
                "3" => Some(list_accounts),
                "4" => Some(delete_account),
                "5" => Some(update_password_action),
                "6" => Some(export_json),
                "7" => Some(import_json),
                "8" => Some(search_action),
                "10" => Some(change_master),
                "11" => Some(generate_action),
                _ => None,
            };
            let Some(action) = action else {
                println!("Невірний пункт меню.");
                continue;
            };

            let no_auth = NO_AUTH_ACTIONS.contains(&choice.as_str());
            if !no_auth
                && !ensure_unlocked(&mut manager, last_activity, timeout_secs, Instant::now())?
            {
                return Ok(1);
            }

            // Inside-action UserAbort means Ctrl+D — abandon and continue.
            match action(&mut manager) {
                Ok(_) => {}
                Err(UserAbort) => {
                    println!();
                }
            }

            if !no_auth {
                last_activity = Instant::now();
            }
        }
    };

    match inner() {
        Ok(code) => Ok(code),
        Err(UserAbort) => {
            println!("\nДо побачення.");
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn within_idle_window_disabled_by_zero_timeout() {
        // Any elapsed value is fine when timeout is 0 (auto-lock off).
        assert!(within_idle_window(Duration::from_secs(0), 0));
        assert!(within_idle_window(Duration::from_secs(10_000), 0));
    }

    #[test]
    fn within_idle_window_strict_boundary() {
        // Exactly `timeout_secs` elapsed must lock (returns false).
        assert!(!within_idle_window(Duration::from_secs(300), 300));
        // One sub-second short of the boundary still active.
        assert!(within_idle_window(
            Duration::from_secs(299) + Duration::from_millis(999),
            300
        ));
        // Past boundary always locks.
        assert!(!within_idle_window(Duration::from_secs(301), 300));
    }
}

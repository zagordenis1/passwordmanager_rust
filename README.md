# `passwordmanagerrs` — Rust-порт [`passwordmanagerpy`](https://github.com/zagordenis/passwordmanagerpy)

**Мови:** **Українська** · [Русский](README.ru.md) · [English](README.en.md)

[![CI](https://github.com/zagordenis1/passwordmanager_rust/actions/workflows/ci.yml/badge.svg)](https://github.com/zagordenis1/passwordmanager_rust/actions/workflows/ci.yml)

Невеликий CLI-менеджер паролів, написаний на ідіоматичному Rust.
**Побайтово сумісний** з оригінальною Python-реалізацією: будь-яку
БД, створену однією зі сторін, можна відкрити іншою (за умови
збігу master-пароля). Базовий KDF — Argon2id; PBKDF2-SHA256
зберігається як read-only fallback для старих БД.

---

## Зміст

1. [Встановлення Rust](#встановлення-rust)
2. [Збірка та запуск](#збірка-та-запуск)
3. [Інтерактивне меню](#інтерактивне-меню)
4. [Не-інтерактивні підкоманди](#не-інтерактивні-підкоманди)
5. [Auto-lock (автоматичне блокування)](#auto-lock-автоматичне-блокування)
6. [Модель безпеки](#модель-безпеки)
7. [Архітектура](#архітектура)
8. [Тести](#тести)
9. [Реліз-бінарник](#реліз-бінарник)
10. [Міграція з Python-версії](#міграція-з-python-версії)
11. [Ліцензія](#ліцензія)

---

## Встановлення Rust

Якщо Rust ще не встановлено — найпростіший шлях через [rustup](https://rustup.rs/).

### Linux / macOS

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Перезавантажте shell або виконайте:
source "$HOME/.cargo/env"
rustc --version   # має бути 1.74 або новіше
```

### Windows

1. Завантажте `rustup-init.exe` зі сторінки https://rustup.rs/.
2. Запустіть, оберіть варіант `default host triple` (зазвичай `x86_64-pc-windows-msvc`).
3. Встановіть [Build Tools для Visual Studio](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (Microsoft C++ Build Tools) — потрібні для лінкера.
4. Перевірте у новій PowerShell-сесії: `rustc --version`.

### Системні залежності

Жодних — Rust-збірка статично лінкує SQLite (`rusqlite/bundled`) та
OpenSSL (`vendored`), тому окремі пакети `libssl` чи `libsqlite3` НЕ
потрібні. На Linux достатньо стандартного toolchain (`gcc`, `make`),
який зазвичай вже є.

---

## Збірка та запуск

### Клонування

```bash
git clone https://github.com/zagordenis1/passwordmanager_rust.git
cd passwordmanager_rust
```

### Збірка дебаг-версії (для розробки)

```bash
cargo build
./target/debug/pwm --help
```

### Збірка реліз-версії (швидка, ~7-10 МіБ)

```bash
cargo build --release
./target/release/pwm --help
```

На Windows бінарник буде у `target\release\pwm.exe`.

### Встановлення в `~/.cargo/bin` (щоб запускати як `pwm`)

```bash
cargo install --path .
pwm --help
```

> **Перевірте, що `~/.cargo/bin` у `$PATH`.** На macOS / Linux Bash
> або Zsh додасть це автоматично після інсталяції rustup; якщо ні —
> додайте `export PATH="$HOME/.cargo/bin:$PATH"` у `~/.bashrc` /
> `~/.zshrc`.

### Перший запуск

```bash
# Створює users.db у поточній теці й запитує master-пароль
pwm

# Або одразу через підкоманду:
pwm init
```

Шлях до БД можна перевизначити:

```bash
pwm --db /home/user/.local/share/pwm/users.db
pwm --db ./test.db init
```

---

## Інтерактивне меню

Запуск без підкоманди відкриває 11-пунктове меню (точна копія
Python-версії, українською):

```
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
```

Master-пароль вводиться один раз на сесію. Після `PM_AUTO_LOCK_SECONDS`
секунд бездіяльності сесія блокується й треба автентифікуватися
повторно.

---

## Не-інтерактивні підкоманди

Зручно для скриптів і pipe-композиції:

| Команда                       | Що робить                                                          |
|-------------------------------|--------------------------------------------------------------------|
| *(без підкоманди)*            | Інтерактивне меню (11 пунктів, українською).                       |
| `pwm init`                    | Перше налаштування master-пароля на свіжій БД.                     |
| `pwm add --login <name>`      | Додати акаунт. Пароль через прихований prompt або `--stdin`.       |
| `pwm get <login>`             | Вивести пароль у stdout (`--full` — весь запис).                   |
| `pwm list [--json]`           | Усі акаунти (з опцією JSON-виводу).                                |
| `pwm rm <login> [--force]`    | Видалити акаунт. `--force` пропускає y/N-підтвердження.            |
| `pwm update <login>`          | Замінити пароль для існуючого login.                               |
| `pwm change-master`           | Змінити master-пароль (атомарно перешифровує всі рядки).           |
| `pwm gen [--length N]`        | Згенерувати пароль і вивести у stdout.                             |
| `pwm search <query>`          | Підрядковий пошук по login + email.                                |
| `pwm export <path>`           | Експорт у JSON (UNIX: файл створюється з режимом `0600`).           |
| `pwm import <path>`           | Імпорт з JSON (дублікати пропускаються за замовчуванням).          |

### Приклади

```bash
# Додати акаунт, пароль читається із stdin (зручно для CI):
echo "supersecret" | pwm add --login alice --email alice@example.com --stdin

# Скопіювати пароль у буфер обміну (Linux, Wayland):
pwm get alice | wl-copy

# Скопіювати пароль у буфер обміну (macOS):
pwm get alice | pbcopy

# Згенерувати 32-символьний пароль із усіма класами:
pwm gen --length 32

# Згенерувати тільки літери + цифри (без символів):
pwm gen --length 24 --no-symbols

# Експорт + імпорт між двома БД:
pwm --db a.db export backup.json
pwm --db b.db import backup.json

# JSON-вивід для обробки jq:
pwm list --json | jq '.[] | .login'
```

### Прапорці

* `--db <шлях>` — глобальний прапорець для будь-якої підкоманди (за замовчуванням `users.db` у поточній теці).
* `--version` / `-V` — версія бінарника.
* `--help` / `-h` — довідка по будь-якій підкоманді (наприклад `pwm add --help`).

Master-пароль завжди читається через
[`rpassword`](https://docs.rs/rpassword) у TTY-режимі (без луни,
не зберігається в історії shell). У не-TTY режимі (pipe) — з одного
рядка stdin, тому `echo "pw" | pwm get foo` працює.

---

## Auto-lock (автоматичне блокування)

Інтерактивне меню має таймер бездіяльності, налаштовується через
`PM_AUTO_LOCK_SECONDS`:

| Значення   | Що означає                                                  |
|------------|-------------------------------------------------------------|
| не задано  | За замовчуванням 300 секунд (5 хвилин).                     |
| `0`        | Повністю вимкнути auto-lock.                                |
| додатне    | Блокувати після N секунд бездіяльності.                     |
| некоректне | Падає до значення за замовчуванням, ніколи не вимикає.      |

Пункти 9 (вихід) та 11 (генератор) позначені як `NO_AUTH_ACTIONS` —
вони НЕ скидають таймер бездіяльності й не вимагають повторної
автентифікації.

```bash
# Безперервна сесія без блокування:
PM_AUTO_LOCK_SECONDS=0 pwm

# Блокування після 60 секунд:
PM_AUTO_LOCK_SECONDS=60 pwm
```

> **Відоме обмеження.** Таймер перевіряється лише між діями
> користувача. Якщо ви залишили бінарник на промпті меню — ключ
> залишається в RAM до наступного натискання клавіші. Деталі у
> `docs/audit-2026-04.md` (M3).

---

## Модель безпеки

| Аспект                            | Як вирішується                                                                                                  |
|-----------------------------------|-----------------------------------------------------------------------------------------------------------------|
| Master-пароль у пам'яті           | Передається як `&str` лише на час потреби; на структурі менеджера не зберігається.                              |
| Похідний ключ KDF (base64-string) | Локальна копія `zeroize()`-ається відразу після створення Fernet.                                               |
| Активний ключ шифрування          | Зберігається в `Option<Fernet>`. Upstream-крейт `fernet` НЕ zeroize-ить — тому скидаємо через `lock()`.         |
| Базовий KDF                       | **Argon2id, m=19456 KiB, t=2, p=1, hash_len=32, salt=16 байт** (рекомендація OWASP 2024).                       |
| Legacy KDF (тільки читання)       | PBKDF2-HMAC-SHA256, 480 000 ітерацій.                                                                           |
| Шифрування                        | Fernet (AES-128-CBC + HMAC-SHA256), побайтово сумісне з Python `cryptography.fernet`.                            |
| Verifier (перевірка пароля)       | Шифрований відомий plaintext `b"password_manager:verifier:v1"`.                                                  |
| Атомарність master-setup          | `BEGIN IMMEDIATE` + recheck всередині транзакції — захист від паралельних `pwm init`.                           |
| Права на експортний файл          | `0600` (тільки власник) на Unix; виводиться попередження про plaintext-вміст.                                   |
| Durability SQLite                 | `journal_mode=WAL`, `synchronous=FULL`, `foreign_keys=ON`.                                                      |
| Auto-lock                         | Таймер бездіяльності в інтерактивному меню (див. вище).                                                          |
| Логування                         | `Debug` redact-ить секрети; master / ключ / plaintext не логуються ніде.                                         |
| `unsafe`                          | Жодного.                                                                                                         |
| `unwrap` / `expect` у проді       | Жодного — лише в тестах.                                                                                         |

### Threat model

**У scope:**

* Викрадена `users.db` без master-пароля → атакуючому доведеться зламувати Argon2id з OWASP-параметрами.
* Випадкові свопи / coredump-и → master і базовий ключ обнулюються (наскільки дозволяє upstream `fernet`).
* Конкурентний запуск `pwm init` → транзакція з reserved-локом не дасть зіпсувати БД.
* Експортний JSON у спільній теці на Unix → mode `0600` блокує сторонніх читачів.

**Поза scope** (захищайтеся засобами ОС):

* Дамп пам'яті привілейованим атакуючим на запущеному процесі.
* Скомпрометований компілятор / supply chain (`cargo audit` допомагає, але не повністю).
* Кейлогери / shoulder surfing.

Повний аудит — `docs/audit-2026-04.md`.

---

## Архітектура

```
src/
├── lib.rs           # Library re-exports (бінарник + тести)
├── main.rs          # Точка входу `pwm`
├── crypto.rs        # Argon2id + PBKDF2 + Fernet helpers + verifier
├── db.rs            # SQLite-схема та meta-аксесори
├── manager.rs       # `PasswordManager`: lock/unlock/CRUD lifecycle
├── generator.rs     # Генератор паролів на CSPRNG
└── cli/
    ├── mod.rs          # Парсер `clap` + диспетчер
    ├── interactive.rs  # 11-пунктове українське меню
    └── commands.rs     # Не-інтерактивні підкоманди

tests/
├── manager_tests.rs       # Інтеграційні тести публічного API
├── e2e_cli.rs             # Реальний бінарник через `assert_cmd`
├── auto_lock.rs           # Семантика auto-lock
└── cross_compat_python.rs # Відкриваємо Python-БД і навпаки
```

---

## Тести

```bash
cargo test                       # Усі тести
cargo test --lib                 # Тільки unit-тести
cargo test --test e2e_cli        # Тільки CLI e2e
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

`cross_compat_python` пропускається, якщо `python3` відсутній у `$PATH`
або якщо `cryptography` / `argon2-cffi` неможливо імпортувати. У CI
вони встановлюються, тому suite виконується безумовно.

Загалом 56 тестів: 38 unit + 3 інтеграційні + 10 e2e + 2 auto-lock + 3
cross-compat.

---

## Реліз-бінарник

```bash
cargo build --release
ls -lh target/release/pwm        # Linux / macOS
dir target\release\pwm.exe       # Windows (PowerShell)
```

Профіль `release` в `Cargo.toml` застосовує `lto = "thin"`,
`codegen-units = 1`, `strip = true` — отриманий статичний бінарник на
x86_64 Linux менший за 10 МіБ (типово 7-8 МіБ).

---

## Міграція з Python-версії

Дивись [`MIGRATION.md`](MIGRATION.md). Коротко: скопіюйте свій
`users.db` туди, де запускається Rust-бінарник — нічого
перешифровувати не треба.

```bash
cp ~/old-python-pwm/users.db ./users.db
pwm list   # буде попередження про PBKDF2 → запустіть `pwm change-master` для міграції на Argon2id
```

---

## Ліцензія

MIT OR Apache-2.0.

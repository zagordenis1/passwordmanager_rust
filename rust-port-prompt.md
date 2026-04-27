# Промт: Порт password manager з Python на Rust

Скопіюй усе нижче у нову сесію Devin / Claude Code / Cursor як один промт.

---

## Контекст

У мене є робочий CLI-менеджер паролів на Python — https://github.com/zagordenis/passwordmanagerpy. Архітектурно він влаштований так:

- **Зберігання**: SQLite-файл `users.db` з двома таблицями — `users(id, login, email, password_enc, created_at)` (де `password_enc` — Fernet ciphertext) і `meta(key, value)` для master-related даних: `salt`, `verifier` (зашифрований відомий plaintext для перевірки master), `kdf_version`.
- **Crypto**:
  - **KDF**: Argon2id (m=19 MiB, t=2, p=1, hash_len=32 байти, salt=16 байт) → base64 → Fernet-ключ. Старі БД (без `kdf_version` row) використовують PBKDF2-HMAC-SHA256 з 480 000 ітерацій — це legacy fallback що його треба зберегти.
  - **Шифрування записів**: Fernet (AES-128-CBC + HMAC-SHA256, формат cryptography.io).
- **CLI**: інтерактивне Ukrainian-language меню `python main.py`, 11 пунктів (додати/знайти/показати/видалити/оновити/експорт-імпорт-JSON/пошук/вихід/змінити master/згенерувати пароль).
- **Auto-lock**: після `PM_AUTO_LOCK_SECONDS` секунд бездіяльності в меню — скидає ключ, при наступній дії питає master заново. Налаштовується через ENV.
- **Тести**: 64 unit-тести через `unittest`. CI на GitHub Actions (matrix Python 3.10/3.11/3.12 + ruff).

## Завдання

Перепиши цю програму на **Rust** з ідіоматичним кодом — НЕ роби 1:1 переклад. Мета — навчальний проєкт + production-quality CLI-утиліта яка дає той самий UX, але з memory-safety і single-static-binary дистрибуцією.

Створи у новому репо `passwordmanagerrs` (або у підкаталозі `rust/` поточного репо — спитай юзера що краще).

## Обов'язкові вимоги

### 1. Стек (фіксовано — не міняти без узгодження)

```toml
# Cargo.toml dependencies
clap = { version = "4", features = ["derive"] }       # CLI парсинг
rusqlite = { version = "0.31", features = ["bundled"] }  # SQLite (вбудований, без системної бібліотеки)
argon2 = "0.5"                                         # Argon2id KDF
fernet = "0.2"                                         # Cross-compatible з Python cryptography.fernet
pbkdf2 = { version = "0.12", features = ["simple"] }   # Тільки для legacy verify
hmac = "0.12"                                          # для PBKDF2
sha2 = "0.10"
rpassword = "7"                                        # Hidden password input у TTY
zeroize = { version = "1", features = ["derive"] }     # Очистка master password з RAM
anyhow = "1"                                           # Application-level errors
thiserror = "1"                                        # Library errors
rand = "0.8"                                           # Salt + password generator
secrecy = "0.8"                                        # Wrapping master password type

[dev-dependencies]
tempfile = "3"
assert_cmd = "2"                                       # E2E тести через справжній бінарник
predicates = "3"
```

### 2. Crypto compatibility — КРИТИЧНО

Rust-версія МАЄ бути здатна **відкривати БД створену Python-версією** (і навпаки), якщо master password той самий. Це доводить що ти зробив crypto правильно.

- **Fernet**: крейт `fernet` (https://docs.rs/fernet) використовує той самий формат як Python `cryptography`. API: `Fernet::new(&key).decrypt(token)` / `.encrypt(plaintext)`.
- **Argon2id**: крейт `argon2` з параметрами `m_cost=19456, t_cost=2, p_cost=1, output_len=Some(32)`. Викликати через `Argon2::new_with_secret` або `Argon2::hash_password_into` (low-level). Salt 16 байт, raw output 32 байти → `base64::URL_SAFE` (з padding) → Fernet key.
- **PBKDF2 legacy**: `pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, 480_000, &mut key)` → перші 32 байти → base64 url-safe → Fernet key.
- **Verifier**: рядок `b"password_manager:verifier:v1"`, зашифрований master-ключем. На login робимо `Fernet::decrypt(verifier)` — якщо успіх, ключ вірний.

**Adversarial-тест compatibility**: створи `tests/cross_compat.rs` який бере БД створену Python-версією (використай Python як `subprocess` у `build.rs` або просто закомить готовий `.db` як test fixture) і відкриває її Rust-кодом. Без цього тесту ти не маєш доказу що порт правильний.

### 3. Структура проєкту

```
src/
├── main.rs           # CLI entry + clap subcommands
├── crypto.rs         # KDF, Fernet helpers, verifier
├── db.rs             # rusqlite connection, schema, get_meta/set_meta
├── manager.rs        # PasswordManager struct (lock/unlock/CRUD)
├── cli/
│   ├── mod.rs        # Інтерактивне меню (як у Python)
│   ├── interactive.rs  # 11 пунктів + auto-lock
│   └── commands.rs   # Non-interactive subcommands (clap-based)
├── generator.rs      # secure password generator
└── lib.rs            # re-exports для тестів

tests/
├── crypto_tests.rs
├── manager_tests.rs
├── cross_compat_python.rs   # Open Python-created DB
└── e2e_cli.rs               # assert_cmd проти справжнього бінарника
```

### 4. Memory safety / secrets handling

Python тут "халтурний" — master password лежить як `str` у GC-керованій пам'яті, ключ Fernet — `bytes`. Rust має зробити це правильно:

- Master password обгорнути у `secrecy::SecretString` — це гарантує що `Drop` зробить `zeroize` буфера.
- Fernet-ключ після деривації — `secrecy::SecretVec<u8>`.
- Salt і verifier — звичайні `Vec<u8>` (не secret).
- Структура `Manager` має `Option<SecretBox<Fernet>>` для unlocked-стану. `lock()` робить `self.fernet = None` → `Drop` зачищає ключ.
- НЕ логувати ні master, ні derived key, ні plaintext паролі. `Debug` impl має redact-ити чутливі поля.

### 5. CLI — два режими

#### Інтерактивний (бекворд-сумісний з Python-версією)

`pwm` без аргументів → той самий менеджер що у Python (Ukrainian prompts, 11 пунктів, auto-lock, той самий UX). Точно копіювати тексти промптів — це доведе що порт справжній:

- `Master password: `
- `Новий master password: ` / `Підтвердіть master password: `
- `Виберіть пункт: `
- `Видалити акаунт 'X'? [y/N]: `
- `Сесію заблоковано через бездіяльність (>N с)`
- `Увага: ця БД використовує старий KDF (PBKDF2). ...`
- `До побачення.` (на пункт 9 / Ctrl+D)
- `Перервано.` (на Ctrl+C)
- `Перешифровано N акаунтів під новим ключем.`

#### Non-interactive (нова можливість, чого Python-версія не має)

Через `clap`:

```bash
pwm init                                  # Створити master password
pwm add --login alice --email a@x.com     # Pwd через stdin або prompt
pwm get alice                             # → друкує password у stdout
pwm get alice --copy                      # → у clipboard через arboard
pwm list [--json]                         # JSON для скриптингу
pwm rm alice [--force]                    # Без підтвердження якщо --force
pwm change-master                         # Інтерактивно
pwm gen [--length 20] [--no-symbols]      # → пароль у stdout
pwm export users.json
pwm import users.json
```

Master password питати через `rpassword::read_password()` (НЕ через clap arg — щоб не лишався у history).

### 6. Auto-lock

Через `tokio::time::Instant` або `std::time::Instant` (sync OK — менеджер однопотоковий). ENV-var `PM_AUTO_LOCK_SECONDS` (default 300, `0` вимикає). Точно та сама поведінка що у Python:
- Пункти 9 (вихід) і 11 (генератор) — `NO_AUTH_ACTIONS`, не скидають таймер і не вимагають re-auth.
- Усе інше — gate перед виконанням.

### 7. Тести

Мінімум:
- **Unit**: 30+ тестів покриваючих crypto (Argon2id round-trip, PBKDF2 round-trip, Fernet encrypt/decrypt, salt generation), manager (lock/unlock, CRUD, change_master, migrate KDF), generator (length, classes, no-empty-symbols).
- **Cross-compat**: відкрити Python-створену БД Rust-кодом (як описано вище).
- **E2E через `assert_cmd`**: запускати справжній бінарник, надсилати stdin, перевіряти stdout/exit code. Покрити: setup master, add user, list, change master, exit on Ctrl+D.
- **CI**: GitHub Actions matrix Linux + macOS + Windows, `cargo test`, `cargo clippy -- -D warnings`, `cargo fmt --check`.

### 8. Документація

- `README.md` — quickstart, build, install, security model, KDF параметри, threat model.
- `MIGRATION.md` — як переїхати з Python-версії (просто скопіюй `users.db`).
- Doc-коментарі (`///`) на кожному pub item з прикладами.

## Чого НЕ робити

- ❌ Не вмикай `unsafe` blocks без явного обґрунтування у коментарі.
- ❌ Не використовуй `unwrap()` / `expect()` у production paths — лише `?` + `anyhow::Result` / `thiserror`.
- ❌ Не друкуй master password у логах / повідомленнях про помилку.
- ❌ Не міняй Argon2id параметри (m=19456, t=2, p=1) — інакше зламається cross-compat з Python.
- ❌ Не прибирай PBKDF2 legacy шлях — він потрібен щоб старі БД відкривалися.
- ❌ Не пиши свою crypto. Тільки `argon2`, `fernet`, `pbkdf2` крейти.
- ❌ Не використовуй `String` для master password — тільки `SecretString`.

## Послідовність роботи

1. **Setup**: `cargo new passwordmanagerrs`, додай deps, створи скелет модулів. Push pre-PR як WIP.
2. **Crypto layer**: `crypto.rs` — `derive_key_argon2id`, `derive_key_pbkdf2_legacy`, `make_verifier`, `check_verifier`. Тести: round-trip + golden-vector проти Python (запиши вектори зі справжнього `python -c "from password_manager import crypto; print(crypto.derive_key('m', b'\\x00'*16).hex())"`).
3. **DB layer**: `db.rs` — `init_db`, `get_meta`, `set_meta`, CRUD для users. Тести з `tempfile`.
4. **Manager**: `manager.rs` — `PasswordManager::new/set_master/verify_master/create_user/get_user/list/delete/update_password/change_master_password/lock/is_legacy_kdf`. Тести.
5. **CLI interactive**: `cli/interactive.rs` — порти Python-меню 1:1 з тими ж промптами. E2E через `assert_cmd`.
6. **CLI non-interactive**: `cli/commands.rs` — clap subcommands. Тести.
7. **Cross-compat**: створи Python-БД через subprocess і відкрий Rust-кодом.
8. **CI**: `.github/workflows/ci.yml`.
9. **PR**: один великий PR (бо це новий репо), або серія невеликих PR-ів якщо у підкаталозі поточного.

## Acceptance criteria

Я вважаю порт готовим коли:

- [ ] `cargo build --release` дає один статичний бінарник `pwm` < 10 MiB.
- [ ] `cargo test` — всі тести зелені на 3 OS.
- [ ] `cargo clippy -- -D warnings` — clean.
- [ ] Cross-compat тест: БД створена Python-версією успішно відкривається Rust-версією, паролі читаються правильно. І навпаки.
- [ ] E2E тест на 11 пунктів інтерактивного меню — той самий UX як у Python.
- [ ] Non-interactive `pwm get alice` працює, master password читається через `rpassword`.
- [ ] Ctrl+C / Ctrl+D обробляються чисто (exit 0, без panic).
- [ ] Auto-lock працює (тест зі скриптованим часом).
- [ ] README.md описує security model і параметри Argon2id.

## Питання які треба підтвердити перед стартом

Спитай мене перед початком:

1. **Новий репо чи підкаталог?** (`passwordmanagerrs` як standalone vs `rust/` усередині поточного)
2. **Бренд-нейм бінарника?** (`pwm`, `pmr`, або щось інше?)
3. **Подвійна сумісність?** Так/ні — чи Rust-БД повинна бути читаною з Python-версії (треба для no-lock-in) чи Rust-only (простіше).
4. **Який мінімальний MSRV (Minimum Supported Rust Version)?** За замовч. — стабільна версія на момент старту.

Після цього починай зі скелета і йди по послідовності. Кожен крок — окремий commit з тестами.

# `passwordmanagerrs` — Rust port of [`passwordmanagerpy`](https://github.com/zagordenis/passwordmanagerpy)

[![CI](https://github.com/zagordenis1/passwordmanager_rust/actions/workflows/ci.yml/badge.svg)](https://github.com/zagordenis1/passwordmanager_rust/actions/workflows/ci.yml)

A small CLI password manager written in idiomatic Rust. It is
**byte-compatible** with the original Python implementation: any database
written by either side is readable by the other when the master password
is the same. The default KDF is Argon2id; PBKDF2-SHA256 is preserved as
a read-only legacy fallback for old DBs.

## Quickstart

```bash
# Build the static `pwm` binary (single executable, no system deps).
cargo build --release

# Interactive Ukrainian-language menu — exact UX of the Python original.
./target/release/pwm

# …or use one of the non-interactive subcommands (great for scripts).
./target/release/pwm init
./target/release/pwm add --login alice --email a@example.com
./target/release/pwm get alice
./target/release/pwm list --json
./target/release/pwm gen --length 32
./target/release/pwm change-master
./target/release/pwm export users.json
```

The binary auto-creates `users.db` in the current working directory by
default. Override with `--db /path/to/users.db` (also works inside the
interactive mode).

## Subcommands

| Command                   | What it does                                                        |
|---------------------------|---------------------------------------------------------------------|
| *(no subcommand)*         | Launch the interactive Ukrainian-language menu (11 items).          |
| `pwm init`                | One-time master-password setup on a fresh DB.                       |
| `pwm add --login <name>`  | Add an account. Password via hidden prompt or `--stdin`.            |
| `pwm get <login>`         | Print the password to stdout (`--full` for the whole record).       |
| `pwm list [--json]`       | Print all accounts, optionally as JSON.                             |
| `pwm rm <login> [--force]`| Delete an account. `--force` skips the y/N prompt.                  |
| `pwm update <login>`      | Replace the password for an existing login.                         |
| `pwm change-master`       | Change the master password (re-encrypts every row atomically).      |
| `pwm gen [--length N]`    | Print a fresh password to stdout.                                   |
| `pwm search <query>`      | Substring search over login + email.                                |
| `pwm export <path>`       | Export all decrypted accounts to a JSON file.                       |
| `pwm import <path>`       | Import accounts from a JSON file (skips duplicates).                |

Master passwords are always read with [`rpassword`](https://docs.rs/rpassword)
in TTY mode (no echo, never persisted in shell history) and from a
single stdin line in non-TTY mode (so `echo "pw" | pwm get foo` works
in scripts and tests).

## Auto-lock

The interactive menu enforces an idle timeout. Configure it via
`PM_AUTO_LOCK_SECONDS`:

| Value     | Meaning                                                  |
|-----------|----------------------------------------------------------|
| unset     | Default: 300 seconds (5 minutes).                        |
| `0`       | Disable auto-lock entirely.                              |
| positive  | Lock after this many seconds of inactivity.              |
| invalid   | Falls back to the default — never silently disables.     |

Items 9 (вихід) and 11 (генератор) are flagged `NO_AUTH_ACTIONS` and
neither reset the idle timer nor require re-authentication.

## Security model

| Concern                     | What this project does                                             |
|-----------------------------|--------------------------------------------------------------------|
| Master password in memory   | Wrapped in `secrecy::SecretString` → zeroized on `Drop`.           |
| Derived Fernet key          | Wrapped in `secrecy::SecretString` → zeroized on `Drop`.           |
| Default KDF                 | **Argon2id, m=19456 KiB, t=2, p=1, hash_len=32, salt=16 bytes**.   |
| Legacy KDF (read-only)      | PBKDF2-HMAC-SHA256, 480 000 iterations.                            |
| Encryption                  | Fernet (AES-128-CBC + HMAC-SHA256), via `cryptography.io`-format.  |
| Verifier                    | `b"password_manager:verifier:v1"` encrypted with the master key.   |
| Auto-lock                   | Idle timer in the interactive menu (see above).                    |
| Logging                     | `Debug` impls redact secrets; no master / key / plaintext logged.  |
| `unsafe` blocks             | None.                                                              |
| `unwrap` / `expect` in prod | None — only in tests.                                              |

### Threat model

In scope:

* Stolen `users.db` file with no master password → attacker faces
  Argon2id with OWASP-recommended cost (memory-hard).
* Casual swapfile / coredump scraping → master and key are zeroized.

Out of scope (use OS-level controls instead):

* Memory dumps from a privileged attacker on a running process.
* Compromised compiler / dependency supply chain (`cargo audit` is your
  friend, but no project of this size can mitigate it alone).
* Keystroke loggers / shoulder surfing.

## Architecture

```
src/
├── lib.rs           # Library re-exports (used by both bin and tests)
├── main.rs          # `pwm` binary entry point
├── crypto.rs        # Argon2id + PBKDF2 + Fernet helpers + verifier
├── db.rs            # SQLite schema and `meta` accessors
├── manager.rs       # `PasswordManager`: lock/unlock/CRUD lifecycle
├── generator.rs     # CSPRNG-based password generator
└── cli/
    ├── mod.rs          # `clap` parser + dispatcher
    ├── interactive.rs  # 11-item Ukrainian menu (Python-compatible)
    └── commands.rs     # Non-interactive subcommands

tests/
├── manager_tests.rs       # Public API integration tests
├── e2e_cli.rs             # Real binary via `assert_cmd`
├── auto_lock.rs           # Auto-lock semantics
└── cross_compat_python.rs # Open Python-created DB & vice versa
```

## Tests

```bash
cargo test                # Unit + integration + e2e + cross-compat
cargo clippy -- -D warnings
cargo fmt --check
```

The `cross_compat_python` suite is silently skipped when `python3` is not
on `$PATH` or when `cryptography` / `argon2-cffi` are not importable. CI
installs them so the suite runs there unconditionally.

## Building a release binary

```bash
cargo build --release
ls -lh target/release/pwm
```

`cargo`'s release profile applies `lto = "thin"`, `codegen-units = 1`,
and `strip = true`, producing a single static binary under 10 MiB on
x86_64 Linux.

## Migrating from the Python version

See [`MIGRATION.md`](MIGRATION.md) — the short answer is "copy your
`users.db` to wherever the Rust binary runs, no re-encryption needed".

## License

Dual-licensed under MIT or Apache-2.0, at your option.

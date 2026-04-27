# Migrating from `passwordmanagerpy` to `passwordmanagerrs`

The Rust port is **byte-compatible** with the Python reference at the
SQLite + crypto layer:

* Same schema (`meta`, `users`, `idx_users_email`).
* Same KDF (Argon2id, parameters `m=19456 KiB, t=2, p=1, hash_len=32`).
* Same legacy KDF (PBKDF2-HMAC-SHA256, 480 000 iterations).
* Same Fernet token format (the `cryptography.io` flavour).
* Same `meta` keys: `salt`, `verifier`, `kdf_version`.
* Same verifier plaintext: `b"password_manager:verifier:v1"`.

This means you can copy your existing `users.db` straight into the new
binary. **No re-encryption is required.**

## TL;DR

```bash
# Wherever your Python users.db currently lives:
cp users.db /path/to/rust/build/dir/users.db

# Now use the Rust binary the same way you used Python:
./pwm                      # interactive menu
./pwm get alice            # non-interactive
```

## Step-by-step

1. **Locate your existing DB.** The Python project defaulted to
   `./users.db`; the Rust port defaults to the same.

2. **Confirm it's not corrupted.** Sanity check with the Python tool one
   last time:

   ```bash
   python -m unittest discover -s tests -v   # Python project
   ```

3. **Copy or symlink it next to the Rust binary** (or pass `--db`):

   ```bash
   ./pwm --db /old/path/users.db
   ```

4. **Confirm it opens.** The Rust binary will accept the same master
   password the Python version did. If you had a *legacy* (pre-Argon2)
   database you'll also see this nudge:

   ```
   Увага: ця БД використовує старий KDF (PBKDF2). Змініть master
   password (пункт 10) щоб мігрувати на Argon2id — нічого не доведеться
   вводити повторно.
   ```

5. **(Optional) Migrate to Argon2id.** Pick **menu item 10** ("Змінити
   master password") and enter the same password you already use. The
   Rust port re-encrypts every row under a fresh Argon2id-derived key,
   atomically (single SQLite transaction). After that point you have a
   modern KDF on disk.

   The non-interactive equivalent is `./pwm change-master`.

## Going the other way

The same DB file works with the Python project too. Either side can read
the other's writes as long as the master password matches.

## What changes

* The Rust binary is a single statically linked executable (~few MiB).
  No Python interpreter, no `pip install`.
* Master passwords are zeroized on drop (`secrecy::SecretString`). Python
  could not provide that guarantee.
* Non-interactive subcommands (`pwm get`, `pwm list --json`, etc.) make
  scripting much friendlier than `expect` against the Python TUI.

## What does **not** change

* The interactive menu still has the same 11 Ukrainian items.
* The same Argon2id parameters and the same legacy PBKDF2 fallback.
* `PM_AUTO_LOCK_SECONDS` works exactly the same way.
* DB schema and on-disk format are identical.

## Verifying the cross-compat claim yourself

`tests/cross_compat_python.rs` is the ground-truth: a CI job that creates
a DB with the Python `cryptography` + `argon2-cffi` libraries and reads
it with the Rust binary, then does the inverse. Run it locally with:

```bash
pip install cryptography argon2-cffi
cargo test --test cross_compat_python
```

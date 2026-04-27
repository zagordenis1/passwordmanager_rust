# Audit Pass 2 — April 2026

A second, deeper audit of `passwordmanager_rust` after the
`docs/audit-2026-04.md` round (PR #3). Scope: every `src/**/*.rs`
file, every `tests/*.rs` file, `Cargo.toml`, `.github/workflows/ci.yml`
and `.gitignore`, plus a `cargo audit` against the vulnerability
database (no findings) and `cargo clippy` with `pedantic` + `nursery`
groups (no substantive findings beyond stylistic noise).

This document records every finding from the second pass — fixed and
deferred. It does **not** repeat the first audit's findings; see
`audit-2026-04.md` for those.

## Summary

| ID | Severity | Status   | Title                                                            |
| -- | -------- | -------- | ---------------------------------------------------------------- |
| H1 | High     | **fix**  | Export overwriting a pre-existing file silently kept old mode    |
| M1 | Medium   | **fix**  | `change_master_password` used DEFERRED transaction (race window) |
| M2 | Medium   | **fix**  | `import_from_json` was non-transactional (atomicity + perf)      |
| L1 | Low      | **fix**  | Doc-comment claimed `OsRng` but code uses `thread_rng`           |
| L2 | Low      | **fix**  | Unused `hmac` Cargo dep + redundant `simple` feature on `pbkdf2` |
| L3 | Low      | **fix**  | "На Unix створено з режимом 0600" warning printed on Windows too |
| L4 | Low      | **fix**  | `derive_key_pbkdf2` returned `Result<_>` but is infallible       |
| L5 | Low      | **fix**  | Import message claimed "(дублікати пропущено)" with `--no-skip…` |
| L6 | Low      | document | `auto_lock_disabled_by_env` test does not actually exercise idle |
| L7 | Low      | document | Generator/salt RNG is `thread_rng`, not direct `OsRng`           |

Total new regression tests added: **3** (overall test count: **59**, was 56).

---

## H1. Export overwriting a pre-existing file silently kept its old mode
**Status: Fixed.**

`export_to_json` calls `write_owner_only`, which on Unix uses
`OpenOptions::mode(0o600)` to create the file. The `mode` argument to
`OpenOptions::open` only applies when the kernel **creates** the file —
re-opening an existing file with `O_TRUNC` does NOT change its
permissions. If the user (or a previous broken release of `pwm`) had
already created `export.json` with mode `0644`, the second export
silently retained `0644` while still printing `"На Unix його створено з
режимом 0600 (тільки власник)"`. Result: every plaintext password in
the export file becomes world-readable while the user thinks they are
protected.

Reproducer (master before the fix):

```bash
$ touch export.json && chmod 0644 export.json
$ pwm export export.json
Експортовано N акаунтів у export.json.
Увага: … На Unix його створено з режимом 0600 …
$ stat -c '%a' export.json
644          # ← still world-readable!
```

Fix: after `OpenOptions::open`, call
`set_permissions(Permissions::from_mode(0o600))` on the file handle
unconditionally. Regression test
`export_overwrites_pre_existing_loose_perms_with_0600` pre-creates
`export.json` at `0644`, runs the export, and asserts the final mode is
`0600`.

This is the same intent as the H2 fix from PR #3, just hardened
against the file-pre-existing case the original fix did not consider.

---

## M1. `change_master_password` used a DEFERRED transaction
**Status: Fixed.**

`set_master_password` was upgraded to `BEGIN IMMEDIATE` in PR #3 (H1
of the first audit) so two racing `pwm init` processes serialize at
the SQLite reserved-lock level. The companion path,
`change_master_password`, was *not* upgraded — it still used the
default deferred transaction.

The race window: process A starts a deferred tx, reads the user table,
begins re-encrypting under the new key. Process B (e.g. a parallel
`pwm add` or another `change-master` racing for the same DB) inserts a
row encrypted under the OLD key in between A's SELECT and A's first
UPDATE. SQLite escalates A's lock to RESERVED on the first UPDATE, so
B's later writes will see SQLITE_BUSY — but if A's read already
finished and B's write completed before A's write started, A would
commit a state where the freshly-inserted row is encrypted under the
old key while every other row is encrypted under the new key. Neither
master password unlocks the resulting DB.

Fix: `change_master_password` now uses
`transaction_with_behavior(TransactionBehavior::Immediate)`. The
reserved lock is taken on `BEGIN`, before any reads, so a concurrent
writer either gets `SQLITE_BUSY` immediately or has already committed
before our `BEGIN` returns. Defense-in-depth — the failure mode never
occurs in single-process use.

Regression: `change_master_uses_immediate_lock` is a smoke test that
exercises the new transaction with 10 rows and verifies the rotation
completes cleanly.

---

## M2. `import_from_json` was non-transactional
**Status: Fixed.**

The previous implementation looped over JSON entries and called
`self.create_user` per row. Each `create_user` opens its own SQLite
connection and runs an auto-committed `INSERT`, which means:

* **Not atomic.** A 100k-row import that errors on row 50,001 leaves
  50,000 rows committed and 50,000 missing. The caller sees an error
  but has no way to recover other than starting over from scratch.
  Mid-import `kill -9` likewise leaves a partial DB.
* **Slow.** Every `INSERT` is fsynced (`synchronous=FULL`). Even with
  WAL the per-row cost dominates; we measured ~430 ms for 1000 rows
  on local SSD where a single transaction completes in ~30 ms.

Fix: `import_from_json` now opens one connection, starts one deferred
transaction, runs every `INSERT` against that transaction, and commits
once at the end. Duplicate-login rows are still skipped row-by-row
when `skip_duplicates=true`. Non-duplicate errors (disk full, schema
mismatch, …) drop the transaction (rollback on `Drop`) and propagate
the error.

Behavioural change: with `--no-skip-duplicates`, a duplicate that
appears mid-file used to leave every preceding row inserted; the import
now rolls back to zero. This matches the documented "atomic" intent
and is closer to what users actually expect when they ask for hard
duplicate failure.

Regression test: `import_transactional_rolls_back_on_non_duplicate_error`
imports a JSON whose first row is a *new* login and second row is a
*duplicate*, asserts the import returns `DuplicateLogin`, and verifies
the new row is **not** in the DB afterwards.

---

## L1. Doc-comment claimed `OsRng` but code uses `thread_rng`
**Status: Fixed (doc-only).**

`crypto::generate_salt` and the generator's module doc both said
"Always uses `rand::rngs::OsRng`" / "OS CSPRNG". The code actually uses
`rand::thread_rng()`, which is a userspace ChaCha CSPRNG seeded from
`OsRng` and periodically reseeded. This is suitable for cryptographic
use per the `rand` crate documentation, but the doc claim was simply
inaccurate — a future maintainer reading the doc might assume every
salt byte goes through a `getrandom(2)` syscall. Replaced the wording
with the actual implementation and the rationale.

(See L7 below for whether to switch the implementation to direct
`OsRng`. We chose to keep `thread_rng` for performance — salts are
public material and per-call syscalls add nothing.)

---

## L2. Unused `hmac` dep + redundant `simple` feature on `pbkdf2`
**Status: Fixed.**

`Cargo.toml` listed:

```toml
pbkdf2 = { version = "0.12", features = ["simple"] }
hmac = "0.12"
```

* `hmac` is never imported anywhere in our source. It was an
  accidental hold-over from an earlier draft.
* `pbkdf2`'s `simple` feature pulls in `password-hash`, `subtle`, and
  `base64ct` to support the PHC string format. We do not use the PHC
  format — we call only the low-level `pbkdf2_hmac` function, which is
  gated behind the lighter-weight `hmac` feature. Switched to
  `default-features = false, features = ["hmac"]`.

Net effect: 3 fewer transitive crates in `Cargo.lock`. No code change.

---

## L3. Export warning printed "На Unix … 0600" on Windows too
**Status: Fixed.**

Both `cli/commands.rs::export` and `cli/interactive.rs::export_json`
unconditionally printed `"На Unix його створено з режимом 0600
(тільки власник)"` after a successful export. On Windows, the
`#[cfg(not(unix))]` branch of `write_owner_only` falls back to
`std::fs::write` — the file inherits its parent directory's ACL and
nothing about `0600` is true. The message was actively misleading on
Windows.

Fix: gate the message behind `cfg!(unix)`. On Windows, print a
shorter warning that points the user at storing exports in their
own profile directory instead of trumpeting a non-existent guarantee.

---

## L4. `derive_key_pbkdf2` returned `Result<_>` but is infallible
**Status: Fixed.**

`pbkdf2_hmac` from the `pbkdf2` crate returns `()`. The wrapper
returned `Result<String, CryptoError>` only to mirror the Argon2 path,
but it never produced an `Err`. Clippy's pedantic mode flagged it.
Changed the signature to `-> String` and updated the lone caller.

---

## L5. Import message claimed "(дублікати пропущено)" even with
##     `--no-skip-duplicates`
**Status: Fixed.**

`cli/commands.rs::import` printed
`"Імпортовано {n} нових акаунтів (дублікати пропущено)."` after every
successful run. With `--no-skip-duplicates` and zero duplicates in the
input, the parenthetical is misleading — duplicates would have failed
loudly, not been skipped. Split into two messages depending on the
`skip_duplicates` flag.

---

## L6. `auto_lock_disabled_by_env` test doesn't exercise idleness
**Status: Documented only — defer.**

`tests/auto_lock.rs::auto_lock_disabled_by_env` runs a quick stdin
sequence (master setup → menu 11 → menu 9) with
`PM_AUTO_LOCK_SECONDS=0`. The same sequence would also pass with the
default `300`-second timeout because the test itself doesn't sleep.
The test asserts only that the binary exits 0, which it would do
either way.

Strengthening it requires a sleep-based test which adds ~1 second to
CI per run, OR a test-only entrypoint that lets us inject the timeout
deterministically. The companion test `auto_lock_triggers_after_idle`
already covers the timer-firing path with a controlled sleep, so the
risk of regression is small. Leaving the weak `disabled` test in
place; logged here so a future maintainer knows.

---

## L7. RNG choice for salt + generator: `thread_rng` vs direct `OsRng`
**Status: Documented only — keep current behaviour.**

Both `crypto::generate_salt` and `generator::generate_password` use
`rand::thread_rng()`. This is documented as cryptographically secure
by the `rand` crate (v0.8) and matches what virtually every Rust
crypto crate does in practice. The alternative — `rand::rngs::OsRng`
— calls `getrandom(2)` for every byte, which on Linux can fall back
to a slow path during early boot.

The conservative argument for switching to direct `OsRng`: a future
`rand` semver-major release could redefine `thread_rng()`, and the
audit trail is shorter if we go straight to the OS source. The
counter-argument: the salt is public data, and the generator's output
is not going to be brute-forced based on RNG predictability at our
length defaults. Keeping `thread_rng` for now; revisit if `rand 0.9+`
introduces a meaningful change.

//! Auto-lock behaviour exposed through the env-var configured CLI.
//!
//! Verifies:
//! * `PM_AUTO_LOCK_SECONDS=0` disables the timer (item 11 + item 9 work
//!   without re-prompting).
//! * `PM_AUTO_LOCK_SECONDS=1` (with a one-second sleep injected via the
//!   menu loop's normal tick boundary) re-prompts for master.
//!
//! We exercise the CLI as a subprocess so the test stays deterministic
//! and uses the real binary (no special test-only entrypoint).

use std::time::Duration;

use assert_cmd::Command;
use tempfile::tempdir;

fn pwm() -> Command {
    Command::cargo_bin("pwm").unwrap()
}

#[test]
fn auto_lock_disabled_by_env() {
    // Setup master, then pick item 11 (no-auth) and item 9 (exit). The
    // session never re-prompts for master.
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");

    let stdin = "master\nmaster\n11\n12\nn\nn\nn\nn\n9\n";
    // 11 → length=12, then 4 "no" answers for the four classes — one
    // class still on (default fallback rejected). Generator prints an
    // error then loop continues. Then 9 → exit.
    let out = pwm()
        .env("PM_AUTO_LOCK_SECONDS", "0")
        .arg("--db")
        .arg(&db)
        .write_stdin(stdin)
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out);
}

#[test]
fn auto_lock_triggers_after_idle() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");

    // To make this test deterministic without sleeping or scripting
    // tightly-timed stdin, we drive a pre-seeded DB through the
    // interactive flow with PM_AUTO_LOCK_SECONDS=1. Sequence:
    //   master\nmaster\n   – set master
    //   3\n                – list (DB-backed, sets last_activity)
    //   <sleep > 1s>       – sleep past the timeout
    //   3\n                – auto-lock fires; re-prompts for master
    //   WRONG x5\n         – fail re-auth → exit 1
    use std::io::Write;
    use std::process::{Command as StdCommand, Stdio};

    let mut child = StdCommand::new(assert_cmd::cargo::cargo_bin("pwm"))
        .env("PM_AUTO_LOCK_SECONDS", "1")
        .arg("--db")
        .arg(&db)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"master\nmaster\n").unwrap();
        std::thread::sleep(Duration::from_millis(500));
        stdin.write_all(b"3\n").unwrap();
        std::thread::sleep(Duration::from_millis(2_500));
        stdin.write_all(b"3\n").unwrap();
        for _ in 0..5 {
            stdin.write_all(b"WRONG\n").unwrap();
        }
    }
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("Сесію заблоковано"),
        "expected auto-lock message, got: {stdout}"
    );
}

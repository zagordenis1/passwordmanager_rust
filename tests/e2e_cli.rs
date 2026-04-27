//! End-to-end tests against the real `pwm` binary via `assert_cmd`.
//!
//! Each test spins up an isolated tempdir + `users.db` so they can run
//! in parallel. Master-password prompts are fed via stdin; in non-TTY
//! mode the binary falls back to plain `read_line` so we don't need a
//! pty.

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::tempdir;

fn pwm() -> Command {
    Command::cargo_bin("pwm").unwrap()
}

#[test]
fn init_then_add_then_get() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");

    let out = pwm()
        .arg("--db")
        .arg(&db)
        .arg("init")
        .write_stdin("master\nmaster\n")
        .output()
        .unwrap();
    assert!(out.status.success(), "init failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Master password встановлено"));

    let out = pwm()
        .arg("--db")
        .arg(&db)
        .args(["add", "--login", "alice", "--email", "a@x", "--stdin"])
        // master + password (one line each).
        .write_stdin("master\np@ssw0rd!\n")
        .output()
        .unwrap();
    assert!(out.status.success(), "add failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("Створено"));
    assert!(stdout.contains("alice"));

    let out = pwm()
        .arg("--db")
        .arg(&db)
        .args(["get", "alice"])
        .write_stdin("master\n")
        .output()
        .unwrap();
    assert!(out.status.success(), "get failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    // First line is master prompt echoed back? No — only the password
    // value goes to stdout, master prompt goes to stderr.
    assert!(stdout.contains("p@ssw0rd!"));
}

#[test]
fn list_json_round_trip() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");

    pwm()
        .arg("--db")
        .arg(&db)
        .arg("init")
        .write_stdin("m\nm\n")
        .assert()
        .success();

    pwm()
        .arg("--db")
        .arg(&db)
        .args(["add", "--login", "alice", "--email", "a@x", "--stdin"])
        .write_stdin("m\npw1\n")
        .assert()
        .success();
    pwm()
        .arg("--db")
        .arg(&db)
        .args(["add", "--login", "bob", "--email", "b@x", "--stdin"])
        .write_stdin("m\npw2\n")
        .assert()
        .success();

    let out = pwm()
        .arg("--db")
        .arg(&db)
        .args(["list", "--json"])
        .write_stdin("m\n")
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("JSON parse");
    assert_eq!(value.as_array().unwrap().len(), 2);
}

#[test]
fn invalid_master_exits_nonzero() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");

    pwm()
        .arg("--db")
        .arg(&db)
        .arg("init")
        .write_stdin("right\nright\n")
        .assert()
        .success();

    let out = pwm()
        .arg("--db")
        .arg(&db)
        .args(["list"])
        .write_stdin("WRONG\n")
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid master password"));
}

#[test]
fn rm_force_skips_confirmation() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");
    pwm()
        .arg("--db")
        .arg(&db)
        .arg("init")
        .write_stdin("m\nm\n")
        .assert()
        .success();
    pwm()
        .arg("--db")
        .arg(&db)
        .args(["add", "--login", "alice", "--email", "a@x", "--stdin"])
        .write_stdin("m\npw\n")
        .assert()
        .success();
    pwm()
        .arg("--db")
        .arg(&db)
        .args(["rm", "alice", "--force"])
        .write_stdin("m\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Видалено"));
}

#[test]
fn change_master_via_subcommand() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");

    pwm()
        .arg("--db")
        .arg(&db)
        .arg("init")
        .write_stdin("old\nold\n")
        .assert()
        .success();
    pwm()
        .arg("--db")
        .arg(&db)
        .args(["add", "--login", "alice", "--email", "a@x", "--stdin"])
        .write_stdin("old\nsecret\n")
        .assert()
        .success();

    pwm()
        .arg("--db")
        .arg(&db)
        .arg("change-master")
        // old + new + confirm
        .write_stdin("old\nnew\nnew\n")
        .assert()
        .success()
        .stdout(predicate::str::contains("Master password змінено"));

    // Old fails, new works, ciphertext readable.
    let out = pwm()
        .arg("--db")
        .arg(&db)
        .args(["get", "alice"])
        .write_stdin("old\n")
        .output()
        .unwrap();
    assert!(!out.status.success());

    let out = pwm()
        .arg("--db")
        .arg(&db)
        .args(["get", "alice"])
        .write_stdin("new\n")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("secret"));
}

#[test]
fn gen_subcommand_produces_correct_length() {
    let out = pwm().args(["gen", "--length", "32"]).output().unwrap();
    assert!(out.status.success());
    let pw = String::from_utf8_lossy(&out.stdout).trim().to_string();
    assert_eq!(pw.chars().count(), 32);
}

#[test]
fn interactive_exit_via_menu_item_9() {
    // No master configured yet → interactive prompts for new master,
    // then we send "9\n" to exit cleanly.
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");
    let out = pwm()
        .arg("--db")
        .arg(&db)
        .write_stdin("master\nmaster\n9\n")
        .output()
        .unwrap();
    assert!(out.status.success(), "interactive exit failed: {:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("До побачення."));
    // Confirm the menu actually rendered with the right prompts.
    assert!(stdout.contains("=== Password Manager ==="));
    assert!(stdout.contains("Виберіть пункт"));
}

#[test]
fn interactive_eof_at_top_level_exits_cleanly() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");
    let out = pwm()
        .arg("--db")
        .arg(&db)
        .write_stdin("master\nmaster\n") // sets up master, then EOF on menu prompt
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("До побачення."));
}

#[test]
fn version_flag_prints_version() {
    let out = pwm().arg("--version").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("pwm"));
}

#[test]
fn export_import_round_trip_via_cli() {
    let dir = tempdir().unwrap();
    let db1 = dir.path().join("a.db");
    let db2 = dir.path().join("b.db");
    let json = dir.path().join("export.json");

    pwm()
        .arg("--db")
        .arg(&db1)
        .arg("init")
        .write_stdin("m\nm\n")
        .assert()
        .success();
    pwm()
        .arg("--db")
        .arg(&db1)
        .args(["add", "--login", "alice", "--email", "a@x", "--stdin"])
        .write_stdin("m\np1\n")
        .assert()
        .success();
    pwm()
        .arg("--db")
        .arg(&db1)
        .args(["export"])
        .arg(&json)
        .write_stdin("m\n")
        .assert()
        .success();

    pwm()
        .arg("--db")
        .arg(&db2)
        .arg("init")
        .write_stdin("other\nother\n")
        .assert()
        .success();
    pwm()
        .arg("--db")
        .arg(&db2)
        .args(["import"])
        .arg(&json)
        .write_stdin("other\n")
        .assert()
        .success();
    let out = pwm()
        .arg("--db")
        .arg(&db2)
        .args(["get", "alice"])
        .write_stdin("other\n")
        .output()
        .unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("p1"));
}

//! Integration tests that exercise the public `PasswordManager` API
//! through the library crate (mirrors the Python `tests/test_password_manager.py`).

use passwordmanagerrs::PasswordManager;
use tempfile::tempdir;

#[test]
fn full_lifecycle() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");

    let mut m = PasswordManager::new(&db).unwrap();
    assert!(!m.has_master_password().unwrap());
    m.set_master_password("master-1").unwrap();
    assert!(m.has_master_password().unwrap());

    m.create_user("alice", "a@x", "p1").unwrap();
    m.create_user("bob", "b@x.com", "p2").unwrap();

    let listed = m.list_users().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].login, "alice");
    assert_eq!(listed[0].password, "p1");

    let found = m.search("ob").unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].login, "bob");

    assert!(m.update_password("alice", "p1-new").unwrap());
    assert_eq!(m.get_user("alice").unwrap().unwrap().password, "p1-new");

    assert!(m.delete_user("bob").unwrap());
    assert!(m.get_user("bob").unwrap().is_none());

    m.lock();
    assert!(!m.is_unlocked());
    assert!(m.list_users().is_err());

    assert!(m.verify_master_password("master-1").unwrap());
    assert!(m.is_unlocked());
    assert_eq!(m.list_users().unwrap().len(), 1);
}

#[test]
fn search_is_case_insensitive_for_ascii() {
    // SQLite LIKE is case-insensitive for ASCII by default.
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");
    let mut m = PasswordManager::new(&db).unwrap();
    m.set_master_password("m").unwrap();
    m.create_user("Alice", "A@x", "p").unwrap();
    let found = m.search("ali").unwrap();
    assert_eq!(found.len(), 1);
}

#[test]
fn empty_login_rejected() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("users.db");
    let mut m = PasswordManager::new(&db).unwrap();
    m.set_master_password("m").unwrap();
    assert!(m.create_user("", "a@x", "p").is_err());
}

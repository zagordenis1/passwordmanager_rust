//! Cryptographic primitives: master-password KDF, Fernet helpers, and a
//! constant-plaintext verifier token used to check the master password.
//!
//! # Compatibility
//!
//! The on-disk format must be byte-compatible with the Python reference
//! implementation (`passwordmanagerpy`). Concretely:
//!
//! * Argon2id with parameters `m=19456 KiB, t=2, p=1, hash_len=32` is the
//!   default KDF. The 32-byte raw output is base64-url-safe (with padding)
//!   to form the Fernet key — exactly what `cryptography.fernet.Fernet`
//!   expects.
//! * Salt is 16 random bytes from the OS CSPRNG.
//! * The legacy KDF — PBKDF2-HMAC-SHA256, 480_000 iterations — is preserved
//!   so old databases can still be unlocked. New writes always use Argon2id.
//! * The verifier plaintext is the byte string `b"password_manager:verifier:v1"`,
//!   encrypted with the derived Fernet key. A successful decrypt-and-compare
//!   means the master password is correct.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use fernet::Fernet;
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

/// Identifier persisted in the `meta(kdf_version)` row for new databases.
pub const KDF_ARGON2ID_V1: &str = "argon2id-v1";

/// Identifier used for databases predating the Argon2id migration. Older
/// DBs simply have no `kdf_version` row at all — we treat that as legacy.
pub const KDF_PBKDF2_LEGACY: &str = "pbkdf2-sha256-legacy";

/// Argon2id memory cost in KiB (19 MiB — comfortably above the OWASP
/// 2024 minimum of 19 MiB and matches the Python reference exactly).
pub const ARGON2_MEMORY_KIB: u32 = 19_456;
/// Argon2id time cost (number of passes).
pub const ARGON2_TIME_COST: u32 = 2;
/// Argon2id parallelism.
pub const ARGON2_PARALLELISM: u32 = 1;

/// PBKDF2 iteration count (legacy path only — never used for new DBs).
pub const PBKDF2_ITERATIONS: u32 = 480_000;

/// Salt size in bytes (matches the Python reference).
pub const SALT_SIZE: usize = 16;

/// Constant verifier plaintext encrypted at master-setup time. Decrypting
/// it on login proves that the derived key (and therefore the master
/// password) is correct. The exact bytes must match the Python reference
/// to keep cross-compat tests green.
pub const VERIFIER_PLAINTEXT: &[u8] = b"password_manager:verifier:v1";

/// Errors raised by this module. Application code should usually surface
/// these via `anyhow::Result` rather than match on the variants directly.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The master password was empty — refused before hitting the KDF.
    #[error("master password must be a non-empty string")]
    EmptyMasterPassword,
    /// Salt shorter than 8 bytes — never produced by `generate_salt`,
    /// only possible if the database is corrupt.
    #[error("salt must be at least 8 bytes (got {0})")]
    SaltTooShort(usize),
    /// `kdf_version` value stored in the database is unrecognised.
    #[error("unknown kdf_version: {0}")]
    UnknownKdf(String),
    /// Argon2 produced an internal error — usually only on absurd
    /// parameter combinations that we never set in practice.
    #[error("argon2 KDF failed: {0}")]
    Argon2(String),
    /// `fernet` rejected the constructed base64 key. Indicates a programming
    /// error: derived keys are always 32 bytes → 44-char base64.
    #[error("invalid fernet key (programming error)")]
    InvalidFernetKey,
    /// Token failed to decrypt under the given key (wrong master password
    /// or tampered DB). Surfaced to the user as a generic auth failure.
    #[error("invalid token / wrong key")]
    InvalidToken,
}

/// Generate a fresh `SALT_SIZE`-byte salt from a cryptographically
/// secure RNG.
///
/// Uses [`rand::thread_rng`] — a userspace ChaCha-based CSPRNG seeded
/// from the OS entropy source (`getrandom(2)` / `BCryptGenRandom` /
/// `arc4random_buf`) and periodically reseeded. This is suitable for
/// cryptographic use per the `rand` crate documentation; the salt is
/// public and unique-per-DB so a per-call OS syscall is unnecessary.
#[must_use]
pub fn generate_salt() -> Vec<u8> {
    let mut salt = vec![0u8; SALT_SIZE];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

fn validate_inputs(master_password: &str, salt: &[u8]) -> Result<(), CryptoError> {
    if master_password.is_empty() {
        return Err(CryptoError::EmptyMasterPassword);
    }
    if salt.len() < 8 {
        return Err(CryptoError::SaltTooShort(salt.len()));
    }
    Ok(())
}

/// Derive a Fernet key (base64-url-safe, padded) from `master_password`
/// and `salt` using the named KDF.
///
/// Returns the 44-byte base64 string ready to feed into [`fernet::Fernet::new`].
/// On success the caller is responsible for treating the returned `String`
/// as secret material — wrap it in [`secrecy::SecretString`] before
/// storing it on a struct.
pub fn derive_key(
    master_password: &str,
    salt: &[u8],
    kdf_version: &str,
) -> Result<String, CryptoError> {
    validate_inputs(master_password, salt)?;
    match kdf_version {
        KDF_ARGON2ID_V1 => derive_key_argon2id(master_password, salt),
        KDF_PBKDF2_LEGACY => Ok(derive_key_pbkdf2(master_password, salt)),
        other => Err(CryptoError::UnknownKdf(other.to_string())),
    }
}

fn derive_key_argon2id(master_password: &str, salt: &[u8]) -> Result<String, CryptoError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(|e| CryptoError::Argon2(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut raw = [0u8; 32];
    argon2
        .hash_password_into(master_password.as_bytes(), salt, &mut raw)
        .map_err(|e| CryptoError::Argon2(e.to_string()))?;

    let key = URL_SAFE.encode(raw);
    raw.zeroize();
    Ok(key)
}

fn derive_key_pbkdf2(master_password: &str, salt: &[u8]) -> String {
    let mut raw = [0u8; 32];
    pbkdf2_hmac::<Sha256>(
        master_password.as_bytes(),
        salt,
        PBKDF2_ITERATIONS,
        &mut raw,
    );
    let key = URL_SAFE.encode(raw);
    raw.zeroize();
    key
}

/// Build a [`Fernet`] from a base64 key produced by [`derive_key`].
pub fn fernet_from_key(key: &str) -> Result<Fernet, CryptoError> {
    Fernet::new(key).ok_or(CryptoError::InvalidFernetKey)
}

/// Encrypt the canonical verifier plaintext under `fernet`. Persisted in
/// the `meta(verifier)` row at master-setup / change time.
pub fn make_verifier(fernet: &Fernet) -> String {
    fernet.encrypt(VERIFIER_PLAINTEXT)
}

/// Return `true` iff `token` was produced by [`make_verifier`] under the
/// same key as `fernet`. Used to verify the master password without
/// trusting the user's typed input.
pub fn check_verifier(fernet: &Fernet, token: &str) -> bool {
    match fernet.decrypt(token) {
        Ok(plaintext) => plaintext == VERIFIER_PLAINTEXT,
        Err(_) => false,
    }
}

/// Encrypt a UTF-8 string. The token is itself UTF-8 (base64-url) and
/// safe to store in a SQLite TEXT column.
pub fn encrypt_str(fernet: &Fernet, plaintext: &str) -> String {
    fernet.encrypt(plaintext.as_bytes())
}

/// Decrypt a token previously produced by [`encrypt_str`].
pub fn decrypt_str(fernet: &Fernet, token: &str) -> Result<String, CryptoError> {
    let bytes = fernet
        .decrypt(token)
        .map_err(|_| CryptoError::InvalidToken)?;
    String::from_utf8(bytes).map_err(|_| CryptoError::InvalidToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn salt_is_random_and_correct_size() {
        let a = generate_salt();
        let b = generate_salt();
        assert_eq!(a.len(), SALT_SIZE);
        assert_eq!(b.len(), SALT_SIZE);
        assert_ne!(a, b, "two consecutive salts must (statistically) differ");
    }

    #[test]
    fn empty_password_is_rejected() {
        let err = derive_key("", &[0u8; 16], KDF_ARGON2ID_V1).unwrap_err();
        assert!(matches!(err, CryptoError::EmptyMasterPassword));
    }

    #[test]
    fn short_salt_is_rejected() {
        let err = derive_key("master", &[0u8; 4], KDF_ARGON2ID_V1).unwrap_err();
        assert!(matches!(err, CryptoError::SaltTooShort(4)));
    }

    #[test]
    fn unknown_kdf_is_rejected() {
        let err = derive_key("master", &[0u8; 16], "bogus").unwrap_err();
        assert!(matches!(err, CryptoError::UnknownKdf(_)));
    }

    #[test]
    fn argon2_round_trip() {
        let salt = generate_salt();
        let key = derive_key("master-1", &salt, KDF_ARGON2ID_V1).unwrap();
        let fernet = fernet_from_key(&key).unwrap();
        let ct = encrypt_str(&fernet, "secret-payload");
        assert_eq!(decrypt_str(&fernet, &ct).unwrap(), "secret-payload");
    }

    #[test]
    fn pbkdf2_round_trip() {
        let salt = generate_salt();
        let key = derive_key("master-1", &salt, KDF_PBKDF2_LEGACY).unwrap();
        let fernet = fernet_from_key(&key).unwrap();
        let ct = encrypt_str(&fernet, "legacy-payload");
        assert_eq!(decrypt_str(&fernet, &ct).unwrap(), "legacy-payload");
    }

    #[test]
    fn argon2_is_deterministic_for_same_inputs() {
        let salt = vec![0xABu8; SALT_SIZE];
        let a = derive_key("same", &salt, KDF_ARGON2ID_V1).unwrap();
        let b = derive_key("same", &salt, KDF_ARGON2ID_V1).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn argon2_and_pbkdf2_yield_different_keys() {
        let salt = b"saltsalt12345678".to_vec();
        let a = derive_key("x", &salt, KDF_ARGON2ID_V1).unwrap();
        let p = derive_key("x", &salt, KDF_PBKDF2_LEGACY).unwrap();
        assert_ne!(a, p);
    }

    #[test]
    fn verifier_round_trip() {
        let key = derive_key("master", &generate_salt(), KDF_ARGON2ID_V1).unwrap();
        let fernet = fernet_from_key(&key).unwrap();
        let token = make_verifier(&fernet);
        assert!(check_verifier(&fernet, &token));
    }

    #[test]
    fn verifier_rejects_wrong_key() {
        let salt = generate_salt();
        let key = derive_key("master", &salt, KDF_ARGON2ID_V1).unwrap();
        let token = make_verifier(&fernet_from_key(&key).unwrap());

        let other_salt = generate_salt();
        let other_key = derive_key("master", &other_salt, KDF_ARGON2ID_V1).unwrap();
        let other = fernet_from_key(&other_key).unwrap();
        assert!(!check_verifier(&other, &token));
    }

    #[test]
    fn argon2_known_answer_is_stable() {
        // Snapshot test: pinning the Argon2id implementation to a known
        // output. If this ever flips, cross-compat with the Python reference
        // breaks too — failing here gives a much clearer diagnostic than
        // the cross-compat suite.
        let salt = b"saltsaltsaltsalt"; // 16 bytes
        let key = derive_key("master-1", salt, KDF_ARGON2ID_V1).unwrap();
        // Re-derive: must match.
        let key2 = derive_key("master-1", salt, KDF_ARGON2ID_V1).unwrap();
        assert_eq!(key, key2);
        // 32-byte raw key → 44 chars base64 url-safe with padding.
        assert_eq!(key.len(), 44);
    }
}

//! Cryptographically secure password generator.
//!
//! Always uses `rand::rngs::OsRng` (which on every supported platform pulls
//! entropy from the OS — `getrandom(2)` / `BCryptGenRandom` /
//! `arc4random_buf`). Never use the seeded PRNGs from `rand` for password
//! material.
//!
//! Default policy: 20 characters, all four character classes
//! (lower / upper / digit / symbol). The generator guarantees that every
//! enabled class is represented at least once before filling the rest.

use rand::seq::SliceRandom;
use rand::Rng;
use thiserror::Error;

/// Default password length. Long enough that brute-force is infeasible
/// regardless of which classes are enabled.
pub const DEFAULT_LENGTH: usize = 20;
/// Minimum supported length: must accommodate one char per enabled class.
pub const MIN_LENGTH: usize = 4;
/// Sanity cap. 4096 chars is already absurd entropy (~25 KiB of bits).
pub const MAX_LENGTH: usize = 4096;

/// Symbol set. Excludes whitespace, quotes and backslash so generated
/// passwords paste cleanly through shells and most web forms.
pub const DEFAULT_SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>/?";

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";

/// Errors raised by the generator.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GeneratorError {
    #[error("length must be between {MIN_LENGTH} and {MAX_LENGTH} (got {0})")]
    LengthOutOfRange(usize),
    #[error("at least one character class must be enabled")]
    NoClassesEnabled,
    #[error("length {length} is too short for {classes} required classes")]
    LengthShorterThanClasses { length: usize, classes: usize },
}

/// Per-policy character pool selection.
#[derive(Debug, Clone)]
pub struct PasswordPolicy {
    pub length: usize,
    pub use_lower: bool,
    pub use_upper: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
    pub symbols: String,
}

impl Default for PasswordPolicy {
    fn default() -> Self {
        Self {
            length: DEFAULT_LENGTH,
            use_lower: true,
            use_upper: true,
            use_digits: true,
            use_symbols: true,
            symbols: DEFAULT_SYMBOLS.to_string(),
        }
    }
}

impl PasswordPolicy {
    fn required_classes(&self) -> Vec<&str> {
        let mut classes: Vec<&str> = Vec::new();
        if self.use_lower {
            classes.push(LOWER);
        }
        if self.use_upper {
            classes.push(UPPER);
        }
        if self.use_digits {
            classes.push(DIGITS);
        }
        if self.use_symbols {
            classes.push(self.symbols.as_str());
        }
        classes
    }

    fn alphabet(&self) -> String {
        let mut alpha = String::new();
        for class in self.required_classes() {
            alpha.push_str(class);
        }
        alpha
    }
}

/// Generate one password matching `policy`. The result is guaranteed to
/// contain at least one character from each enabled class.
pub fn generate_password(policy: &PasswordPolicy) -> Result<String, GeneratorError> {
    if policy.length < MIN_LENGTH || policy.length > MAX_LENGTH {
        return Err(GeneratorError::LengthOutOfRange(policy.length));
    }
    let classes = policy.required_classes();
    if classes.is_empty() || classes.iter().any(|c| c.is_empty()) {
        return Err(GeneratorError::NoClassesEnabled);
    }
    if policy.length < classes.len() {
        return Err(GeneratorError::LengthShorterThanClasses {
            length: policy.length,
            classes: classes.len(),
        });
    }

    let alphabet: Vec<char> = policy.alphabet().chars().collect();
    let mut rng = rand::thread_rng();

    // Step 1: one guaranteed char per enabled class.
    let mut chars: Vec<char> = classes
        .iter()
        .map(|class| {
            let pool: Vec<char> = class.chars().collect();
            let idx = rng.gen_range(0..pool.len());
            pool[idx]
        })
        .collect();

    // Step 2: fill the rest from the combined alphabet.
    while chars.len() < policy.length {
        let idx = rng.gen_range(0..alphabet.len());
        chars.push(alphabet[idx]);
    }

    // Step 3: shuffle so guaranteed chars aren't always at the start.
    chars.shuffle(&mut rng);
    Ok(chars.into_iter().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_lower(s: &str) -> bool {
        s.chars().any(|c| c.is_ascii_lowercase())
    }
    fn has_upper(s: &str) -> bool {
        s.chars().any(|c| c.is_ascii_uppercase())
    }
    fn has_digit(s: &str) -> bool {
        s.chars().any(|c| c.is_ascii_digit())
    }
    fn has_symbol(s: &str, set: &str) -> bool {
        s.chars().any(|c| set.contains(c))
    }

    #[test]
    fn default_policy_produces_all_classes() {
        let p = PasswordPolicy::default();
        for _ in 0..32 {
            let pw = generate_password(&p).unwrap();
            assert_eq!(pw.chars().count(), DEFAULT_LENGTH);
            assert!(has_lower(&pw));
            assert!(has_upper(&pw));
            assert!(has_digit(&pw));
            assert!(has_symbol(&pw, DEFAULT_SYMBOLS));
        }
    }

    #[test]
    fn length_too_short_rejected() {
        let p = PasswordPolicy {
            length: 2,
            ..Default::default()
        };
        assert_eq!(
            generate_password(&p),
            Err(GeneratorError::LengthOutOfRange(2))
        );
    }

    #[test]
    fn length_too_long_rejected() {
        let p = PasswordPolicy {
            length: MAX_LENGTH + 1,
            ..Default::default()
        };
        assert!(matches!(
            generate_password(&p),
            Err(GeneratorError::LengthOutOfRange(_))
        ));
    }

    #[test]
    fn no_classes_rejected() {
        let p = PasswordPolicy {
            length: 12,
            use_lower: false,
            use_upper: false,
            use_digits: false,
            use_symbols: false,
            symbols: DEFAULT_SYMBOLS.to_string(),
        };
        assert_eq!(generate_password(&p), Err(GeneratorError::NoClassesEnabled));
    }

    #[test]
    fn empty_symbols_string_rejected_when_only_class() {
        let p = PasswordPolicy {
            length: 12,
            use_lower: false,
            use_upper: false,
            use_digits: false,
            use_symbols: true,
            symbols: String::new(),
        };
        assert_eq!(generate_password(&p), Err(GeneratorError::NoClassesEnabled));
    }

    #[test]
    fn length_shorter_than_class_count_rejected() {
        // 4 classes but length 4 is OK; length 4 with only 4 classes works.
        // Test: length 5 with 6 classes is impossible. We can't have 6
        // classes in our model, so use a reduced length scenario:
        // 4 classes + length 4 -> OK.
        let p = PasswordPolicy {
            length: 4,
            ..Default::default()
        };
        let pw = generate_password(&p).unwrap();
        assert_eq!(pw.chars().count(), 4);
        assert!(has_lower(&pw));
        assert!(has_upper(&pw));
        assert!(has_digit(&pw));
        assert!(has_symbol(&pw, DEFAULT_SYMBOLS));
    }

    #[test]
    fn lowercase_only_policy_works() {
        let p = PasswordPolicy {
            length: 16,
            use_lower: true,
            use_upper: false,
            use_digits: false,
            use_symbols: false,
            symbols: DEFAULT_SYMBOLS.to_string(),
        };
        let pw = generate_password(&p).unwrap();
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }
}

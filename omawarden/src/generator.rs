use rand::rngs::OsRng;
use rand::seq::SliceRandom;
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const DEFAULT_PASSWORD_LENGTH: usize = 20;
pub const MIN_PASSWORD_LENGTH: usize = 5;
pub const MAX_PASSWORD_LENGTH: usize = 128;

pub const DEFAULT_PASSPHRASE_WORDS: usize = 4;
pub const MIN_PASSPHRASE_WORDS: usize = 3;
pub const MAX_PASSPHRASE_WORDS: usize = 20;

pub const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
pub const NUMBERS: &[u8] = b"0123456789";
pub const SPECIAL: &[u8] = b"!@#$%^&*()_+-=[]{}|;:,.<>?";
pub const AMBIGUOUS: &[u8] = b"0Oo1lI|";

const EFF_LARGE_WORDLIST_RAW: &str = include_str!("../resources/eff_large_wordlist.txt");

fn default_password_length() -> usize {
    DEFAULT_PASSWORD_LENGTH
}

fn default_true() -> bool {
    true
}

fn default_one() -> usize {
    1
}

fn default_passphrase_words() -> usize {
    DEFAULT_PASSPHRASE_WORDS
}

fn default_separator() -> String {
    "-".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordOptions {
    #[serde(default = "default_password_length")]
    pub length: usize,
    #[serde(default = "default_true")]
    pub uppercase: bool,
    #[serde(default = "default_true")]
    pub lowercase: bool,
    #[serde(default = "default_true")]
    pub numbers: bool,
    #[serde(default = "default_true")]
    pub special: bool,
    #[serde(default)]
    pub avoid_ambiguous: bool,
    #[serde(default = "default_one")]
    pub min_numbers: usize,
    #[serde(default = "default_one")]
    pub min_special: usize,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            length: DEFAULT_PASSWORD_LENGTH,
            uppercase: true,
            lowercase: true,
            numbers: true,
            special: true,
            avoid_ambiguous: false,
            min_numbers: 1,
            min_special: 1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassphraseOptions {
    #[serde(default = "default_passphrase_words")]
    pub words: usize,
    #[serde(default = "default_separator")]
    pub separator: String,
    #[serde(default)]
    pub capitalize: bool,
}

impl Default for PassphraseOptions {
    fn default() -> Self {
        Self {
            words: DEFAULT_PASSPHRASE_WORDS,
            separator: "-".to_string(),
            capitalize: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Zeroize, ZeroizeOnDrop)]
pub struct GeneratedSecret {
    pub value: String,
    #[zeroize(skip)]
    pub entropy: f64,
    #[zeroize(skip)]
    pub secret_type: String,
}

fn filter_charset(chars: &[u8], avoid_ambiguous: bool) -> Vec<u8> {
    if !avoid_ambiguous {
        chars.to_vec()
    } else {
        chars
            .iter()
            .copied()
            .filter(|c| !AMBIGUOUS.contains(c))
            .collect()
    }
}

pub fn generate_password(options: &PasswordOptions) -> Result<GeneratedSecret, String> {
    if options.length < MIN_PASSWORD_LENGTH || options.length > MAX_PASSWORD_LENGTH {
        return Err(format!(
            "Password length must be between {} and {} characters. Use 14 or more characters for a strong password.",
            MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH
        ));
    }

    if !options.uppercase && !options.lowercase && !options.numbers && !options.special {
        return Err("At least one character set must be selected".to_string());
    }

    let length = options.length;
    let mut rng = OsRng;

    let upper_pool = if options.uppercase {
        filter_charset(UPPERCASE, options.avoid_ambiguous)
    } else {
        Vec::new()
    };
    let lower_pool = if options.lowercase {
        filter_charset(LOWERCASE, options.avoid_ambiguous)
    } else {
        Vec::new()
    };
    let number_pool = if options.numbers {
        filter_charset(NUMBERS, options.avoid_ambiguous)
    } else {
        Vec::new()
    };
    let special_pool = if options.special {
        filter_charset(SPECIAL, options.avoid_ambiguous)
    } else {
        Vec::new()
    };

    let mut combined_pool = Vec::new();
    combined_pool.extend_from_slice(&upper_pool);
    combined_pool.extend_from_slice(&lower_pool);
    combined_pool.extend_from_slice(&number_pool);
    combined_pool.extend_from_slice(&special_pool);

    if combined_pool.is_empty() {
        return Err("No characters available with current configuration".to_string());
    }

    let mut result: Vec<u8> = Vec::with_capacity(length);

    // Guaranteed minimums
    if options.numbers && !number_pool.is_empty() && options.min_numbers > 0 {
        for _ in 0..options.min_numbers.min(length) {
            result.push(*number_pool.choose(&mut rng).unwrap());
        }
    }
    if options.special && !special_pool.is_empty() && options.min_special > 0 {
        let remaining = length.saturating_sub(result.len());
        for _ in 0..options.min_special.min(remaining) {
            result.push(*special_pool.choose(&mut rng).unwrap());
        }
    }
    if options.uppercase && !upper_pool.is_empty() && result.len() < length {
        result.push(*upper_pool.choose(&mut rng).unwrap());
    }
    if options.lowercase && !lower_pool.is_empty() && result.len() < length {
        result.push(*lower_pool.choose(&mut rng).unwrap());
    }

    // Fill the rest from combined pool
    while result.len() < length {
        result.push(*combined_pool.choose(&mut rng).unwrap());
    }

    // Shuffle result
    result.shuffle(&mut rng);

    let password = String::from_utf8(result).map_err(|e| e.to_string())?;
    let pool_size = combined_pool.len() as f64;
    let entropy = (length as f64) * pool_size.log2();

    Ok(GeneratedSecret {
        value: password,
        entropy: (entropy * 10.0).round() / 10.0,
        secret_type: "password".to_string(),
    })
}

pub fn get_eff_words() -> Vec<&'static str> {
    EFF_LARGE_WORDLIST_RAW
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .collect()
}

pub fn generate_passphrase(options: &PassphraseOptions) -> Result<GeneratedSecret, String> {
    if options.words < MIN_PASSPHRASE_WORDS || options.words > MAX_PASSPHRASE_WORDS {
        return Err(format!(
            "Passphrase word count must be between {} and {} words.",
            MIN_PASSPHRASE_WORDS, MAX_PASSPHRASE_WORDS
        ));
    }

    let words_pool = get_eff_words();
    if words_pool.is_empty() {
        return Err("Wordlist is empty".to_string());
    }

    let word_count = options.words;
    let mut rng = OsRng;

    let mut selected_words = Vec::with_capacity(word_count);
    for _ in 0..word_count {
        let idx = rng.gen_range(0..words_pool.len());
        let mut word = words_pool[idx].to_string();
        if options.capitalize {
            let mut chars = word.chars();
            if let Some(first) = chars.next() {
                word = first.to_uppercase().collect::<String>() + chars.as_str();
            }
        }
        selected_words.push(word);
    }

    let passphrase = selected_words.join(&options.separator);
    // 7776 words = ~12.915 bits per word
    let pool_size = words_pool.len() as f64;
    let entropy = (word_count as f64) * pool_size.log2();

    Ok(GeneratedSecret {
        value: passphrase,
        entropy: (entropy * 10.0).round() / 10.0,
        secret_type: "passphrase".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_default_password() {
        let options = PasswordOptions::default();
        let res = generate_password(&options).expect("failed to generate");
        assert_eq!(res.value.len(), DEFAULT_PASSWORD_LENGTH);
        assert_eq!(res.secret_type, "password");
        assert!(res.entropy > 100.0);
    }

    #[test]
    fn test_generate_password_length_validation() {
        for bad_len in [0, 1, 2, 3, 4] {
            let res = generate_password(&PasswordOptions {
                length: bad_len,
                ..Default::default()
            });
            assert!(res.is_err(), "Expected error for length {}", bad_len);
            let err = res.err().unwrap();
            assert!(err.contains("Password length must be between 5 and 128"));
            assert!(err.contains("Use 14 or more characters for a strong password"));
        }

        let res_5 = generate_password(&PasswordOptions {
            length: 5,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(res_5.value.len(), 5);

        let res_128 = generate_password(&PasswordOptions {
            length: 128,
            ..Default::default()
        })
        .unwrap();
        assert_eq!(res_128.value.len(), 128);

        for bad_len in [129, 200] {
            let res = generate_password(&PasswordOptions {
                length: bad_len,
                ..Default::default()
            });
            assert!(res.is_err(), "Expected error for length {}", bad_len);
            let err = res.err().unwrap();
            assert!(err.contains("Password length must be between 5 and 128"));
        }
    }

    #[test]
    fn test_generate_passphrase_words_validation() {
        for bad_words in [0, 1, 2] {
            let res = generate_passphrase(&PassphraseOptions {
                words: bad_words,
                ..Default::default()
            });
            assert!(res.is_err(), "Expected error for words {}", bad_words);
            let err = res.err().unwrap();
            assert!(err.contains("Passphrase word count must be between 3 and 20"));
        }

        let res_21 = generate_passphrase(&PassphraseOptions {
            words: 21,
            ..Default::default()
        });
        assert!(res_21.is_err());
    }

    #[test]
    fn test_generate_password_charset_subsets() {
        // Numbers only
        let options = PasswordOptions {
            length: 12,
            uppercase: false,
            lowercase: false,
            numbers: true,
            special: false,
            avoid_ambiguous: false,
            min_numbers: 1,
            min_special: 0,
        };
        let res = generate_password(&options).unwrap();
        assert!(res.value.chars().all(|c| c.is_ascii_digit()));

        // Lowercase only
        let options = PasswordOptions {
            length: 15,
            uppercase: false,
            lowercase: true,
            numbers: false,
            special: false,
            avoid_ambiguous: false,
            min_numbers: 0,
            min_special: 0,
        };
        let res = generate_password(&options).unwrap();
        assert!(res.value.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn test_avoid_ambiguous_characters() {
        let options = PasswordOptions {
            length: 64,
            uppercase: true,
            lowercase: true,
            numbers: true,
            special: true,
            avoid_ambiguous: true,
            min_numbers: 1,
            min_special: 1,
        };
        for _ in 0..10 {
            let res = generate_password(&options).unwrap();
            for c in res.value.chars() {
                assert!(
                    !AMBIGUOUS.contains(&(c as u8)),
                    "Found ambiguous char '{}' in generated password",
                    c
                );
            }
        }
    }

    #[test]
    fn test_no_charset_selected_errors() {
        let options = PasswordOptions {
            length: 16,
            uppercase: false,
            lowercase: false,
            numbers: false,
            special: false,
            avoid_ambiguous: false,
            min_numbers: 0,
            min_special: 0,
        };
        assert!(generate_password(&options).is_err());
    }

    #[test]
    fn test_generate_passphrase_defaults() {
        let options = PassphraseOptions::default();
        let res = generate_passphrase(&options).expect("failed to generate passphrase");
        assert_eq!(res.secret_type, "passphrase");
        let words: Vec<&str> = res.value.split('-').collect();
        assert_eq!(words.len(), DEFAULT_PASSPHRASE_WORDS);
        assert!((res.entropy - 51.7).abs() < 1.0);
    }

    #[test]
    fn test_generate_passphrase_custom_separator_and_capitalize() {
        let options = PassphraseOptions {
            words: 5,
            separator: ".".to_string(),
            capitalize: true,
        };
        let res = generate_passphrase(&options).unwrap();
        let words: Vec<&str> = res.value.split('.').collect();
        assert_eq!(words.len(), 5);
        for w in words {
            let first = w.chars().next().unwrap();
            assert!(first.is_uppercase(), "Word '{}' should be capitalized", w);
        }
    }

    #[test]
    fn test_wordlist_is_complete_and_eff_standards() {
        let words = get_eff_words();
        assert_eq!(words.len(), 7776);
        assert_eq!(words[0], "abacus");
        assert_eq!(words[7775], "zoom");
    }
}

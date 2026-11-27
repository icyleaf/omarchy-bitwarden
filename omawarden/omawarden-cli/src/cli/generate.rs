use omawarden_engine::clipboard::ClipboardGuard;
use omawarden_engine::config::Config;
use serde_json::json;
use std::process::ExitCode;

pub(crate) struct GenerateArgs {
    pub(crate) length: usize,
    pub(crate) no_uppercase: bool,
    pub(crate) no_lowercase: bool,
    pub(crate) no_numbers: bool,
    pub(crate) no_special: bool,
    pub(crate) avoid_ambiguous: bool,
    pub(crate) min_numbers: usize,
    pub(crate) min_special: usize,
    pub(crate) passphrase: bool,
    pub(crate) words: usize,
    pub(crate) separator: String,
    pub(crate) capitalize: bool,
    pub(crate) copy: bool,
    pub(crate) json: bool,
}

pub(crate) fn run(args: GenerateArgs, cfg: &Config) -> ExitCode {
    let GenerateArgs {
        length,
        no_uppercase,
        no_lowercase,
        no_numbers,
        no_special,
        avoid_ambiguous,
        min_numbers,
        min_special,
        passphrase,
        words,
        separator,
        capitalize,
        copy,
        json,
    } = args;

    let secret_res = if passphrase {
        let options = omawarden_engine::generator::PassphraseOptions {
            words,
            separator,
            capitalize,
        };
        omawarden_engine::generator::generate_passphrase(&options)
    } else {
        let options = omawarden_engine::generator::PasswordOptions {
            length,
            uppercase: !no_uppercase,
            lowercase: !no_lowercase,
            numbers: !no_numbers,
            special: !no_special,
            avoid_ambiguous,
            min_numbers,
            min_special,
        };
        omawarden_engine::generator::generate_password(&options)
    };

    let secret = match secret_res {
        Ok(s) => s,
        Err(e) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": e
                    }))
                    .unwrap()
                );
            } else {
                eprintln!("Error: {}", e);
            }
            return ExitCode::FAILURE;
        }
    };

    let guard = ClipboardGuard::default();
    let mut copied = false;
    if copy {
        let timeout = if cfg.clipboard_clear_seconds > 0 {
            cfg.clipboard_clear_seconds
        } else {
            30
        };
        if guard.copy(&secret.value, true, timeout) {
            copied = true;
            if !json {
                println!(
                    "Generated secret copied to clipboard (auto-clears in {}s)",
                    timeout
                );
            }
        } else {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": "Failed to copy generated secret to clipboard"
                    }))
                    .unwrap()
                );
            } else {
                eprintln!("Failed to copy generated secret to clipboard");
            }
            return ExitCode::FAILURE;
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "password": secret.value,
                "entropy": secret.entropy,
                "type": secret.secret_type,
                "copied": copied
            }))
            .unwrap()
        );
        ExitCode::SUCCESS
    } else if !copy {
        println!("{}", secret.value);
        ExitCode::SUCCESS
    } else {
        ExitCode::SUCCESS
    }
}

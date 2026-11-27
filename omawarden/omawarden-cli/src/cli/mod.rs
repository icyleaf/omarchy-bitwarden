mod attachment;
mod auth;
mod client;
mod clipboard;
mod config;
mod copy;
mod daemon;
mod doctor;
mod folder;
mod generate;
mod hook;
mod io;
mod org;
mod server;
mod ssh_agent;
mod ssh_key;
mod totp;
mod vault;

use clap::{Parser, Subcommand};
use omawarden_engine::config::ConfigManager;
use std::path::PathBuf;
use std::process::ExitCode;

use attachment::AttachmentAction;
use auth::AuthAction;
use config::ConfigAction;
use folder::FolderAction;
use hook::HookAction;
use org::OrgAction;
use server::ServerAction;
use ssh_agent::SshAgentAction;
use ssh_key::SshKeyAction;
use vault::VaultAction;

#[derive(Parser)]
#[command(
    name = "omawarden",
    version = omawarden_engine::VERSION_WITH_BUILD_INFO,
    about = "High-performance helper CLI and daemon for Omarchy Bitwarden Plugin"
)]
struct Cli {
    #[arg(long, value_name = "CONFIG_PATH", help = "Path to config.json")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    #[command(about = "Manage configuration")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    #[command(about = "Check CLI health and installation")]
    Health,
    #[command(about = "Run system health and upstream server capability diagnostics")]
    Doctor {
        #[arg(long, help = "Output diagnostics in JSON format")]
        json: bool,
    },
    #[command(about = "Manage Bitwarden authentication and vault sessions")]
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },
    #[command(about = "Manage system integration hooks")]
    Hook {
        #[command(subcommand)]
        action: HookAction,
    },
    #[command(about = "Vault sync and search operations")]
    Vault {
        #[command(subcommand)]
        action: VaultAction,
    },
    #[command(about = "Manage vault folders (list, create, edit/rename, delete)")]
    Folder {
        #[command(subcommand)]
        action: FolderAction,
    },
    #[command(about = "Inspect joined Organizations and Collections")]
    Org {
        #[command(subcommand)]
        action: OrgAction,
    },
    #[command(about = "Clipboard operations (copy vault item field, pipe stdin, or clear)")]
    Copy {
        #[arg(index = 1, help = "Vault item ID or name query")]
        query: Option<String>,
        #[arg(long, help = "Clear clipboard immediately")]
        clear: bool,
        #[arg(long, help = "Read text to copy from standard input")]
        stdin: bool,
        #[arg(long, help = "Mark STDIN text as sensitive with auto-clear")]
        sensitive: bool,
        #[arg(long, help = "Copy password (default for login items)")]
        password: bool,
        #[arg(long, help = "Copy username")]
        username: bool,
        #[arg(long, help = "Copy TOTP code")]
        totp: bool,
        #[arg(long, help = "Copy notes")]
        notes: bool,
        #[arg(long, help = "Copy SSH private key or card security code")]
        private_key: bool,
        #[arg(long, help = "Copy SSH public key or card number")]
        public_key: bool,
        #[arg(
            long,
            help = "Copy a custom field by name (exact, then case-insensitive fallback)"
        )]
        field: Option<String>,
        #[arg(long, help = "Auto-clear timeout in seconds (default: config value)")]
        timeout: Option<i64>,
        #[arg(long, hide = true, requires = "stdin")]
        expected_lock_generation: Option<u64>,
    },
    #[command(hide = true)]
    ClipboardHolder {
        seconds: u64,
        #[arg(long)]
        provider: Option<String>,
        #[arg(long)]
        binary_path: Option<PathBuf>,
        #[arg(long)]
        public: bool,
        #[arg(long, conflicts_with = "cache_path")]
        expected_lock_generation: Option<u64>,
        #[arg(long, requires = "expected_credential_id")]
        cache_path: Option<PathBuf>,
        #[arg(long, requires = "cache_path")]
        expected_credential_id: Option<String>,
        #[arg(index = 2)]
        legacy_path: Option<PathBuf>,
    },
    #[command(about = "Generate TOTP verification code from vault item ID/name, or via STDIN")]
    Totp {
        #[arg(
            index = 1,
            help = "Vault item ID or name query in the vault (use --stdin to pipe raw secrets/URIs)"
        )]
        query: Option<String>,
        #[arg(
            long,
            help = "Read secret, otpauth URI, or query JSON from standard input"
        )]
        stdin: bool,
        #[arg(long, help = "Copy generated code directly to clipboard")]
        copy: bool,
    },
    #[command(about = "Manage vault item attachments")]
    Attachment {
        #[command(subcommand)]
        action: AttachmentAction,
    },
    #[command(about = "SSH key lifecycle management (generate, import, export)")]
    SshKey {
        #[command(subcommand)]
        action: SshKeyAction,
    },
    #[command(name = "ssh-agent", about = "SSH agent backed by the vault's SSH keys")]
    SshAgent {
        #[arg(long, alias = "force", help = "Bypass server capability gating checks")]
        ignore_server_capabilities: bool,
        #[command(subcommand)]
        action: Option<SshAgentAction>,
    },
    #[command(about = "Manage or run omawarden background daemon")]
    Daemon {
        #[arg(long, help = "Auto-lock timeout in minutes")]
        auto_lock: Option<u64>,
        #[arg(long, help = "Stop the running background daemon")]
        stop: bool,
        #[arg(value_name = "ACTION", help = "Optional daemon action: 'stop'")]
        action: Option<String>,
    },
    #[command(about = "Generate cryptographically secure passwords or Diceware passphrases")]
    Generate {
        #[arg(
            short = 'l',
            long,
            default_value = "20",
            help = "Length of the generated password (5-128, recommended: 14+)"
        )]
        length: usize,
        #[arg(long, help = "Do not include uppercase letters")]
        no_uppercase: bool,
        #[arg(long, help = "Do not include lowercase letters")]
        no_lowercase: bool,
        #[arg(long, help = "Do not include numbers")]
        no_numbers: bool,
        #[arg(long, help = "Do not include special symbols")]
        no_special: bool,
        #[arg(
            long,
            help = "Avoid visually ambiguous characters (0, O, o, 1, l, I, |)"
        )]
        avoid_ambiguous: bool,
        #[arg(long, default_value = "1", help = "Minimum number of numeric digits")]
        min_numbers: usize,
        #[arg(
            long,
            default_value = "1",
            help = "Minimum number of special characters"
        )]
        min_special: usize,
        #[arg(
            short = 'p',
            long,
            help = "Generate a Diceware passphrase instead of a character password"
        )]
        passphrase: bool,
        #[arg(
            short = 'w',
            long,
            default_value = "4",
            help = "Number of words in the passphrase (3-20)"
        )]
        words: usize,
        #[arg(
            short = 's',
            long,
            default_value = "-",
            help = "Word separator for passphrase"
        )]
        separator: String,
        #[arg(long, help = "Capitalize each word in the passphrase")]
        capitalize: bool,
        #[arg(
            short = 'c',
            long,
            help = "Copy generated secret to clipboard with auto-clear"
        )]
        copy: bool,
        #[arg(long, help = "Output generated secret as JSON")]
        json: bool,
    },
    #[command(about = "Inspect upstream server version and feature capabilities")]
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
}

pub(crate) fn run() -> ExitCode {
    let cli = Cli::parse();
    let config_mgr = ConfigManager::new(cli.config.as_deref());
    let mut cfg = config_mgr.load();

    match cli.command {
        Commands::ClipboardHolder {
            seconds,
            provider,
            binary_path,
            public,
            expected_lock_generation,
            cache_path,
            expected_credential_id,
            legacy_path,
        } => clipboard::run_holder(clipboard::HolderArgs {
            seconds,
            provider,
            binary_path,
            public,
            expected_lock_generation,
            cache_path,
            expected_credential_id,
            legacy_path,
        }),
        Commands::Daemon {
            auto_lock,
            stop,
            action,
        } => daemon::run(auto_lock, stop, action, &cfg, cli.config.as_deref()),
        Commands::Config { action } => {
            config::run(action, &mut cfg, &config_mgr, cli.config.as_deref())
        }
        Commands::SshAgent {
            ignore_server_capabilities,
            action,
        } => ssh_agent::run(ignore_server_capabilities, action, &cfg),
        Commands::Health => doctor::run_health(&cfg),
        Commands::Doctor { json } => doctor::run_doctor(json, &cfg),
        Commands::Auth { action } => auth::run(action, &cfg, &config_mgr),
        Commands::Hook { action } => hook::run(action),
        Commands::Vault { action } => vault::run(action, &cfg),
        Commands::Org { action } => org::run(action),
        Commands::Folder { action } => folder::run(action),
        Commands::Copy {
            query,
            clear,
            stdin,
            sensitive,
            password,
            username,
            totp,
            notes,
            private_key,
            public_key,
            field,
            timeout,
            expected_lock_generation,
        } => copy::run(
            copy::CopyArgs {
                query,
                clear,
                stdin,
                sensitive,
                password,
                username,
                totp,
                notes,
                private_key,
                public_key,
                field,
                timeout,
                expected_lock_generation,
            },
            &cfg,
        ),
        Commands::Totp { query, stdin, copy } => totp::run(query, stdin, copy, &cfg),
        Commands::Attachment { action } => attachment::run(action),
        Commands::SshKey { action } => ssh_key::run(action, &cfg),
        Commands::Generate {
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
        } => generate::run(
            generate::GenerateArgs {
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
            },
            &cfg,
        ),
        Commands::Server { action } => server::run(action, &cfg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vault::CreateItemAction;

    #[test]
    fn test_cli_daemon_auto_lock_arg_parsing() {
        // Without --auto-lock flag, auto_lock should be None so it can inherit from config
        let cli_default = Cli::try_parse_from(["omawarden", "daemon"]).unwrap();
        match cli_default.command {
            Commands::Daemon {
                auto_lock,
                stop,
                action,
            } => {
                assert_eq!(auto_lock, None);
                assert!(!stop);
                assert_eq!(action, None);
            }
            _ => panic!("Expected Commands::Daemon"),
        }

        // With --auto-lock flag, auto_lock should be Some(N)
        let cli_explicit =
            Cli::try_parse_from(["omawarden", "daemon", "--auto-lock", "45"]).unwrap();
        match cli_explicit.command {
            Commands::Daemon { auto_lock, .. } => assert_eq!(auto_lock, Some(45)),
            _ => panic!("Expected Commands::Daemon"),
        }

        // With stop action
        let cli_stop_arg = Cli::try_parse_from(["omawarden", "daemon", "stop"]).unwrap();
        match cli_stop_arg.command {
            Commands::Daemon { action, .. } => assert_eq!(action.as_deref(), Some("stop")),
            _ => panic!("Expected Commands::Daemon"),
        }

        // With --stop flag
        let cli_stop_flag = Cli::try_parse_from(["omawarden", "daemon", "--stop"]).unwrap();
        match cli_stop_flag.command {
            Commands::Daemon { stop, .. } => assert!(stop),
            _ => panic!("Expected Commands::Daemon"),
        }
    }

    #[test]
    fn test_cli_check_updates_arg_parsing() {
        let cli_default = Cli::try_parse_from(["omawarden", "config", "set"]).unwrap();
        match cli_default.command {
            Commands::Config {
                action: ConfigAction::Set { check_updates, .. },
            } => assert_eq!(check_updates, None),
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }

        let cli_false =
            Cli::try_parse_from(["omawarden", "config", "set", "--check-updates", "false"])
                .unwrap();
        match cli_false.command {
            Commands::Config {
                action: ConfigAction::Set { check_updates, .. },
            } => assert_eq!(check_updates.as_deref(), Some("false")),
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }

        let cli_true =
            Cli::try_parse_from(["omawarden", "config", "set", "--check-updates", "true"]).unwrap();
        match cli_true.command {
            Commands::Config {
                action: ConfigAction::Set { check_updates, .. },
            } => assert_eq!(check_updates.as_deref(), Some("true")),
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }
    }

    #[test]
    fn test_cli_show_website_icons_arg_parsing() {
        // Without the flag, show_website_icons should be None so config keeps its value
        let cli_default = Cli::try_parse_from(["omawarden", "config", "set"]).unwrap();
        match cli_default.command {
            Commands::Config {
                action:
                    ConfigAction::Set {
                        show_website_icons, ..
                    },
            } => assert_eq!(show_website_icons, None),
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }

        let cli_false = Cli::try_parse_from([
            "omawarden",
            "config",
            "set",
            "--show-website-icons",
            "false",
        ])
        .unwrap();
        match cli_false.command {
            Commands::Config {
                action:
                    ConfigAction::Set {
                        show_website_icons, ..
                    },
            } => assert_eq!(show_website_icons, Some("false".to_string())),
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }

        let cli_true =
            Cli::try_parse_from(["omawarden", "config", "set", "--show-website-icons", "true"])
                .unwrap();
        match cli_true.command {
            Commands::Config {
                action:
                    ConfigAction::Set {
                        show_website_icons, ..
                    },
            } => assert_eq!(show_website_icons, Some("true".to_string())),
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }
    }

    #[test]
    fn test_cli_max_attachment_size_arg_parsing() {
        let cli_default = Cli::try_parse_from(["omawarden", "config", "set"]).unwrap();
        match cli_default.command {
            Commands::Config {
                action:
                    ConfigAction::Set {
                        max_attachment_size,
                        ..
                    },
            } => assert_eq!(max_attachment_size, None),
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }

        let cli_custom =
            Cli::try_parse_from(["omawarden", "config", "set", "--max-attachment-size", "250"])
                .unwrap();
        match cli_custom.command {
            Commands::Config {
                action:
                    ConfigAction::Set {
                        max_attachment_size,
                        ..
                    },
            } => assert_eq!(max_attachment_size, Some(250)),
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }
    }

    #[test]
    fn test_cli_client_cert_and_key_arg_parsing() {
        let cli_default = Cli::try_parse_from(["omawarden", "config", "set"]).unwrap();
        match cli_default.command {
            Commands::Config {
                action:
                    ConfigAction::Set {
                        client_cert,
                        client_key,
                        ..
                    },
            } => {
                assert_eq!(client_cert, None);
                assert_eq!(client_key, None);
            }
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }

        let cli_custom = Cli::try_parse_from([
            "omawarden",
            "config",
            "set",
            "--client-cert",
            "/path/to/cert.pem",
            "--client-key",
            "/path/to/key.pem",
        ])
        .unwrap();
        match cli_custom.command {
            Commands::Config {
                action:
                    ConfigAction::Set {
                        client_cert,
                        client_key,
                        ..
                    },
            } => {
                assert_eq!(client_cert, Some("/path/to/cert.pem".to_string()));
                assert_eq!(client_key, Some("/path/to/key.pem".to_string()));
            }
            _ => panic!("Expected Commands::Config with ConfigAction::Set"),
        }
    }

    #[test]
    fn test_cli_totp_stdin_and_query_arg_parsing() {
        let cli_stdin = Cli::try_parse_from(["omawarden", "totp", "--stdin"]).unwrap();
        match cli_stdin.command {
            Commands::Totp { stdin, query, .. } => {
                assert!(stdin);
                assert_eq!(query, None);
            }
            _ => panic!("Expected Commands::Totp"),
        }

        let cli_query = Cli::try_parse_from(["omawarden", "totp", "my-github-item"]).unwrap();
        match cli_query.command {
            Commands::Totp { stdin, query, .. } => {
                assert!(!stdin);
                assert_eq!(query.as_deref(), Some("my-github-item"));
            }
            _ => panic!("Expected Commands::Totp"),
        }
    }

    #[test]
    fn test_cli_zero_argv_sensitive_args_rejected() {
        // Assert --session is rejected
        assert!(
            Cli::try_parse_from(["omawarden", "--session", "dummy_token", "vault", "sync"])
                .is_err()
        );
        assert!(
            Cli::try_parse_from(["omawarden", "vault", "sync", "--session", "dummy_token"])
                .is_err()
        );

        // Assert --secret is rejected from totp
        assert!(
            Cli::try_parse_from(["omawarden", "totp", "--secret", "JBSWY3DPEHPK3PXP"]).is_err()
        );

        // Assert --code is rejected from auth login-password
        assert!(Cli::try_parse_from([
            "omawarden",
            "auth",
            "login-password",
            "--email",
            "test@example.com",
            "--code",
            "123456"
        ])
        .is_err());
    }

    #[test]
    fn test_cli_rejects_totp_argv_zero_argv_rule_11() {
        assert!(Cli::try_parse_from([
            "omawarden",
            "vault",
            "create",
            "login",
            "--name",
            "GitHub",
            "--username",
            "octocat",
            "--password-stdin",
            "--totp",
            "JBSWY3DPEHPK3PXP",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "omawarden",
            "vault",
            "edit",
            "GitHub",
            "--totp",
            "JBSWY3DPEHPK3PXP",
        ])
        .is_err());
        assert!(Cli::try_parse_from([
            "omawarden",
            "vault",
            "create",
            "login",
            "--name",
            "GitHub",
            "--username",
            "octocat",
            "--password",
            "pass",
            "--totp-stdin",
        ])
        .is_ok());
        assert!(
            Cli::try_parse_from(["omawarden", "vault", "edit", "GitHub", "--totp-stdin",]).is_ok()
        );
        assert!(
            Cli::try_parse_from(["omawarden", "vault", "edit", "GitHub", "--clear-totp",]).is_ok()
        );
        assert!(Cli::try_parse_from([
            "omawarden",
            "vault",
            "edit",
            "GitHub",
            "--totp-stdin",
            "--clear-totp",
        ])
        .is_err());
    }

    #[test]
    fn test_cli_generate_password_default_and_flags() {
        let cli_default = Cli::try_parse_from(["omawarden", "generate"]).unwrap();
        match cli_default.command {
            Commands::Generate {
                length,
                no_uppercase,
                no_lowercase,
                no_numbers,
                no_special,
                avoid_ambiguous,
                passphrase,
                copy,
                ..
            } => {
                assert_eq!(length, 20);
                assert!(!no_uppercase);
                assert!(!no_lowercase);
                assert!(!no_numbers);
                assert!(!no_special);
                assert!(!avoid_ambiguous);
                assert!(!passphrase);
                assert!(!copy);
            }
            _ => panic!("Expected Commands::Generate"),
        }

        let cli_custom = Cli::try_parse_from([
            "omawarden",
            "generate",
            "-l",
            "32",
            "--no-special",
            "--avoid-ambiguous",
            "-c",
            "--json",
        ])
        .unwrap();
        match cli_custom.command {
            Commands::Generate {
                length,
                no_special,
                avoid_ambiguous,
                copy,
                json,
                ..
            } => {
                assert_eq!(length, 32);
                assert!(no_special);
                assert!(avoid_ambiguous);
                assert!(copy);
                assert!(json);
            }
            _ => panic!("Expected Commands::Generate"),
        }
    }

    #[test]
    fn test_cli_generate_passphrase_flags() {
        let cli = Cli::try_parse_from([
            "omawarden",
            "generate",
            "--passphrase",
            "-w",
            "6",
            "-s",
            ".",
            "--capitalize",
        ])
        .unwrap();
        match cli.command {
            Commands::Generate {
                passphrase,
                words,
                separator,
                capitalize,
                ..
            } => {
                assert!(passphrase);
                assert_eq!(words, 6);
                assert_eq!(separator, ".");
                assert!(capitalize);
            }
            _ => panic!("Expected Commands::Generate"),
        }
    }

    #[test]
    fn test_cli_vault_delete_flags_and_aliases() {
        // Default delete
        let cli = Cli::try_parse_from(["omawarden", "vault", "delete", "my-target"]).unwrap();
        match cli.command {
            Commands::Vault {
                action:
                    VaultAction::Delete {
                        target,
                        permanent,
                        trash,
                        yes,
                        json,
                    },
            } => {
                assert_eq!(target, "my-target");
                assert!(!permanent);
                assert!(!trash);
                assert!(!yes);
                assert!(!json);
            }
            _ => panic!("Expected VaultAction::Delete"),
        }

        // Flags: --permanent, -y, --json
        let cli_flags = Cli::try_parse_from([
            "omawarden",
            "vault",
            "delete",
            "target-uuid",
            "--permanent",
            "-y",
            "--json",
        ])
        .unwrap();
        match cli_flags.command {
            Commands::Vault {
                action:
                    VaultAction::Delete {
                        target,
                        permanent,
                        trash,
                        yes,
                        json,
                    },
            } => {
                assert_eq!(target, "target-uuid");
                assert!(permanent);
                assert!(!trash);
                assert!(yes);
                assert!(json);
            }
            _ => panic!("Expected VaultAction::Delete"),
        }

        // Flag: --trash
        let cli_trash =
            Cli::try_parse_from(["omawarden", "vault", "delete", "trashed-target", "--trash"])
                .unwrap();
        match cli_trash.command {
            Commands::Vault {
                action:
                    VaultAction::Delete {
                        target,
                        trash,
                        permanent,
                        ..
                    },
            } => {
                assert_eq!(target, "trashed-target");
                assert!(trash);
                assert!(!permanent);
            }
            _ => panic!("Expected VaultAction::Delete"),
        }

        // Alias: rm
        let cli_rm =
            Cli::try_parse_from(["omawarden", "vault", "rm", "target-rm", "--yes"]).unwrap();
        match cli_rm.command {
            Commands::Vault {
                action: VaultAction::Delete { target, yes, .. },
            } => {
                assert_eq!(target, "target-rm");
                assert!(yes);
            }
            _ => panic!("Expected VaultAction::Delete for alias rm"),
        }

        // Alias: remove
        let cli_remove =
            Cli::try_parse_from(["omawarden", "vault", "remove", "target-remove"]).unwrap();
        match cli_remove.command {
            Commands::Vault {
                action: VaultAction::Delete { target, .. },
            } => {
                assert_eq!(target, "target-remove");
            }
            _ => panic!("Expected VaultAction::Delete for alias remove"),
        }
    }

    #[test]
    fn test_cli_vault_share_flags() {
        let cli = Cli::try_parse_from([
            "omawarden",
            "vault",
            "share",
            "my-personal-login",
            "--organization-id",
            "org-1",
            "--collection-id",
            "col-a",
            "--collection-id",
            "col-b",
            "--yes",
            "--json",
        ])
        .unwrap();
        match cli.command {
            Commands::Vault {
                action:
                    VaultAction::Share {
                        target,
                        organization_id,
                        collection_ids,
                        yes,
                        json,
                    },
            } => {
                assert_eq!(target, "my-personal-login");
                assert_eq!(organization_id, "org-1");
                assert_eq!(collection_ids, vec!["col-a", "col-b"]);
                assert!(yes);
                assert!(json);
            }
            _ => panic!("Expected VaultAction::Share"),
        }
    }

    #[test]
    fn test_cli_vault_edit_flags() {
        let cli = Cli::try_parse_from([
            "omawarden",
            "vault",
            "edit",
            "my-target",
            "--name",
            "new-name",
            "--username",
            "new-user",
            "--password",
            "new-pass",
            "--notes",
            "new-notes",
            "--uri",
            "https://new.uri",
            "--folder-id",
            "folder-123",
            "--favorite",
            "true",
            "--field",
            "Cluster=Prod",
            "--hidden-field",
            "API_KEY=secret",
            "--bool-field",
            "Verified=true",
            "--remove-field",
            "Obsolete",
            "--json",
        ])
        .unwrap();

        match cli.command {
            Commands::Vault {
                action:
                    VaultAction::Edit {
                        target,
                        name,
                        username,
                        password,
                        password_stdin,
                        generate_password,
                        generate_passphrase,
                        totp_stdin: _,
                        clear_totp: _,
                        notes,
                        notes_stdin,
                        uris,
                        add_uris,
                        clear_uris,
                        fields,
                        hidden_fields,
                        bool_fields,
                        remove_fields,
                        folder_id,
                        favorite,
                        stdin,
                        from_json,
                        json,
                    },
            } => {
                assert_eq!(target, "my-target");
                assert_eq!(name.as_deref(), Some("new-name"));
                assert_eq!(username.as_deref(), Some("new-user"));
                assert_eq!(password.as_deref(), Some("new-pass"));
                assert!(!password_stdin);
                assert!(!generate_password);
                assert!(!generate_passphrase);
                assert_eq!(notes.as_deref(), Some("new-notes"));
                assert!(!notes_stdin);
                assert_eq!(uris, vec!["https://new.uri"]);
                assert!(add_uris.is_empty());
                assert!(!clear_uris);
                assert_eq!(fields, vec!["Cluster=Prod"]);
                assert_eq!(hidden_fields, vec!["API_KEY=secret"]);
                assert_eq!(bool_fields, vec!["Verified=true"]);
                assert_eq!(remove_fields, vec!["Obsolete"]);
                assert_eq!(folder_id.as_deref(), Some("folder-123"));
                assert_eq!(favorite, Some(true));
                assert!(!stdin);
                assert!(from_json.is_none());
                assert!(json);
            }
            _ => panic!("Expected VaultAction::Edit"),
        }

        // Generator flags
        let cli_gen_pwd = Cli::try_parse_from([
            "omawarden",
            "vault",
            "edit",
            "my-target",
            "--generate-password",
        ])
        .unwrap();
        match cli_gen_pwd.command {
            Commands::Vault {
                action:
                    VaultAction::Edit {
                        generate_password,
                        generate_passphrase,
                        ..
                    },
            } => {
                assert!(generate_password);
                assert!(!generate_passphrase);
            }
            _ => panic!("Expected VaultAction::Edit"),
        }

        let cli_gen_passphrase = Cli::try_parse_from([
            "omawarden",
            "vault",
            "edit",
            "my-target",
            "--generate-passphrase",
        ])
        .unwrap();
        match cli_gen_passphrase.command {
            Commands::Vault {
                action:
                    VaultAction::Edit {
                        generate_password,
                        generate_passphrase,
                        ..
                    },
            } => {
                assert!(!generate_password);
                assert!(generate_passphrase);
            }
            _ => panic!("Expected VaultAction::Edit"),
        }

        // Stdin flags
        let cli_stdin = Cli::try_parse_from([
            "omawarden",
            "vault",
            "edit",
            "my-target",
            "--password-stdin",
            "--notes-stdin",
        ])
        .unwrap();

        match cli_stdin.command {
            Commands::Vault {
                action:
                    VaultAction::Edit {
                        password_stdin,
                        notes_stdin,
                        ..
                    },
            } => {
                assert!(password_stdin);
                assert!(notes_stdin);
            }
            _ => panic!("Expected VaultAction::Edit"),
        }
    }

    #[test]
    fn test_cli_vault_edit_stdin_and_from_json_flags() {
        let cli_stdin =
            Cli::try_parse_from(["omawarden", "vault", "edit", "my-target", "--stdin"]).unwrap();
        match cli_stdin.command {
            Commands::Vault {
                action:
                    VaultAction::Edit {
                        stdin, from_json, ..
                    },
            } => {
                assert!(stdin);
                assert!(from_json.is_none());
            }
            _ => panic!("Expected VaultAction::Edit"),
        }

        let cli_file = Cli::try_parse_from([
            "omawarden",
            "vault",
            "edit",
            "my-target",
            "--from-json",
            "/tmp/update.json",
        ])
        .unwrap();
        match cli_file.command {
            Commands::Vault {
                action:
                    VaultAction::Edit {
                        stdin, from_json, ..
                    },
            } => {
                assert!(!stdin);
                assert_eq!(
                    from_json.as_deref(),
                    Some(std::path::Path::new("/tmp/update.json"))
                );
            }
            _ => panic!("Expected VaultAction::Edit"),
        }

        // Payload flags are mutually exclusive with every field flag.
        for conflicting in [
            vec!["--stdin", "--password", "x"],
            vec!["--stdin", "--name", "x"],
            vec!["--stdin", "--notes", "x"],
            vec!["--stdin", "--uri", "https://example.com"],
            vec!["--stdin", "--remove-field", "x"],
            vec!["--from-json", "/tmp/update.json", "--folder-id", "f"],
            vec!["--stdin", "--from-json", "/tmp/update.json"],
        ] {
            let mut argv = vec!["omawarden", "vault", "edit", "my-target"];
            argv.extend(conflicting.iter().copied());
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "expected clap to reject conflicting payload flags"
            );
        }
    }

    #[test]
    fn test_cli_copy_field_flag() {
        let cli =
            Cli::try_parse_from(["omawarden", "copy", "my-target", "--field", "PIN"]).unwrap();
        match cli.command {
            Commands::Copy {
                query,
                field,
                password,
                username,
                ..
            } => {
                assert_eq!(query.as_deref(), Some("my-target"));
                assert_eq!(field.as_deref(), Some("PIN"));
                assert!(!password);
                assert!(!username);
            }
            _ => panic!("Expected Commands::Copy"),
        }

        // Without --field the flag stays None so the existing default applies.
        let cli_default = Cli::try_parse_from(["omawarden", "copy", "my-target"]).unwrap();
        match cli_default.command {
            Commands::Copy { field, .. } => assert!(field.is_none()),
            _ => panic!("Expected Commands::Copy"),
        }
    }

    #[test]
    fn test_clap_vault_create_card() {
        let card_cli = Cli::try_parse_from([
            "omawarden",
            "vault",
            "create",
            "card",
            "--name",
            "Corp Visa",
            "--cardholder-name",
            "Jane Doe",
            "--brand",
            "Visa",
            "--exp-month",
            "08",
            "--exp-year",
            "2029",
        ])
        .unwrap();
        match card_cli.command {
            Commands::Vault {
                action:
                    VaultAction::Create {
                        item:
                            Some(CreateItemAction::Card {
                                name,
                                cardholder_name,
                                brand,
                                exp_month,
                                exp_year,
                                ..
                            }),
                        ..
                    },
            } => {
                assert_eq!(name, "Corp Visa");
                assert_eq!(cardholder_name.as_deref(), Some("Jane Doe"));
                assert_eq!(brand.as_deref(), Some("Visa"));
                assert_eq!(exp_month.as_deref(), Some("08"));
                assert_eq!(exp_year.as_deref(), Some("2029"));
            }
            _ => panic!("Expected VaultAction::Create(Card)"),
        }

        // Security Rule 11 (Zero-Argv): sensitive card number and CVV must be rejected in argv
        assert!(
            Cli::try_parse_from([
                "omawarden",
                "vault",
                "create",
                "card",
                "--name",
                "Corp Visa",
                "--number",
                "4111111111111111",
            ])
            .is_err(),
            "--number must be rejected in argv (Zero-Argv Rule 11)"
        );
        assert!(
            Cli::try_parse_from([
                "omawarden",
                "vault",
                "create",
                "card",
                "--name",
                "Corp Visa",
                "--code",
                "123",
            ])
            .is_err(),
            "--code must be rejected in argv (Zero-Argv Rule 11)"
        );
    }

    #[test]
    fn test_clap_vault_create_identity_and_zero_argv_rule_11() {
        let id_cli = Cli::try_parse_from([
            "omawarden",
            "vault",
            "create",
            "identity",
            "--name",
            "Work ID",
            "--title",
            "Dr",
            "--first-name",
            "Ada",
            "--address3",
            "Suite B",
            "--country",
            "UK",
        ])
        .unwrap();
        match id_cli.command {
            Commands::Vault {
                action:
                    VaultAction::Create {
                        item:
                            Some(CreateItemAction::Identity {
                                name,
                                title,
                                first_name,
                                address3,
                                country,
                                ..
                            }),
                        ..
                    },
            } => {
                assert_eq!(name, "Work ID");
                assert_eq!(title.as_deref(), Some("Dr"));
                assert_eq!(first_name.as_deref(), Some("Ada"));
                assert_eq!(address3.as_deref(), Some("Suite B"));
                assert_eq!(country.as_deref(), Some("UK"));
            }
            _ => panic!("Expected VaultAction::Create(Identity)"),
        }

        // Security Rule 11 (Zero-Argv): sensitive ID numbers must be rejected in argv
        for bad_flag in ["--ssn", "--passport-number", "--license-number"] {
            assert!(
                Cli::try_parse_from([
                    "omawarden",
                    "vault",
                    "create",
                    "identity",
                    "--name",
                    "Work ID",
                    bad_flag,
                    "SECRET-123",
                ])
                .is_err(),
                "{bad_flag} must be rejected in argv (Zero-Argv Rule 11)"
            );
        }
    }

    #[test]
    fn test_attachment_download_cli_rejects_open_flag() {
        assert!(
            Cli::try_parse_from([
                "omawarden",
                "attachment",
                "download",
                "--item-id",
                "item-1",
                "--attachment-id",
                "att-1",
                "--filename",
                "secret.txt",
                "--open",
            ])
            .is_err(),
            "attachment download must reject removed --open flag"
        );

        let parsed = Cli::try_parse_from([
            "omawarden",
            "attachment",
            "download",
            "--item-id",
            "item-1",
            "--attachment-id",
            "att-1",
            "--filename",
            "secret.txt",
            "--output-dir",
            "/tmp/out",
            "--preview",
        ])
        .unwrap();
        match parsed.command {
            Commands::Attachment {
                action:
                    AttachmentAction::Download {
                        item_id,
                        attachment_id,
                        filename,
                        output_dir,
                        preview,
                        ..
                    },
            } => {
                assert_eq!(item_id, "item-1");
                assert_eq!(attachment_id, "att-1");
                assert_eq!(filename, "secret.txt");
                assert_eq!(output_dir.as_deref(), Some("/tmp/out"));
                assert!(preview);
            }
            _ => panic!("Expected AttachmentAction::Download"),
        }
    }

    #[test]
    fn test_attachment_upload_cli_parses_flags() {
        let parsed = Cli::try_parse_from([
            "omawarden",
            "attachment",
            "upload",
            "--item-id",
            "cipher-42",
            "--file",
            "/tmp/cert.pem",
            "--name",
            "prod-cert.pem",
            "--json",
        ])
        .unwrap();
        match parsed.command {
            Commands::Attachment {
                action:
                    AttachmentAction::Upload {
                        item_id,
                        file,
                        name,
                        json,
                        expected_lock_generation,
                    },
            } => {
                assert_eq!(item_id, "cipher-42");
                assert_eq!(file, PathBuf::from("/tmp/cert.pem"));
                assert_eq!(name.as_deref(), Some("prod-cert.pem"));
                assert!(json);
                assert_eq!(expected_lock_generation, None);
            }
            _ => panic!("Expected AttachmentAction::Upload"),
        }
    }

    #[test]
    fn test_attachment_delete_cli_parses_flags_and_aliases() {
        for subcmd in ["delete", "rm", "remove"] {
            let parsed = Cli::try_parse_from([
                "omawarden",
                "attachment",
                subcmd,
                "--item-id",
                "cipher-42",
                "--attachment-id",
                "att-99",
                "--yes",
                "--json",
            ])
            .unwrap();
            match parsed.command {
                Commands::Attachment {
                    action:
                        AttachmentAction::Delete {
                            item_id,
                            attachment_id,
                            yes,
                            json,
                            expected_lock_generation,
                        },
                } => {
                    assert_eq!(item_id, "cipher-42");
                    assert_eq!(attachment_id, "att-99");
                    assert!(yes);
                    assert!(json);
                    assert_eq!(expected_lock_generation, None);
                }
                _ => panic!("Expected AttachmentAction::Delete for alias '{subcmd}'"),
            }
        }
    }
}

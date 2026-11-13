mod clipboard_holder;

use clap::{Parser, Subcommand};
use omawarden::attachment::get_attachment;
use omawarden::auth::AuthManager;
use omawarden::clipboard::{ClipboardGuard, ClipboardScope};
use omawarden::config::{Config, ConfigManager, ConfigUpdateOptions};
use omawarden::daemon::{
    ensure_daemon_running, run_daemon_server, send_daemon_request, DaemonState,
};
use omawarden::health::check_system_health;
use omawarden::hook::install_lock_hook;
use omawarden::keyring::KeyringManager;
use omawarden::ssh::{
    generate_keypair, parse_private_key, write_keypair_files, write_keypair_files_named,
    SshAlgorithm,
};
use omawarden::storage::{StorageManager, VaultStorage};
use omawarden::totp::{generate_totp, TotpResult};
use omawarden::vault::{VaultItem, VaultManager};
use serde_json::{json, Value};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

/// Strict boolean for CLI flags: anything outside true/false/1/0/yes/no is a
/// parse error instead of silently becoming `false`. `--quick-unlock ture`
/// used to report success, persist `quick_unlock: false` and immediately
/// wipe the retained key.
fn parse_cli_bool(v: &str) -> Result<bool, String> {
    match v.trim().to_lowercase().as_str() {
        "true" | "1" | "yes" => Ok(true),
        "false" | "0" | "no" => Ok(false),
        other => Err(format!(
            "invalid boolean '{other}': expected one of true|false|1|0|yes|no"
        )),
    }
}

/// Parse one `NAME=VALUE` custom field declaration, rejecting a missing
/// separator or an empty name before the payload reaches the daemon.
fn parse_custom_field_name_value(raw: &str) -> Result<(String, String), String> {
    let Some((name, value)) = raw.split_once('=') else {
        return Err(format!(
            "Invalid custom field '{raw}': expected NAME=VALUE."
        ));
    };
    let name = name.trim();
    if name.is_empty() {
        return Err(format!(
            "Invalid custom field '{raw}': name cannot be empty."
        ));
    }
    Ok((name.to_string(), value.to_string()))
}

/// Build the encrypted-ready `fields` array (plaintext, encrypted by the
/// daemon) from the repeatable typed field flags. Text fields map to type 0,
/// hidden fields to type 1 and boolean fields to type 2.
fn build_custom_fields(
    fields: &[String],
    hidden_fields: &[String],
    bool_fields: &[String],
) -> Result<Vec<Value>, String> {
    let mut out = Vec::new();
    for raw in fields {
        let (name, value) = parse_custom_field_name_value(raw)?;
        out.push(json!({ "name": name, "value": value, "type": 0 }));
    }
    for raw in hidden_fields {
        let (name, value) = parse_custom_field_name_value(raw)?;
        out.push(json!({ "name": name, "value": value, "type": 1 }));
    }
    for raw in bool_fields {
        let (name, value) = parse_custom_field_name_value(raw)?;
        let canonical = match value.to_lowercase().as_str() {
            "true" => "true",
            "false" => "false",
            other => {
                return Err(format!(
                    "Invalid boolean value '{other}' for custom field '{name}': expected true or false."
                ));
            }
        };
        out.push(json!({ "name": name, "value": canonical, "type": 2 }));
    }
    Ok(out)
}

/// Auth output can carry a raw access token in `session`. Piped callers (the
/// QML helper) depend on it; an interactive terminal would only leave it
/// behind in scrollback, so redact it there.
fn print_json_redacting_session<T: serde::Serialize>(value: &T) {
    let mut val = serde_json::to_value(value).unwrap_or(Value::Null);
    if io::stdout().is_terminal() {
        if let Some(session) = val.get("session").and_then(Value::as_str) {
            if !session.is_empty() {
                val["session"] = json!("[redacted; pipe stdout to keep the token]");
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&val).unwrap());
}

#[derive(Parser)]
#[command(
    name = "omawarden",
    version = concat!(env!("CARGO_PKG_VERSION"), " (", env!("GIT_HASH"), " ", env!("BUILD_DATE"), ")"),
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

#[derive(Subcommand)]
enum ServerAction {
    #[command(about = "Inspect upstream server version and feature capabilities")]
    Capabilities {
        #[arg(long, help = "Force refresh capabilities from upstream server")]
        refresh: bool,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum SshAgentAction {
    #[command(about = "Show whether the agent is enabled and running, and its socket (JSON)")]
    Status,
    #[command(about = "Start the SSH agent")]
    Start {
        #[arg(long, alias = "force", help = "Bypass server capability gating checks")]
        ignore_server_capabilities: bool,
    },
    #[command(about = "List signatures waiting for confirmation (JSON)")]
    Pending,
    #[command(about = "Answer a pending confirmation")]
    Reply {
        #[arg(help = "Prompt id from `ssh-agent pending`")]
        id: u64,
        #[arg(long, conflicts_with = "deny", required_unless_present = "deny")]
        allow: bool,
        #[arg(long)]
        deny: bool,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum ConfigAction {
    #[command(about = "Get current configuration or a specific key")]
    Get {
        #[arg(help = "Optional configuration key to query")]
        key: Option<String>,
    },
    #[command(about = "Set configuration options")]
    Set {
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long)]
        identity_url: Option<String>,
        #[arg(long)]
        download_dir: Option<String>,
        #[arg(long)]
        auto_lock: Option<i64>,
        #[arg(long)]
        clipboard_clear: Option<i64>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        remember_email: Option<String>,
        #[arg(long)]
        check_updates: Option<String>,
        #[arg(long)]
        log_level: Option<String>,
        #[arg(long)]
        show_website_icons: Option<String>,
        #[arg(long)]
        remember_last_search: Option<String>,
        #[arg(long, help = "Maximum allowed attachment size in MB (default: 500)")]
        max_attachment_size: Option<u64>,
        #[arg(
            long,
            help = "Path to client certificate PEM file for mTLS (pass \"\" to clear)"
        )]
        client_cert: Option<String>,
        #[arg(long, help = "Path to separate client private key PEM file for mTLS")]
        client_key: Option<String>,
        #[arg(
            long,
            value_parser = parse_cli_bool,
            help = "Serve vault SSH keys as an SSH agent (true/false)"
        )]
        ssh_agent: Option<bool>,
        #[arg(long, help = "Confirm SSH signatures: always, first-use or never")]
        ssh_agent_confirm: Option<String>,
        #[arg(
            long,
            value_parser = parse_cli_bool,
            help = "Unlock via system authentication after a soft lock (true/false; ADR-0025)"
        )]
        quick_unlock: Option<bool>,
    },
}

#[derive(Subcommand)]
enum AuthAction {
    #[command(about = "Get current authentication and vault lock status")]
    Status,
    #[command(about = "Login using Master Password (credentials read from stdin)")]
    LoginPassword {
        #[arg(long, required = true)]
        email: String,
        #[arg(
            long,
            num_args = 0..=1,
            default_missing_value = "true",
            help = "Remember email address in configuration"
        )]
        remember_email: Option<String>,
    },
    #[command(about = "Login using API Key (client_secret read from stdin)")]
    LoginApikey {
        #[arg(long, required = true)]
        client_id: String,
    },
    #[command(
        about = "Send or resend two-factor verification code to email (password read from stdin)"
    )]
    SendTwoFactorEmail {
        #[arg(long, required = true)]
        email: String,
    },
    #[command(about = "Check current FIDO2 / WebAuthn environment and device status")]
    Fido2Status,
    #[command(about = "Unlock vault with master password (password read from stdin)")]
    Unlock,
    #[command(about = "Unlock vault via system authentication, polkit-backed (ADR-0025)")]
    QuickUnlock,
    #[command(about = "Report whether quick unlock is enabled and a retained key is available")]
    QuickUnlockCheck,
    #[command(about = "Lock vault and clear session")]
    Lock,
    #[command(about = "Logout from Bitwarden account")]
    Logout,
}

#[derive(Subcommand)]
enum HookAction {
    #[command(
        about = "Install optional system-lock hook into Omarchy hooks directory (daemon also auto-detects locks natively)"
    )]
    Install,
}

#[derive(Subcommand)]
enum VaultAction {
    #[command(about = "Sync vault from Bitwarden server")]
    Sync,
    #[command(about = "List all vault items")]
    List {
        #[arg(long = "filter")]
        category: Option<String>,
        #[arg(long, help = "List only soft-deleted items in the Trash")]
        trash: bool,
    },
    #[command(about = "Search vault items")]
    Search {
        #[arg(value_name = "QUERY", default_value = "")]
        query: String,
        #[arg(
            long = "query",
            help = "Search query string (alternative to positional argument)"
        )]
        query_flag: Option<String>,
        #[arg(long = "filter")]
        category: Option<String>,
        #[arg(long, help = "Search only soft-deleted items in the Trash")]
        trash: bool,
    },
    #[command(about = "Create a new vault cipher")]
    Create {
        #[command(subcommand)]
        item: Option<CreateItemAction>,
        #[arg(
            long,
            conflicts_with = "stdin",
            help = "Path to JSON file containing cipher payload"
        )]
        from_json: Option<PathBuf>,
        #[arg(
            long,
            conflicts_with = "from_json",
            help = "Read cipher payload JSON from standard input"
        )]
        stdin: bool,
        #[arg(long, global = true, help = "Output structured JSON")]
        json: bool,
    },
    #[command(
        about = "Delete a cipher from the vault",
        alias = "remove",
        alias = "rm"
    )]
    Delete {
        #[arg(
            value_name = "TARGET",
            help = "Target cipher name or 32-character / UUID ID to delete"
        )]
        target: String,
        #[arg(
            long,
            help = "Permanently delete the cipher instead of soft-deleting (moving to trash)"
        )]
        permanent: bool,
        #[arg(long, help = "Permanently delete a soft-deleted cipher from the Trash")]
        trash: bool,
        #[arg(
            short = 'y',
            long = "yes",
            help = "Skip confirmation prompt in interactive terminals"
        )]
        yes: bool,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(about = "Restore a soft-deleted cipher from the Trash")]
    Restore {
        #[arg(
            value_name = "TARGET",
            help = "Target trashed cipher name or 32-character / UUID ID to restore"
        )]
        target: String,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
    #[command(about = "Edit an existing vault cipher")]
    Edit {
        #[arg(
            value_name = "TARGET",
            help = "Target cipher name or 32-character / UUID ID to edit"
        )]
        target: String,
        #[arg(long, help = "New name for the cipher")]
        name: Option<String>,
        #[arg(long, help = "New username for login cipher")]
        username: Option<String>,
        #[arg(
            long,
            conflicts_with_all = ["password_stdin", "generate_password", "generate_passphrase"],
            help = "New password for login cipher"
        )]
        password: Option<String>,
        #[arg(
            long,
            conflicts_with_all = ["password", "generate_password", "generate_passphrase"],
            help = "Read new password from standard input"
        )]
        password_stdin: bool,
        #[arg(
            long,
            conflicts_with_all = ["password", "password_stdin", "generate_passphrase"],
            help = "Automatically generate a new 16-character high-entropy password"
        )]
        generate_password: bool,
        #[arg(
            long,
            conflicts_with_all = ["password", "password_stdin", "generate_password"],
            help = "Automatically generate a new 4-word Diceware passphrase"
        )]
        generate_passphrase: bool,
        #[arg(
            long,
            conflicts_with = "notes_stdin",
            help = "New notes for the cipher"
        )]
        notes: Option<String>,
        #[arg(
            long,
            conflicts_with = "notes",
            help = "Read new notes from standard input"
        )]
        notes_stdin: bool,
        #[arg(
            long = "uri",
            action = clap::ArgAction::Append,
            help = "New URI for login cipher (repeatable to replace URI list)"
        )]
        uris: Vec<String>,
        #[arg(
            long = "add-uri",
            action = clap::ArgAction::Append,
            conflicts_with = "clear_uris",
            help = "Append an additional URI to existing URIs"
        )]
        add_uris: Vec<String>,
        #[arg(
            long,
            conflicts_with_all = ["uris", "add_uris"],
            help = "Clear all URIs from login cipher"
        )]
        clear_uris: bool,
        #[arg(
            long = "field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Upsert a text custom field (NAME=VALUE; repeatable)"
        )]
        fields: Vec<String>,
        #[arg(
            long = "hidden-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Upsert a hidden custom field (NAME=VALUE; repeatable)"
        )]
        hidden_fields: Vec<String>,
        #[arg(
            long = "bool-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=true|false",
            help = "Upsert a boolean custom field (repeatable)"
        )]
        bool_fields: Vec<String>,
        #[arg(
            long = "remove-field",
            action = clap::ArgAction::Append,
            value_name = "NAME",
            help = "Remove a custom field by name (repeatable)"
        )]
        remove_fields: Vec<String>,
        #[arg(long, help = "Folder ID for the cipher")]
        folder_id: Option<String>,
        #[arg(
            long,
            value_parser = parse_cli_bool,
            help = "Favorite status (true/false)"
        )]
        favorite: Option<bool>,
        #[arg(long, help = "Output response in JSON format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum CreateItemAction {
    #[command(about = "Create a new Login cipher")]
    Login {
        #[arg(long, help = "Name of the login cipher")]
        name: String,
        #[arg(long, help = "Username")]
        username: String,
        #[arg(
            long,
            conflicts_with_all = ["password_stdin", "generate_password", "generate_passphrase"],
            help = "Password (prefer --password-stdin in automation/pipelines)"
        )]
        password: Option<String>,
        #[arg(
            long,
            conflicts_with_all = ["password", "generate_password", "generate_passphrase"],
            help = "Read password from standard input"
        )]
        password_stdin: bool,
        #[arg(
            long,
            conflicts_with_all = ["password", "password_stdin", "generate_passphrase"],
            help = "Automatically generate a 16-character high-entropy password"
        )]
        generate_password: bool,
        #[arg(
            long,
            conflicts_with_all = ["password", "password_stdin", "generate_password"],
            help = "Automatically generate a 4-word Diceware passphrase"
        )]
        generate_passphrase: bool,
        #[arg(long, help = "Optional notes")]
        notes: Option<String>,
        #[arg(
            long = "uri",
            action = clap::ArgAction::Append,
            help = "Optional URI (repeatable for multiple URLs)"
        )]
        uris: Vec<String>,
        #[arg(
            long = "field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Text custom field (repeatable)"
        )]
        fields: Vec<String>,
        #[arg(
            long = "hidden-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Hidden custom field (repeatable)"
        )]
        hidden_fields: Vec<String>,
        #[arg(
            long = "bool-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=true|false",
            help = "Boolean custom field (repeatable)"
        )]
        bool_fields: Vec<String>,
        #[arg(long, help = "Optional folder ID")]
        folder_id: Option<String>,
        #[arg(long, help = "Organization ID (organization ciphers are read-only)")]
        organization_id: Option<String>,
        #[arg(long, help = "Collection ID (organization ciphers are read-only)")]
        collection_id: Option<String>,
    },
    #[command(about = "Create a new Secure Note cipher", alias = "secure-note")]
    Note {
        #[arg(long, help = "Name of the secure note")]
        name: String,
        #[arg(
            long,
            required_unless_present = "notes_stdin",
            help = "Content of the secure note (prefer --notes-stdin for sensitive data)"
        )]
        notes: Option<String>,
        #[arg(
            long,
            conflicts_with = "notes",
            help = "Read note content from standard input"
        )]
        notes_stdin: bool,
        #[arg(
            long = "field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Text custom field (repeatable)"
        )]
        fields: Vec<String>,
        #[arg(
            long = "hidden-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=VALUE",
            help = "Hidden custom field (repeatable)"
        )]
        hidden_fields: Vec<String>,
        #[arg(
            long = "bool-field",
            action = clap::ArgAction::Append,
            value_name = "NAME=true|false",
            help = "Boolean custom field (repeatable)"
        )]
        bool_fields: Vec<String>,
        #[arg(long, help = "Optional folder ID")]
        folder_id: Option<String>,
        #[arg(long, help = "Organization ID (organization ciphers are read-only)")]
        organization_id: Option<String>,
        #[arg(long, help = "Collection ID (organization ciphers are read-only)")]
        collection_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum AttachmentAction {
    #[command(about = "Download or view an attachment")]
    Download {
        #[arg(long, required = true)]
        item_id: String,
        #[arg(long, required = true)]
        attachment_id: String,
        #[arg(long, required = true)]
        filename: String,
        #[arg(long)]
        output_dir: Option<String>,
        #[arg(long)]
        open: bool,
        #[arg(long)]
        preview: bool,
        #[arg(long, hide = true)]
        expected_lock_generation: Option<String>,
    },
    #[command(about = "Clean temporary preview attachments")]
    Clean {
        #[arg(long)]
        item_id: Option<String>,
    },
}

#[derive(Subcommand)]
enum SshKeyAction {
    #[command(about = "Generate a new SSH keypair and store it in Bitwarden")]
    Create {
        #[arg(long, required = true)]
        name: String,
        #[arg(long, default_value = "ed25519")]
        algorithm: SshAlgorithm,
        #[arg(long)]
        comment: Option<String>,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long, alias = "force", help = "Bypass server capability gating checks")]
        ignore_server_capabilities: bool,
    },
    #[command(about = "Import an existing SSH private key file or STDIN into Bitwarden")]
    Import {
        #[arg(long, required = true)]
        name: String,
        #[arg(long)]
        private_key: Option<PathBuf>,
        #[arg(long)]
        public_key: Option<PathBuf>,
        #[arg(long)]
        stdin: bool,
        #[arg(long)]
        notes: Option<String>,
        #[arg(long)]
        folder: Option<String>,
        #[arg(long, alias = "force", help = "Bypass server capability gating checks")]
        ignore_server_capabilities: bool,
    },
    #[command(about = "Export an SSH key to local file or standard output")]
    Export {
        #[arg(index = 1, required = true)]
        query: String,
        #[arg(long)]
        out_dir: Option<PathBuf>,
        #[arg(long)]
        private_key_file: Option<String>,
        #[arg(long)]
        public_key_file: Option<String>,
        #[arg(long)]
        stdout: bool,
        #[arg(long)]
        public_only: bool,
        #[arg(long)]
        private_only: bool,
    },
}

fn read_secret_stdin() -> String {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return String::new();
    }
    let mut buffer = String::new();
    if stdin.lock().read_line(&mut buffer).is_ok() {
        return buffer.trim_end_matches(&['\r', '\n'][..]).to_string();
    }
    String::new()
}

fn read_clipboard_stdin() -> String {
    let stdin = io::stdin();
    let mut raw = String::new();
    if stdin.lock().read_line(&mut raw).is_ok() {
        let trimmed = raw.trim_end_matches(&['\r', '\n'][..]);
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            if let Some(text) = val.get("text").and_then(|v| v.as_str()) {
                return text.to_string();
            }
        }
        let mut rest = String::new();
        let _ = stdin.lock().read_to_string(&mut rest);
        if rest.is_empty() {
            return trimmed.to_string();
        } else {
            return format!("{}{}", raw, rest);
        }
    }
    String::new()
}

fn parse_auth_payload(raw: &str) -> (String, Option<String>, Option<i32>, Option<String>) {
    let trimmed = raw.trim_end_matches(&['\r', '\n'][..]).trim();
    if trimmed.is_empty() {
        return (String::new(), None, None, None);
    }

    if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
        if let Some(map) = val.as_object() {
            let pwd = map
                .get("password")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let code_val = map
                .get("code")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let two_factor_provider = map
                .get("two_factor_provider")
                .or_else(|| map.get("twoFactorProvider"))
                .or_else(|| map.get("provider"))
                .and_then(|v| {
                    if let Some(n) = v.as_i64() {
                        Some(n as i32)
                    } else if let Some(s) = v.as_str() {
                        s.parse::<i32>().ok()
                    } else {
                        None
                    }
                });
            let new_device_otp = map
                .get("new_device_otp")
                .or_else(|| map.get("newDeviceOtp"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            return (pwd, code_val, two_factor_provider, new_device_otp);
        }
    }

    let mut pwd = trimmed.to_string();
    if pwd.starts_with('"') && pwd.ends_with('"') && pwd.len() >= 2 {
        if let Ok(unescaped) = serde_json::from_str::<String>(&pwd) {
            pwd = unescaped;
        }
    }

    (pwd, None, None, None)
}

fn read_auth_payload() -> (String, Option<String>, Option<i32>, Option<String>) {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return (String::new(), None, None, None);
    }
    let mut buffer = String::new();
    if stdin.lock().read_line(&mut buffer).is_err() {
        return (String::new(), None, None, None);
    }
    parse_auth_payload(&buffer)
}

fn main() -> ExitCode {
    // Disable process tracing (ptrace) and core dump generation for memory
    // defense. Fail-open is accepted (a desktop helper should not refuse to
    // run over prctl), but never silently: without this the whole process
    // stays ptraceable and core-dumpable.
    if let Err(e) = omawarden::locked::disable_dumpable() {
        omawarden::log_error!(
            "omawarden:locked",
            "Could not disable ptrace/core dumps (prctl PR_SET_DUMPABLE: {e}); tracing protections are INACTIVE for this process"
        );
    }

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
        } => {
            let active_path = binary_path.as_deref().or(legacy_path.as_deref());
            let resolved_provider =
                omawarden::clipboard::resolve_provider(provider.as_deref(), active_path);
            let scope = expected_lock_generation
                .map(ClipboardScope::Session)
                .or_else(|| {
                    cache_path
                        .zip(expected_credential_id)
                        .map(|(path, credential_id)| ClipboardScope::Cache {
                            path,
                            credential_id,
                        })
                });
            match clipboard_holder::hold_selection(
                resolved_provider,
                std::time::Duration::from_secs(seconds),
                !public,
                scope.as_ref(),
            ) {
                Ok(()) => ExitCode::SUCCESS,
                Err(_) => ExitCode::FAILURE,
            }
        }
        Commands::Daemon {
            auto_lock,
            stop,
            action,
        } => {
            if stop || action.as_deref() == Some("stop") {
                let client = omawarden::daemon::DaemonClient::new();
                let resp = client.send_raw(&json!({ "action": "stop", "admin": true }));
                match resp {
                    Ok(val) if val.get("ok") == Some(&Value::Bool(true)) => {
                        println!("{}", serde_json::to_string_pretty(&val).unwrap());
                        ExitCode::SUCCESS
                    }
                    Ok(val) => {
                        eprintln!("{}", serde_json::to_string_pretty(&val).unwrap());
                        ExitCode::FAILURE
                    }
                    Err(omawarden::daemon::DispatchError::NotSent) => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": true,
                                "status": "stopped",
                                "message": "Daemon is not running."
                            }))
                            .unwrap()
                        );
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": e.to_string(),
                            }))
                            .unwrap()
                        );
                        ExitCode::FAILURE
                    }
                }
            } else {
                let default_auto_lock = if cfg.auto_lock_minutes >= 0 {
                    cfg.auto_lock_minutes as u64
                } else {
                    15
                };
                let auto_lock_mins = auto_lock.unwrap_or(default_auto_lock);
                let storage_mgr = match cli.config.as_deref() {
                    Some(cp) => {
                        if let Some(parent) = cp.parent() {
                            StorageManager::new(
                                parent.join(omawarden::storage::DEFAULT_STORAGE_FILENAME),
                            )
                        } else {
                            StorageManager::default()
                        }
                    }
                    None => StorageManager::default(),
                };
                let state = Arc::new(DaemonState::new(storage_mgr, auto_lock_mins));
                println!(
                    "Starting omawarden daemon (auto_lock: {}m)...",
                    auto_lock_mins
                );
                if let Err(e) = run_daemon_server(state) {
                    eprintln!("Daemon server error: {}", e);
                    ExitCode::FAILURE
                } else {
                    ExitCode::SUCCESS
                }
            }
        }

        Commands::Config { action } => match action {
            ConfigAction::Get { key } => {
                if let Some(k) = key {
                    match k.as_str() {
                        "server_url" => println!("{}", cfg.server_url),
                        "identity_url" => println!("{}", cfg.identity_url.as_deref().unwrap_or("")),
                        "download_dir" => println!("{}", cfg.download_dir),
                        "auto_lock_minutes" | "auto_lock" => println!("{}", cfg.auto_lock_minutes),
                        "clipboard_clear_seconds" | "clipboard_clear" => {
                            println!("{}", cfg.clipboard_clear_seconds)
                        }
                        "email" => println!("{}", cfg.email),
                        "remember_email" => println!("{}", cfg.remember_email),
                        "check_updates" => println!("{}", cfg.check_updates),
                        "log_level" => println!("{}", cfg.log_level),
                        "show_website_icons" => println!("{}", cfg.show_website_icons),
                        "remember_last_search" => println!("{}", cfg.remember_last_search),
                        "max_attachment_size_mb" | "max_attachment_size" => {
                            println!("{}", cfg.max_attachment_size_mb)
                        }
                        "client_cert_path" | "client_cert" => {
                            println!("{}", cfg.client_cert_path.as_deref().unwrap_or(""))
                        }
                        "client_key_path" | "client_key" => {
                            println!("{}", cfg.client_key_path.as_deref().unwrap_or(""))
                        }
                        "client_cert_server" => {
                            println!("{}", cfg.client_cert_server.as_deref().unwrap_or(""))
                        }
                        "ssh_agent_enabled" | "ssh_agent" => println!("{}", cfg.ssh_agent_enabled),
                        "quick_unlock" => println!("{}", cfg.quick_unlock),
                        "ssh_agent_confirm" => println!("{}", cfg.ssh_agent_confirm),
                        _ => {
                            eprintln!("Unknown configuration key: {}", k);
                            return ExitCode::FAILURE;
                        }
                    }
                } else {
                    println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
                }
                ExitCode::SUCCESS
            }
            ConfigAction::Set {
                server_url,
                identity_url,
                download_dir,
                auto_lock,
                clipboard_clear,
                email,
                remember_email,
                check_updates,
                log_level,
                show_website_icons,
                remember_last_search,
                max_attachment_size,
                client_cert,
                client_key,
                ssh_agent,
                ssh_agent_confirm,
                quick_unlock,
            } => {
                let storage_mgr = match cli.config.as_deref() {
                    Some(cp) => {
                        if let Some(parent) = cp.parent() {
                            StorageManager::new(
                                parent.join(omawarden::storage::DEFAULT_STORAGE_FILENAME),
                            )
                        } else {
                            StorageManager::default()
                        }
                    }
                    None => StorageManager::default(),
                };
                let keyring_mgr = KeyringManager::default();

                let parsed_remember_email = remember_email.map(|v| {
                    let lower = v.trim().to_lowercase();
                    matches!(lower.as_str(), "true" | "1" | "yes")
                });
                let parsed_check_updates = check_updates.map(|v| {
                    let lower = v.trim().to_lowercase();
                    matches!(lower.as_str(), "true" | "1" | "yes")
                });

                let parsed_show_website_icons = show_website_icons.map(|v| {
                    let lower = v.trim().to_lowercase();
                    matches!(lower.as_str(), "true" | "1" | "yes")
                });

                let parsed_remember_last_search = remember_last_search.map(|v| {
                    let lower = v.trim().to_lowercase();
                    matches!(lower.as_str(), "true" | "1" | "yes")
                });

                if let Some(ref cert_str) = client_cert {
                    let trimmed = cert_str.trim();
                    if !trimmed.is_empty() {
                        let cert_path = std::path::Path::new(trimmed);
                        if !cert_path.exists() {
                            eprintln!(
                                "Error: Client certificate file not found: '{}'",
                                cert_path.display()
                            );
                            return ExitCode::FAILURE;
                        }
                        let key_target = if let Some(ref key_str) = client_key {
                            let key_trimmed = key_str.trim();
                            if !key_trimmed.is_empty() {
                                std::path::Path::new(key_trimmed)
                            } else {
                                cert_path
                            }
                        } else {
                            cert_path
                        };

                        if !key_target.exists() {
                            eprintln!(
                                "Error: Client private key file not found: '{}'",
                                key_target.display()
                            );
                            return ExitCode::FAILURE;
                        }

                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            if let Ok(meta) = std::fs::metadata(key_target) {
                                let mode = meta.permissions().mode() & 0o777;
                                if mode & 0o077 != 0 {
                                    eprintln!(
                                        "Error: Insecure permissions ({:#o}) on client private key '{}': file must be restricted to 0600 or 0400 (run `chmod 600 {}`)",
                                        mode,
                                        key_target.display(),
                                        key_target.display()
                                    );
                                    return ExitCode::FAILURE;
                                }
                            }
                        }
                    }
                }

                let options = ConfigUpdateOptions {
                    server_url,
                    identity_url,
                    download_dir,
                    auto_lock_minutes: auto_lock,
                    clipboard_clear_seconds: clipboard_clear,
                    email,
                    remember_email: parsed_remember_email,
                    check_updates: parsed_check_updates,
                    log_level,
                    show_website_icons: parsed_show_website_icons,
                    remember_last_search: parsed_remember_last_search,
                    max_attachment_size_mb: max_attachment_size,
                    client_cert_path: client_cert,
                    client_key_path: client_key,
                    ssh_agent_enabled: ssh_agent,
                    ssh_agent_confirm: ssh_agent_confirm.clone(),
                    quick_unlock,
                };

                let (updated_cfg, _server_changed) =
                    match config_mgr.update_config(options, &storage_mgr, &keyring_mgr) {
                        Ok(res) => res,
                        Err(e) => {
                            eprintln!("Failed to save configuration: {}", e);
                            return ExitCode::FAILURE;
                        }
                    };
                cfg = updated_cfg;
                if ssh_agent.is_some() {
                    // Start or stop the agent in the running daemon (no restart, so no lock).
                    let _ = send_daemon_request(&json!({ "action": "ssh_agent_apply" }));
                }
                if let Some(lock_mins) = auto_lock {
                    let _ = send_daemon_request(&json!({
                        "action": "set_auto_lock",
                        "auto_lock_minutes": lock_mins
                    }));
                }
                let safe_url = if cfg.server_url.is_empty() {
                    "default (official)".to_string()
                } else if let Ok(parsed) = url::Url::parse(&cfg.server_url) {
                    if let Some(host) = parsed.host_str() {
                        if host == "vault.bitwarden.com"
                            || host == "api.bitwarden.com"
                            || host == "bitwarden.com"
                            || host == "vault.bitwarden.eu"
                            || host == "api.bitwarden.eu"
                            || host == "bitwarden.eu"
                        {
                            format!("{}://{}", parsed.scheme(), host)
                        } else {
                            "<REDACTED_CUSTOM_HOST>".to_string()
                        }
                    } else {
                        "<REDACTED_CUSTOM_HOST>".to_string()
                    }
                } else {
                    "<REDACTED_CUSTOM_HOST>".to_string()
                };
                let safe_id_url = if let Some(ref u) = cfg.identity_url {
                    if let Ok(parsed) = url::Url::parse(u) {
                        if let Some(host) = parsed.host_str() {
                            if host == "identity.bitwarden.com" || host == "identity.bitwarden.eu" {
                                format!("{}://{}", parsed.scheme(), host)
                            } else {
                                "<REDACTED_CUSTOM_HOST>".to_string()
                            }
                        } else {
                            "<REDACTED_CUSTOM_HOST>".to_string()
                        }
                    } else {
                        "<REDACTED_CUSTOM_HOST>".to_string()
                    }
                } else {
                    "auto".to_string()
                };
                omawarden::log_info!(
                    "omawarden:config",
                    "Updated configuration (log_level: {}, server_url: {}, identity_url: {}).",
                    cfg.log_level,
                    safe_url,
                    safe_id_url
                );
                println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
                ExitCode::SUCCESS
            }
        },

        Commands::SshAgent {
            ignore_server_capabilities,
            action,
        } => match action {
            None | Some(SshAgentAction::Start { .. }) => {
                let bypass = ignore_server_capabilities
                    || matches!(
                        action,
                        Some(SshAgentAction::Start {
                            ignore_server_capabilities: true
                        })
                    );

                if let Err(e) = omawarden::capabilities::check_feature_gating(
                    &cfg.server_url,
                    "ssh-key-vault-item",
                    bypass,
                ) {
                    let err_msg = format!("Refusing to launch SSH agent: {e}");
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": false,
                            "error": err_msg,
                        }))
                        .unwrap()
                    );
                    return ExitCode::FAILURE;
                }

                let _ = ensure_daemon_running();
                let request = json!({
                    "action": "ssh_agent_apply",
                    "ignore_server_capabilities": bypass
                });
                match send_daemon_request(&request) {
                    Some(resp) => {
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                        if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        }
                    }
                    None => {
                        eprintln!("The omawarden daemon is not responding.");
                        ExitCode::FAILURE
                    }
                }
            }
            Some(sub_action) => {
                let request = match sub_action {
                    SshAgentAction::Status => json!({ "action": "ssh_agent_status" }),
                    SshAgentAction::Pending => json!({ "action": "ssh_agent_pending" }),
                    SshAgentAction::Reply { id, allow, deny: _ } => {
                        json!({ "action": "ssh_agent_reply", "id": id, "approve": allow })
                    }
                    SshAgentAction::Start { .. } => unreachable!(),
                };
                let _ = ensure_daemon_running();
                match send_daemon_request(&request) {
                    Some(mut resp) => {
                        if let Some(obj) = resp.as_object_mut() {
                            obj.insert("enabled".into(), json!(cfg.ssh_agent_enabled));
                            obj.insert("confirm".into(), json!(cfg.ssh_agent_confirm));
                        }
                        println!("{}", serde_json::to_string_pretty(&resp).unwrap());
                        let delivered = resp
                            .get("delivered")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(true);
                        if resp.get("ok").and_then(|v| v.as_bool()).unwrap_or(false) && delivered {
                            ExitCode::SUCCESS
                        } else {
                            ExitCode::FAILURE
                        }
                    }
                    None => {
                        eprintln!("The omawarden daemon is not responding.");
                        ExitCode::FAILURE
                    }
                }
            }
        },

        Commands::Health => {
            let status = check_system_health(&cfg.server_url);
            println!("{}", serde_json::to_string_pretty(&status).unwrap());
            ExitCode::SUCCESS
        }

        Commands::Doctor { json } => {
            let status = check_system_health(&cfg.server_url);
            if json {
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            } else {
                println!("System Diagnostics:");
                let ver_str = status.version.as_deref().unwrap_or("unknown");
                let commit_str = status
                    .commit
                    .as_deref()
                    .map(|c| format!(" (commit {})", c))
                    .unwrap_or_default();
                println!("  CLI Version:        v{}{}", ver_str, commit_str);
                println!(
                    "  Keyring:            {}",
                    if status.keyring_available {
                        "[OK] Available (secret-tool)"
                    } else {
                        "[FAIL] Unavailable"
                    }
                );
                println!(
                    "  Clipboard Guard:    {}",
                    if status.clipboard_available {
                        "[OK] Available"
                    } else {
                        "[FAIL] Unavailable"
                    }
                );

                println!("\nUpstream Capabilities:");
                println!("  Server URL:         {}", status.server_url);
                println!(
                    "  Server Reachable:   {}",
                    if status.server_reachable {
                        "[OK] Yes"
                    } else {
                        "[FAIL] No"
                    }
                );

                if let Some(ref caps) = status.upstream_capabilities {
                    if let Some(ref n) = caps.server_name {
                        println!("  Server Name:        {}", n);
                    }
                    if let Some(ref v) = caps.server_version {
                        println!("  Server Version:     {}", v);
                    }
                    if let Some(ref v) = caps.server_vendor_version {
                        println!("  Vendor Version:     {}", v);
                    }
                    if let Some(ref g) = caps.git_hash {
                        println!("  Git Hash:           {}", g);
                    }
                    println!("  Features:");
                    for detail in &caps.details {
                        println!("    - {}", detail);
                    }
                    if !caps.recommendations.is_empty() {
                        println!("  Recommendations:");
                        for rec in &caps.recommendations {
                            println!("    - {}", rec);
                        }
                    }
                } else if !status.server_reachable {
                    println!("  Capabilities:       [--] Skipped (server unreachable)");
                } else {
                    println!("  Capabilities:       [--] Detection failed or unavailable");
                }

                println!(
                    "\nHealth Verdict:       {}",
                    if status.ok {
                        "[OK] All checks passed."
                    } else {
                        "[WARN] Some health checks failed or degraded."
                    }
                );
                if let Some(ref err) = status.error {
                    println!("  Failure Reason:     {}", err);
                }
            }
            if status.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }

        Commands::Auth { action } => {
            let auth_mgr = AuthManager::with_config(
                &cfg.server_url,
                cfg.identity_url.as_deref(),
                None,
                None,
                Some(config_mgr.clone()),
            );
            match action {
                AuthAction::Status => {
                    if let Err(e @ omawarden::daemon::DispatchError::IncompatibleProtocol { .. }) =
                        omawarden::daemon::ensure_daemon_running()
                    {
                        let st = json!({
                            "status": "incompatible_daemon",
                            "error": e.to_string(),
                        });
                        println!("{}", serde_json::to_string_pretty(&st).unwrap());
                        return ExitCode::FAILURE;
                    }
                    let st = auth_mgr.get_status(false);
                    println!("{}", serde_json::to_string_pretty(&st).unwrap());
                    ExitCode::SUCCESS
                }
                AuthAction::LoginPassword {
                    email,
                    remember_email,
                } => {
                    let (pwd, stdin_code, stdin_provider, stdin_new_device_otp) =
                        if io::stdin().is_terminal() {
                            let p = rpassword::prompt_password("Enter Master Password: ")
                                .unwrap_or_default();
                            (p, None, None, None)
                        } else {
                            read_auth_payload()
                        };
                    let mut effective_code = stdin_code;
                    let mut effective_provider = stdin_provider;
                    let mut effective_new_device_otp = stdin_new_device_otp;
                    let mut res = auth_mgr.login_password(
                        &email,
                        &pwd,
                        effective_code.as_deref(),
                        effective_provider,
                        effective_new_device_otp.as_deref(),
                    );
                    if !res.ok
                        && effective_code.is_none()
                        && effective_new_device_otp.is_none()
                        && io::stdin().is_terminal()
                    {
                        if res.new_device_verification_required == Some(true) {
                            let prompt_code = rpassword::prompt_password(
                                "Enter New Device Verification Code (check your email): ",
                            )
                            .unwrap_or_default();
                            if !prompt_code.trim().is_empty() {
                                effective_new_device_otp = Some(prompt_code.trim().to_string());
                                res = auth_mgr.login_password(
                                    &email,
                                    &pwd,
                                    None,
                                    None,
                                    effective_new_device_otp.as_deref(),
                                );
                            }
                        } else if res.two_factor_required == Some(true) {
                            let mut providers =
                                res.two_factor_providers.clone().unwrap_or_else(|| vec![0]);
                            // A server reporting two_factor_required with an empty
                            // providers list would panic on providers[default_idx]
                            // below; fall back to the authenticator-app provider.
                            if providers.is_empty() {
                                providers.push(0);
                            }
                            let default_idx = if let Some(pref) = res.two_factor_provider {
                                providers.iter().position(|p| *p == pref).unwrap_or(0)
                            } else {
                                0
                            };
                            let chosen_provider = if providers.len() == 1 {
                                providers[0]
                            } else {
                                eprintln!("\nTwo-Factor Authentication Methods:");
                                for (idx, p) in providers.iter().enumerate() {
                                    let label = match p {
                                        0 => "Authenticator App (TOTP)".to_string(),
                                        1 => "Email Verification Code".to_string(),
                                        3 => "YubiKey OTP".to_string(),
                                        7 => match res.fido2_status.as_deref() {
                                            Some("tool_not_found") => {
                                                "WebAuthn / Passkey / Security Key (libfido2 not installed)".to_string()
                                            }
                                            Some("no_device") => {
                                                "WebAuthn / Passkey / Security Key (no key detected)".to_string()
                                            }
                                            _ => "WebAuthn / Passkey / Security Key".to_string(),
                                        },
                                        _ => "Other".to_string(),
                                    };
                                    eprintln!("  [{}] {}", idx + 1, label);
                                }
                                eprint!(
                                    "Select method [1-{}, default: {}]: ",
                                    providers.len(),
                                    default_idx + 1
                                );
                                let _ = io::stderr().flush();
                                let mut choice = String::new();
                                let _ = io::stdin().read_line(&mut choice);
                                let idx = choice
                                    .trim()
                                    .parse::<usize>()
                                    .unwrap_or(default_idx + 1)
                                    .saturating_sub(1);
                                *providers.get(idx).unwrap_or(&providers[default_idx])
                            };

                            effective_provider = Some(chosen_provider);
                            if chosen_provider == 7 {
                                omawarden::log_info!(
                                    "omawarden:auth",
                                    "Requesting WebAuthn challenge from server..."
                                );
                                res = auth_mgr.login_password(&email, &pwd, None, Some(7), None);
                            } else {
                                let prompt_label = match chosen_provider {
                                    1 => {
                                        "Enter Email Two-Factor Verification Code (check your email): "
                                    }
                                    3 => "Touch your YubiKey or enter OTP: ",
                                    _ => "Enter Two-Factor (2FA) Code: ",
                                };
                                let prompt_code =
                                    rpassword::prompt_password(prompt_label).unwrap_or_default();
                                if !prompt_code.trim().is_empty() {
                                    effective_code = Some(prompt_code.trim().to_string());
                                    res = auth_mgr.login_password(
                                        &email,
                                        &pwd,
                                        effective_code.as_deref(),
                                        effective_provider,
                                        None,
                                    );
                                }
                            }
                        }
                    }
                    if res.ok {
                        if let Some(ref rem) = remember_email {
                            let should_remember =
                                matches!(rem.to_lowercase().as_str(), "true" | "1" | "yes");
                            let mut latest_cfg = config_mgr.load();
                            latest_cfg.remember_email = should_remember;
                            if should_remember {
                                latest_cfg.email = email.trim().to_lowercase();
                            } else {
                                latest_cfg.email.clear();
                            }
                            let _ = config_mgr.save(&latest_cfg);
                        }
                    }
                    print_json_redacting_session(&res);
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::LoginApikey { client_id } => {
                    let actual_secret = if io::stdin().is_terminal() {
                        rpassword::prompt_password("Enter Client Secret: ").unwrap_or_default()
                    } else {
                        let raw_secret = read_secret_stdin();
                        let mut secret = raw_secret.clone();
                        if raw_secret.starts_with('{') && raw_secret.ends_with('}') {
                            if let Ok(val) = serde_json::from_str::<Value>(&raw_secret) {
                                if let Some(s) = val.get("client_secret").and_then(|v| v.as_str()) {
                                    secret = s.to_string();
                                }
                            }
                        }
                        secret
                    };
                    let res = auth_mgr.login_apikey(&client_id, &actual_secret);
                    print_json_redacting_session(&res);
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::SendTwoFactorEmail { email } => {
                    let (pwd, _, _, _) = if io::stdin().is_terminal() {
                        let p = rpassword::prompt_password("Enter Master Password: ")
                            .unwrap_or_default();
                        (p, None, None, None)
                    } else {
                        read_auth_payload()
                    };
                    if pwd.is_empty() {
                        let res = serde_json::json!({
                            "ok": false,
                            "error": "Password is required to send verification code."
                        });
                        print_json_redacting_session(&res);
                        ExitCode::FAILURE
                    } else {
                        match auth_mgr.send_two_factor_email(&email, &pwd) {
                            Ok(()) => {
                                let res = serde_json::json!({
                                    "ok": true,
                                    "message": "Two-factor verification code sent to your email."
                                });
                                print_json_redacting_session(&res);
                                ExitCode::SUCCESS
                            }
                            Err(e) => {
                                let res = serde_json::json!({
                                    "ok": false,
                                    "error": e.to_string()
                                });
                                print_json_redacting_session(&res);
                                ExitCode::FAILURE
                            }
                        }
                    }
                }
                AuthAction::Fido2Status => {
                    let status = omawarden::webauthn::check_fido2_status();
                    let res = serde_json::json!({
                        "ok": true,
                        "status": status.as_str()
                    });
                    print_json_redacting_session(&res);
                    ExitCode::SUCCESS
                }
                AuthAction::Unlock => {
                    let pwd = if io::stdin().is_terminal() {
                        rpassword::prompt_password("Enter Master Password: ").unwrap_or_default()
                    } else {
                        read_secret_stdin()
                    };
                    let res = auth_mgr.unlock(&pwd);
                    print_json_redacting_session(&res);
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::QuickUnlock => {
                    if let Err(e @ omawarden::daemon::DispatchError::IncompatibleProtocol { .. }) =
                        omawarden::daemon::ensure_daemon_running()
                    {
                        let resp = json!({
                            "ok": false,
                            "status": "locked",
                            "error": e.to_string(),
                        });
                        print_json_redacting_session(&resp);
                        return ExitCode::FAILURE;
                    }
                    let client = omawarden::daemon::DaemonClient::new()
                        .with_timeout(Some(Duration::from_secs(130)));
                    let resp = match client.send(&json!({ "action": "quick_unlock" })) {
                        Ok(resp) => resp,
                        Err(omawarden::daemon::DispatchError::IncompatibleProtocol {
                            running,
                            min_supported,
                            current,
                        }) => json!({
                            "ok": false,
                            "status": "locked",
                            "error": format!("Incompatible daemon protocol version {running} (supported: {min_supported}..={current}). Please restart the daemon.")
                        }),
                        Err(_) => json!({
                            "ok": false,
                            "status": "locked",
                            "error": "omawarden daemon is not running."
                        }),
                    };
                    print_json_redacting_session(&resp);
                    if resp.get("ok").and_then(Value::as_bool).unwrap_or(false) {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::QuickUnlockCheck => {
                    // Prefer the daemon as the single source: its ping carries
                    // both the cached setting and the readiness it gates, so
                    // the two can no longer come from disagreeing files. The
                    // fields degrade independently: a daemon older than this
                    // feature reports readiness (quick_unlock) but not the
                    // cached setting (quick_unlock_enabled), which then falls
                    // back to the config file; no daemon at all means no
                    // readiness and a config-file setting.
                    let ping = match omawarden::daemon::dispatch_daemon_request(
                        &json!({ "action": "ping" }),
                    ) {
                        Ok(p) => Some(p),
                        Err(e @ omawarden::daemon::DispatchError::IncompatibleProtocol { .. }) => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": e.to_string(),
                                }))
                                .unwrap()
                            );
                            return ExitCode::FAILURE;
                        }
                        Err(_) => None,
                    };
                    let field = |name: &str| {
                        ping.as_ref()
                            .and_then(|r| r.get(name))
                            .and_then(Value::as_bool)
                    };
                    let available = field("quick_unlock").unwrap_or(false);
                    let enabled = field("quick_unlock_enabled")
                        .unwrap_or_else(|| ConfigManager::default().load().quick_unlock);
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "enabled": enabled,
                            "available": available,
                        }))
                        .unwrap()
                    );
                    ExitCode::SUCCESS
                }
                AuthAction::Lock => {
                    let res = auth_mgr.lock();
                    print_json_redacting_session(&res);
                    ExitCode::SUCCESS
                }
                AuthAction::Logout => {
                    let res = auth_mgr.logout();
                    print_json_redacting_session(&res);
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
            }
        }

        Commands::Hook { action } => match action {
            HookAction::Install => match install_lock_hook(None, None) {
                Ok(path) => {
                    let json_val = serde_json::json!({
                        "ok": true,
                        "installed_path": path.to_string_lossy(),
                        "note": "Lock hook installed. omawarden daemon also natively auto-detects screen lock, sleep, and Omarchy shell lock."
                    });
                    println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    let json_val = serde_json::json!({
                        "ok": false,
                        "error": e.to_string()
                    });
                    println!("{}", serde_json::to_string_pretty(&json_val).unwrap());
                    ExitCode::FAILURE
                }
            },
        },

        Commands::Vault { action } => {
            let vault_mgr = VaultManager::with_identity_url(
                &cfg.server_url,
                cfg.identity_url.as_deref(),
                None,
                None,
            );
            match action {
                VaultAction::Sync => {
                    let client_ctx = omawarden::api::resolve_effective_client_context(None);
                    if let Err(e @ omawarden::daemon::DispatchError::IncompatibleProtocol { .. }) =
                        omawarden::daemon::ensure_daemon_running()
                    {
                        let resp_val = json!({
                            "ok": false,
                            "error": e.to_string(),
                        });
                        println!("{}", serde_json::to_string_pretty(&resp_val).unwrap());
                        return ExitCode::FAILURE;
                    }
                    let mut sync_req = json!({ "action": "sync" });
                    if let Some(ref ctx) = client_ctx {
                        sync_req["client"] = json!(ctx);
                    }
                    let resp_val = match omawarden::daemon::dispatch_daemon_request(&sync_req) {
                        Ok(response) => response,
                        Err(omawarden::daemon::DispatchError::NotSent) => json!({
                            "ok": false,
                            "error": "Cannot reach the vault daemon. Restart it and retry synchronization."
                        }),
                        Err(omawarden::daemon::DispatchError::Unconfirmed) => json!({
                            "ok": false,
                            "error": "Could not confirm synchronization. Check the vault before retrying."
                        }),
                        Err(omawarden::daemon::DispatchError::IncompatibleProtocol {
                            running,
                            min_supported,
                            current,
                        }) => json!({
                            "ok": false,
                            "error": format!("Incompatible daemon protocol version {running} (supported: {min_supported}..={current}). Please restart the daemon.")
                        }),
                        Err(omawarden::daemon::DispatchError::LaunchFailed(msg)) => json!({
                            "ok": false,
                            "error": format!("Could not start the daemon: {msg}")
                        }),
                    };
                    let ok = resp_val["ok"].as_bool().unwrap_or(false);
                    println!("{}", serde_json::to_string_pretty(&resp_val).unwrap());
                    if ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                VaultAction::List { category, trash } => {
                    if let Err(e @ omawarden::daemon::DispatchError::IncompatibleProtocol { .. }) =
                        omawarden::daemon::ensure_daemon_running()
                    {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": e.to_string(),
                            }))
                            .unwrap()
                        );
                        return ExitCode::FAILURE;
                    }
                    let st = send_daemon_request(&json!({ "action": "status" }));
                    let is_unlocked = st
                        .as_ref()
                        .and_then(|v| v.get("is_unlocked"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !is_unlocked && !vault_mgr.is_unlocked() {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": "Vault is locked. Please unlock using 'omawarden auth unlock' first."
                            }))
                            .unwrap()
                        );
                        return ExitCode::FAILURE;
                    }
                    if is_unlocked && !vault_mgr.is_unlocked() {
                        if let Some(daemon_resp) =
                            send_daemon_request(&json!({ "action": "list", "trash": trash }))
                        {
                            if daemon_resp.get("ok") == Some(&Value::Bool(false)) {
                                println!("{}", serde_json::to_string_pretty(&daemon_resp).unwrap());
                                return ExitCode::FAILURE;
                            }
                            if let Ok(items) = serde_json::from_value::<
                                Vec<omawarden::vault::VaultItem>,
                            >(daemon_resp)
                            {
                                let filtered = vault_mgr.search(&items, "", category.as_deref());
                                println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
                                return ExitCode::SUCCESS;
                            }
                        } else {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": "Cannot reach the vault daemon to list items."
                                }))
                                .unwrap()
                            );
                            return ExitCode::FAILURE;
                        }
                    }
                    let items = vault_mgr.get_items_by_state(trash);
                    let filtered = vault_mgr.search(&items, "", category.as_deref());
                    println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
                    ExitCode::SUCCESS
                }
                VaultAction::Search {
                    query,
                    query_flag,
                    category,
                    trash,
                } => {
                    let query = if query.is_empty() {
                        query_flag.unwrap_or(query)
                    } else {
                        query
                    };
                    if let Err(e @ omawarden::daemon::DispatchError::IncompatibleProtocol { .. }) =
                        omawarden::daemon::ensure_daemon_running()
                    {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": e.to_string(),
                            }))
                            .unwrap()
                        );
                        return ExitCode::FAILURE;
                    }
                    let st = send_daemon_request(&json!({ "action": "status" }));
                    let is_unlocked = st
                        .as_ref()
                        .and_then(|v| v.get("is_unlocked"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !is_unlocked && !vault_mgr.is_unlocked() {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": "Vault is locked. Please unlock using 'omawarden auth unlock' first."
                            }))
                            .unwrap()
                        );
                        return ExitCode::FAILURE;
                    }
                    if is_unlocked && !vault_mgr.is_unlocked() {
                        if let Some(daemon_resp) = send_daemon_request(&json!({
                            "action": "search",
                            "query": query,
                            "category": category,
                            "trash": trash
                        })) {
                            if daemon_resp.get("ok") == Some(&Value::Bool(false)) {
                                println!("{}", serde_json::to_string_pretty(&daemon_resp).unwrap());
                                return ExitCode::FAILURE;
                            }
                            if let Ok(items) = serde_json::from_value::<
                                Vec<omawarden::vault::VaultItem>,
                            >(daemon_resp)
                            {
                                println!("{}", serde_json::to_string_pretty(&items).unwrap());
                                return ExitCode::SUCCESS;
                            }
                        } else {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": "Cannot reach the vault daemon to search items."
                                }))
                                .unwrap()
                            );
                            return ExitCode::FAILURE;
                        }
                    }
                    let results =
                        vault_mgr.search_items_by_state(&query, category.as_deref(), trash);
                    println!("{}", serde_json::to_string_pretty(&results).unwrap());
                    ExitCode::SUCCESS
                }
                VaultAction::Create {
                    item,
                    from_json,
                    stdin,
                    json,
                } => {
                    if item.is_some() && (stdin || from_json.is_some()) {
                        let err_msg =
                            "Cannot combine a cipher type subcommand with --stdin or --from-json.";
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": err_msg,
                                }))
                                .unwrap()
                            );
                        } else {
                            eprintln!("Error: {err_msg}");
                        }
                        return ExitCode::FAILURE;
                    }

                    let client_ctx = omawarden::api::resolve_effective_client_context(None);
                    let (mut daemon_req, label, cipher_name) = match item {
                        Some(CreateItemAction::Login {
                            name,
                            username,
                            password,
                            password_stdin,
                            generate_password,
                            generate_passphrase,
                            notes,
                            uris,
                            fields,
                            hidden_fields,
                            bool_fields,
                            folder_id,
                            organization_id,
                            collection_id,
                        }) => {
                            if organization_id
                                .as_deref()
                                .filter(|s| !s.is_empty())
                                .is_some()
                                || collection_id.as_deref().filter(|s| !s.is_empty()).is_some()
                            {
                                let err_msg = "Organization ciphers are read-only.";
                                if json {
                                    println!(
                                        "{}",
                                        serde_json::to_string_pretty(&json!({
                                            "ok": false,
                                            "error": err_msg,
                                        }))
                                        .unwrap()
                                    );
                                } else {
                                    eprintln!("Error: {err_msg}");
                                }
                                return ExitCode::FAILURE;
                            }

                            let password_val = if generate_password {
                                let opts = omawarden::generator::PasswordOptions {
                                    length: 16,
                                    ..Default::default()
                                };
                                let pwd = match omawarden::generator::generate_password(&opts) {
                                    Ok(s) => s.value.clone(),
                                    Err(e) => {
                                        eprintln!("Error generating password: {e}");
                                        return ExitCode::FAILURE;
                                    }
                                };
                                zeroize::Zeroizing::new(pwd)
                            } else if generate_passphrase {
                                let opts = omawarden::generator::PassphraseOptions::default();
                                let pass = match omawarden::generator::generate_passphrase(&opts) {
                                    Ok(s) => s.value.clone(),
                                    Err(e) => {
                                        eprintln!("Error generating passphrase: {e}");
                                        return ExitCode::FAILURE;
                                    }
                                };
                                zeroize::Zeroizing::new(pass)
                            } else if password_stdin {
                                let mut buf = String::new();
                                io::stdin().read_to_string(&mut buf).unwrap_or_default();
                                zeroize::Zeroizing::new(
                                    buf.trim_end_matches(['\r', '\n']).to_string(),
                                )
                            } else if let Some(p) = password {
                                zeroize::Zeroizing::new(p)
                            } else {
                                let is_interactive = (io::stdin().is_terminal()
                                    || std::env::var_os("OMA_FORCE_PROMPT").is_some())
                                    && !json;
                                if !is_interactive {
                                    let err_msg = "Password is required. Provide --password, --password-stdin, --generate-password, or run interactively in a terminal.";
                                    if json {
                                        println!(
                                            "{}",
                                            serde_json::to_string_pretty(&json!({
                                                "ok": false,
                                                "error": err_msg,
                                            }))
                                            .unwrap()
                                        );
                                    } else {
                                        eprintln!("Error: {err_msg}");
                                    }
                                    return ExitCode::FAILURE;
                                }

                                let prompt_msg = "Enter password (or press Enter to generate): ";
                                let entered = if io::stdin().is_terminal() {
                                    rpassword::prompt_password(prompt_msg).unwrap_or_default()
                                } else {
                                    eprint!("{prompt_msg}");
                                    let _ = io::stderr().flush();
                                    let mut buf = String::new();
                                    let _ = io::stdin().read_line(&mut buf);
                                    buf.trim_end_matches(['\r', '\n']).to_string()
                                };

                                if entered.trim().is_empty() {
                                    let opts = omawarden::generator::PasswordOptions {
                                        length: 16,
                                        ..Default::default()
                                    };
                                    let pwd = match omawarden::generator::generate_password(&opts) {
                                        Ok(s) => s.value.clone(),
                                        Err(e) => {
                                            eprintln!("Error generating password: {e}");
                                            return ExitCode::FAILURE;
                                        }
                                    };
                                    zeroize::Zeroizing::new(pwd)
                                } else {
                                    zeroize::Zeroizing::new(entered)
                                }
                            };

                            let custom_fields =
                                match build_custom_fields(&fields, &hidden_fields, &bool_fields) {
                                    Ok(list) => list,
                                    Err(err_msg) => {
                                        if json {
                                            println!(
                                                "{}",
                                                serde_json::to_string_pretty(&json!({
                                                    "ok": false,
                                                    "error": err_msg,
                                                }))
                                                .unwrap()
                                            );
                                        } else {
                                            eprintln!("Error: {err_msg}");
                                        }
                                        return ExitCode::FAILURE;
                                    }
                                };

                            let mut req = json!({
                                "action": "cipher_create",
                                "cipher_type": "login",
                                "name": name,
                                "username": username,
                                "password": *password_val,
                                "notes": notes,
                                "uris": uris,
                                "folder_id": folder_id,
                            });
                            if !custom_fields.is_empty() {
                                req["fields"] = json!(custom_fields);
                            }
                            (req, "login cipher", name)
                        }
                        Some(CreateItemAction::Note {
                            name,
                            notes,
                            notes_stdin,
                            fields,
                            hidden_fields,
                            bool_fields,
                            folder_id,
                            organization_id,
                            collection_id,
                        }) => {
                            if organization_id
                                .as_deref()
                                .filter(|s| !s.is_empty())
                                .is_some()
                                || collection_id.as_deref().filter(|s| !s.is_empty()).is_some()
                            {
                                let err_msg = "Organization ciphers are read-only.";
                                if json {
                                    println!(
                                        "{}",
                                        serde_json::to_string_pretty(&json!({
                                            "ok": false,
                                            "error": err_msg,
                                        }))
                                        .unwrap()
                                    );
                                } else {
                                    eprintln!("Error: {err_msg}");
                                }
                                return ExitCode::FAILURE;
                            }

                            let notes_val = if notes_stdin {
                                let mut buf = String::new();
                                io::stdin().read_to_string(&mut buf).unwrap_or_default();
                                zeroize::Zeroizing::new(
                                    buf.trim_end_matches(['\r', '\n']).to_string(),
                                )
                            } else {
                                zeroize::Zeroizing::new(notes.unwrap_or_default())
                            };

                            let custom_fields =
                                match build_custom_fields(&fields, &hidden_fields, &bool_fields) {
                                    Ok(list) => list,
                                    Err(err_msg) => {
                                        if json {
                                            println!(
                                                "{}",
                                                serde_json::to_string_pretty(&json!({
                                                    "ok": false,
                                                    "error": err_msg,
                                                }))
                                                .unwrap()
                                            );
                                        } else {
                                            eprintln!("Error: {err_msg}");
                                        }
                                        return ExitCode::FAILURE;
                                    }
                                };

                            let mut req = json!({
                                "action": "cipher_create",
                                "type": 2,
                                "cipher_type": "note",
                                "name": name,
                                "notes": *notes_val,
                                "folder_id": folder_id,
                            });
                            if !custom_fields.is_empty() {
                                req["fields"] = json!(custom_fields);
                            }
                            (req, "note cipher", name)
                        }
                        None => {
                            let raw_json = if stdin {
                                let mut buf = String::new();
                                io::stdin().read_to_string(&mut buf).unwrap_or_default();
                                zeroize::Zeroizing::new(buf)
                            } else if let Some(path) = from_json {
                                match std::fs::read_to_string(&path) {
                                    Ok(content) => zeroize::Zeroizing::new(content),
                                    Err(err) => {
                                        let err_msg =
                                            format!("Cannot read file '{}': {err}", path.display());
                                        if json {
                                            println!(
                                                "{}",
                                                serde_json::to_string_pretty(&json!({
                                                    "ok": false,
                                                    "error": err_msg,
                                                }))
                                                .unwrap()
                                            );
                                        } else {
                                            eprintln!("Error: {err_msg}");
                                        }
                                        return ExitCode::FAILURE;
                                    }
                                }
                            } else {
                                let err_msg = "Specify a cipher type subcommand (e.g. 'login', 'note') or pass --stdin / --from-json.";
                                if json {
                                    println!(
                                        "{}",
                                        serde_json::to_string_pretty(&json!({
                                            "ok": false,
                                            "error": err_msg,
                                        }))
                                        .unwrap()
                                    );
                                } else {
                                    eprintln!("Error: {err_msg}");
                                }
                                return ExitCode::FAILURE;
                            };

                            let mut val: Value = match serde_json::from_str(&raw_json) {
                                Ok(v) => v,
                                Err(err) => {
                                    let err_msg = format!("Invalid JSON payload: {err}");
                                    if json {
                                        println!(
                                            "{}",
                                            serde_json::to_string_pretty(&json!({
                                                "ok": false,
                                                "error": err_msg,
                                            }))
                                            .unwrap()
                                        );
                                    } else {
                                        eprintln!("Error: {err_msg}");
                                    }
                                    return ExitCode::FAILURE;
                                }
                            };

                            let has_org = val
                                .get("organizationId")
                                .and_then(|v| v.as_str())
                                .filter(|s| !s.is_empty())
                                .is_some()
                                || val
                                    .get("organization_id")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .is_some();
                            let has_cols = val
                                .get("collectionIds")
                                .and_then(|v| v.as_array())
                                .filter(|a| !a.is_empty())
                                .is_some()
                                || val
                                    .get("collection_ids")
                                    .and_then(|v| v.as_array())
                                    .filter(|a| !a.is_empty())
                                    .is_some()
                                || val
                                    .get("collectionIds")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .is_some()
                                || val
                                    .get("collection_ids")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .is_some()
                                || val
                                    .get("collectionId")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .is_some()
                                || val
                                    .get("collection_id")
                                    .and_then(|v| v.as_str())
                                    .filter(|s| !s.is_empty())
                                    .is_some();
                            if has_org || has_cols {
                                let err_msg = "Organization ciphers are read-only.";
                                if json {
                                    println!(
                                        "{}",
                                        serde_json::to_string_pretty(&json!({
                                            "ok": false,
                                            "error": err_msg,
                                        }))
                                        .unwrap()
                                    );
                                } else {
                                    eprintln!("Error: {err_msg}");
                                }
                                return ExitCode::FAILURE;
                            }

                            val["action"] = json!("cipher_create");
                            let name = val
                                .get("name")
                                .and_then(|v| v.as_str())
                                .unwrap_or("unnamed")
                                .to_string();
                            (val, "cipher", name)
                        }
                    };

                    if let Some(ref ctx) = client_ctx {
                        daemon_req["client"] = json!(ctx);
                    }
                    match submit_cipher_mutation(&daemon_req) {
                        Ok(receipt) => {
                            if json {
                                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
                            } else {
                                let id = receipt["item"]["id"].as_str().unwrap_or("unknown");
                                println!("Created {} \"{}\" ({}).", label, cipher_name, id);
                            }
                            ExitCode::SUCCESS
                        }
                        Err(error) => {
                            let err_msg = error
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Failed to create cipher");
                            if json {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&json!({
                                        "ok": false,
                                        "error": err_msg,
                                    }))
                                    .unwrap()
                                );
                            } else {
                                eprintln!("Error: {}", err_msg);
                            }
                            ExitCode::FAILURE
                        }
                    }
                }
                VaultAction::Delete {
                    target,
                    permanent,
                    trash,
                    yes,
                    json,
                } => {
                    let client_ctx = omawarden::api::resolve_effective_client_context(None);
                    let is_interactive = (std::io::stdin().is_terminal()
                        || std::env::var_os("OMA_FORCE_PROMPT").is_some())
                        && !yes
                        && !json;

                    let resolved = match resolve_target_cipher(
                        &target,
                        "delete",
                        client_ctx.as_ref(),
                        is_interactive,
                        json,
                        trash,
                    ) {
                        Ok(item) => item,
                        Err(code) => return code,
                    };

                    let item_id = resolved["id"].as_str().unwrap_or("").to_string();
                    let item_name = resolved["name"].as_str().unwrap_or("").to_string();

                    if resolved
                        .get("organization_id")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.is_empty())
                    {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": "Organization ciphers are read-only.",
                                }))
                                .unwrap()
                            );
                        } else {
                            eprintln!("Error: Organization ciphers are read-only.");
                        }
                        return ExitCode::FAILURE;
                    }

                    // When --trash is passed, permanent deletion is implied (DELETE /ciphers/{id})
                    let is_permanent = trash || permanent;
                    let action_verb = if is_permanent {
                        "Permanently delete"
                    } else {
                        "Delete"
                    };

                    if is_interactive {
                        eprint!("{action_verb} item '{item_name}'? [y/N] ");
                        let _ = io::stderr().flush();
                        let mut input = String::new();
                        if io::stdin().read_line(&mut input).is_err() {
                            eprintln!("Deletion aborted.");
                            return ExitCode::FAILURE;
                        }
                        let trimmed = input.trim();
                        if !trimmed.eq_ignore_ascii_case("y")
                            && !trimmed.eq_ignore_ascii_case("yes")
                        {
                            eprintln!("Deletion aborted.");
                            return ExitCode::FAILURE;
                        }
                    }

                    let action = if trash {
                        "cipher_delete_trash"
                    } else {
                        "cipher_delete"
                    };
                    let mut daemon_req = json!({
                        "action": action,
                        "id": item_id,
                        "permanent": is_permanent,
                    });
                    if let Some(ref ctx) = client_ctx {
                        daemon_req["client"] = json!(ctx);
                    }

                    match submit_cipher_mutation(&daemon_req) {
                        Ok(receipt) => {
                            if json {
                                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
                            } else {
                                let id = receipt["item"]["id"].as_str().unwrap_or(&item_id);
                                let name = receipt["item"]["name"].as_str().unwrap_or(&item_name);
                                if is_permanent {
                                    println!("Permanently deleted cipher \"{}\" ({}).", name, id);
                                } else {
                                    println!("Deleted cipher \"{}\" ({}).", name, id);
                                }
                            }
                            ExitCode::SUCCESS
                        }
                        Err(error) => {
                            let err_msg = error
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Failed to delete cipher");
                            if json {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&json!({
                                        "ok": false,
                                        "error": err_msg,
                                    }))
                                    .unwrap()
                                );
                            } else {
                                eprintln!("Error: {}", err_msg);
                            }
                            ExitCode::FAILURE
                        }
                    }
                }
                VaultAction::Restore { target, json } => {
                    let client_ctx = omawarden::api::resolve_effective_client_context(None);
                    let is_interactive = (std::io::stdin().is_terminal()
                        || std::env::var_os("OMA_FORCE_PROMPT").is_some())
                        && !json;

                    let resolved = match resolve_target_cipher(
                        &target,
                        "restore",
                        client_ctx.as_ref(),
                        is_interactive,
                        json,
                        true,
                    ) {
                        Ok(item) => item,
                        Err(code) => return code,
                    };

                    let item_id = resolved["id"].as_str().unwrap_or("").to_string();
                    let item_name = resolved["name"].as_str().unwrap_or("").to_string();

                    if resolved
                        .get("organization_id")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.is_empty())
                    {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": "Organization ciphers are read-only.",
                                }))
                                .unwrap()
                            );
                        } else {
                            eprintln!("Error: Organization ciphers are read-only.");
                        }
                        return ExitCode::FAILURE;
                    }

                    let mut daemon_req = json!({
                        "action": "cipher_restore",
                        "id": item_id,
                    });
                    if let Some(ref ctx) = client_ctx {
                        daemon_req["client"] = json!(ctx);
                    }

                    match submit_cipher_mutation(&daemon_req) {
                        Ok(receipt) => {
                            if json {
                                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
                            } else {
                                let id = receipt["item"]["id"].as_str().unwrap_or(&item_id);
                                let name = receipt["item"]["name"].as_str().unwrap_or(&item_name);
                                println!("Restored cipher \"{}\" ({}).", name, id);
                            }
                            ExitCode::SUCCESS
                        }
                        Err(error) => {
                            let err_msg = error
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Failed to restore cipher");
                            if json {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&json!({
                                        "ok": false,
                                        "error": err_msg,
                                    }))
                                    .unwrap()
                                );
                            } else {
                                eprintln!("Error: {}", err_msg);
                            }
                            ExitCode::FAILURE
                        }
                    }
                }
                VaultAction::Edit {
                    target,
                    name,
                    username,
                    password,
                    password_stdin,
                    generate_password,
                    generate_passphrase,
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
                    json,
                } => {
                    let has_field_flags = name.is_some()
                        || username.is_some()
                        || password.is_some()
                        || password_stdin
                        || generate_password
                        || generate_passphrase
                        || notes.is_some()
                        || notes_stdin
                        || !uris.is_empty()
                        || !add_uris.is_empty()
                        || clear_uris
                        || !fields.is_empty()
                        || !hidden_fields.is_empty()
                        || !bool_fields.is_empty()
                        || !remove_fields.is_empty()
                        || folder_id.is_some()
                        || favorite.is_some();

                    let is_interactive = (std::io::stdin().is_terminal()
                        || std::env::var_os("OMA_FORCE_PROMPT").is_some())
                        && !json;

                    if !has_field_flags && !is_interactive {
                        let err_msg = "No fields specified to edit. Provide at least one field to update (e.g. --password) or run in an interactive terminal to use $EDITOR.";
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": err_msg,
                                }))
                                .unwrap()
                            );
                        } else {
                            eprintln!("Error: {err_msg}");
                        }
                        return ExitCode::FAILURE;
                    }

                    let client_ctx = omawarden::api::resolve_effective_client_context(None);

                    let resolved = match resolve_target_cipher(
                        &target,
                        "edit",
                        client_ctx.as_ref(),
                        is_interactive,
                        json,
                        false,
                    ) {
                        Ok(item) => item,
                        Err(code) => return code,
                    };

                    let item_id = resolved["id"].as_str().unwrap_or("").to_string();
                    let item_name = resolved["name"].as_str().unwrap_or("").to_string();
                    let item_type = resolved["type"].as_str().unwrap_or("");

                    if resolved
                        .get("organization_id")
                        .and_then(Value::as_str)
                        .is_some_and(|s| !s.is_empty())
                    {
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": "Organization ciphers are read-only.",
                                }))
                                .unwrap()
                            );
                        } else {
                            eprintln!("Error: Organization ciphers are read-only.");
                        }
                        return ExitCode::FAILURE;
                    }

                    if !has_field_flags {
                        return handle_editor_edit(&cfg, &resolved, client_ctx.as_ref());
                    }

                    if (username.is_some()
                        || password.is_some()
                        || password_stdin
                        || generate_password
                        || generate_passphrase
                        || !uris.is_empty()
                        || !add_uris.is_empty()
                        || clear_uris)
                        && item_type != "login"
                    {
                        let err_msg =
                            "Username, password, and URI can only be updated on login ciphers.";
                        if json {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": err_msg,
                                }))
                                .unwrap()
                            );
                        } else {
                            eprintln!("Error: {}", err_msg);
                        }
                        return ExitCode::FAILURE;
                    }

                    let custom_fields =
                        match build_custom_fields(&fields, &hidden_fields, &bool_fields) {
                            Ok(list) => list,
                            Err(err_msg) => {
                                if json {
                                    println!(
                                        "{}",
                                        serde_json::to_string_pretty(&json!({
                                            "ok": false,
                                            "error": err_msg,
                                        }))
                                        .unwrap()
                                    );
                                } else {
                                    eprintln!("Error: {err_msg}");
                                }
                                return ExitCode::FAILURE;
                            }
                        };

                    let password_val = if generate_password {
                        let opts = omawarden::generator::PasswordOptions {
                            length: 16,
                            ..Default::default()
                        };
                        let pwd = match omawarden::generator::generate_password(&opts) {
                            Ok(s) => s.value.clone(),
                            Err(e) => {
                                eprintln!("Error generating password: {e}");
                                return ExitCode::FAILURE;
                            }
                        };
                        Some(zeroize::Zeroizing::new(pwd))
                    } else if generate_passphrase {
                        let opts = omawarden::generator::PassphraseOptions::default();
                        let pass = match omawarden::generator::generate_passphrase(&opts) {
                            Ok(s) => s.value.clone(),
                            Err(e) => {
                                eprintln!("Error generating passphrase: {e}");
                                return ExitCode::FAILURE;
                            }
                        };
                        Some(zeroize::Zeroizing::new(pass))
                    } else if password_stdin {
                        let mut buf = zeroize::Zeroizing::new(String::new());
                        io::stdin().read_to_string(&mut buf).unwrap_or_default();
                        let trimmed = buf.trim_end_matches(['\r', '\n']);
                        Some(zeroize::Zeroizing::new(trimmed.to_string()))
                    } else {
                        password.map(zeroize::Zeroizing::new)
                    };

                    let notes_val = if notes_stdin {
                        let mut buf = zeroize::Zeroizing::new(String::new());
                        io::stdin().read_to_string(&mut buf).unwrap_or_default();
                        let trimmed = buf.trim_end_matches(['\r', '\n']);
                        Some(zeroize::Zeroizing::new(trimmed.to_string()))
                    } else {
                        notes.map(zeroize::Zeroizing::new)
                    };

                    let mut daemon_req = json!({
                        "action": "cipher_update",
                        "id": item_id,
                        "name": name,
                        "username": username,
                        "password": password_val.as_deref(),
                        "notes": notes_val.as_deref(),
                        "folder_id": folder_id,
                        "favorite": favorite,
                    });
                    if !uris.is_empty() {
                        daemon_req["uris"] = json!(uris);
                    }
                    if !add_uris.is_empty() {
                        daemon_req["add_uris"] = json!(add_uris);
                    }
                    if clear_uris {
                        daemon_req["clear_uris"] = json!(true);
                    }
                    if !custom_fields.is_empty() {
                        daemon_req["fields"] = json!(custom_fields);
                    }
                    if !remove_fields.is_empty() {
                        daemon_req["remove_fields"] = json!(remove_fields);
                    }
                    if let Some(ref ctx) = client_ctx {
                        daemon_req["client"] = json!(ctx);
                    }

                    match submit_cipher_mutation(&daemon_req) {
                        Ok(receipt) => {
                            if json {
                                println!("{}", serde_json::to_string_pretty(&receipt).unwrap());
                            } else {
                                let id = receipt["item"]["id"].as_str().unwrap_or(item_id.as_str());
                                let name = receipt["item"]["name"]
                                    .as_str()
                                    .unwrap_or(item_name.as_str());
                                println!("Updated cipher \"{}\" ({}).", name, id);
                            }
                            ExitCode::SUCCESS
                        }
                        Err(error) => {
                            let err_msg = error
                                .get("error")
                                .and_then(|v| v.as_str())
                                .unwrap_or("Failed to update cipher");
                            if json {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&json!({
                                        "ok": false,
                                        "error": err_msg,
                                    }))
                                    .unwrap()
                                );
                            } else {
                                eprintln!("Error: {}", err_msg);
                            }
                            ExitCode::FAILURE
                        }
                    }
                }
            }
        }

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
        } => {
            let guard = ClipboardGuard::default();
            if !guard.is_available() {
                let err_msg = guard
                    .unavailable_reason()
                    .unwrap_or_else(|| "Clipboard utility not found.".to_string());
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": err_msg
                    }))
                    .unwrap()
                );
                return ExitCode::FAILURE;
            }

            if clear {
                let ok = guard.clear();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "ok": ok })).unwrap()
                );
                return if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                };
            }

            if stdin {
                let text_val = read_clipboard_stdin();
                let timeout_val = timeout.unwrap_or(cfg.clipboard_clear_seconds);
                let ok = match expected_lock_generation {
                    Some(generation) => {
                        guard.copy_in_session(&text_val, sensitive, timeout_val, generation)
                    }
                    None => guard.copy(&text_val, sensitive, timeout_val),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": ok,
                        "copied": "stdin",
                        "timeout": if sensitive { timeout_val } else { 0 }
                    }))
                    .unwrap()
                );
                return if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                };
            }

            let query = match query {
                Some(q) if !q.trim().is_empty() => q,
                _ => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": false,
                            "error": "Missing item query or action flag (--clear / --stdin). See 'omawarden copy --help'."
                        }))
                        .unwrap()
                    );
                    return ExitCode::FAILURE;
                }
            };

            // --field cannot be combined with other field selection flags
            let field_flags = [username, totp, notes, public_key, private_key, password];
            if field.is_some() && field_flags.iter().any(|&f| f) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": "--field cannot be combined with --username, --totp, --notes, --public-key, --private-key, or --password"
                    }))
                    .unwrap()
                );
                return ExitCode::FAILURE;
            }

            let (item, scope) = match vault_output_item(&cfg, &query, true) {
                Ok(Some(VaultOutputItem {
                    item,
                    scope: Some(scope),
                })) => (item, scope),
                result => {
                    let error = match result {
                        Ok(Some(_)) => "Could not verify the clipboard source session.".into(),
                        Ok(None) => format!("Item '{}' not found in vault", query),
                        Err(error) => error,
                    };
                    println!("{}", json!({ "ok": false, "error": error }));
                    return ExitCode::FAILURE;
                }
            };

            let (field_name, text_to_copy, is_sensitive) = if username {
                let u = item
                    .login
                    .as_ref()
                    .and_then(|l| l.get("username"))
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        item.identity
                            .as_ref()
                            .and_then(|id| id.get("username"))
                            .and_then(|v| v.as_str())
                    })
                    .or_else(|| {
                        item.identity
                            .as_ref()
                            .and_then(|id| id.get("email"))
                            .and_then(|v| v.as_str())
                    })
                    .unwrap_or_default()
                    .to_string();
                ("username".to_string(), u, false)
            } else if totp {
                let seed = item
                    .login
                    .as_ref()
                    .and_then(|l| l.get("totp"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default();
                if let Some(t_res) = omawarden::totp::generate_totp(seed, None, 6, 30) {
                    ("totp".to_string(), t_res.code, true)
                } else {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": false,
                            "error": "Item has no valid TOTP configuration"
                        }))
                        .unwrap()
                    );
                    return ExitCode::FAILURE;
                }
            } else if notes {
                (
                    "notes".to_string(),
                    item.notes.clone().unwrap_or_default(),
                    false,
                )
            } else if public_key {
                let pk = item
                    .ssh_key
                    .as_ref()
                    .and_then(|s| s.public_key.as_deref())
                    .or_else(|| {
                        item.card
                            .as_ref()
                            .and_then(|c| c.get("number"))
                            .and_then(|v| v.as_str())
                    })
                    .unwrap_or_default()
                    .to_string();
                ("public_key".to_string(), pk, false)
            } else if private_key {
                let privk = item
                    .ssh_key
                    .as_ref()
                    .and_then(|s| s.private_key.as_deref())
                    .or_else(|| {
                        item.card
                            .as_ref()
                            .and_then(|c| c.get("code"))
                            .and_then(|v| v.as_str())
                    })
                    .unwrap_or_default()
                    .to_string();
                ("private_key".to_string(), privk, true)
            } else if let Some(ref field_name_query) = field {
                // Find the custom field by exact name, then case-insensitive fallback
                let field_name_lower = field_name_query.to_lowercase();
                let mut found_field = None;
                let mut found_field_type = 0i64;
                let mut found_field_name = field_name_query.clone();

                for f in &item.fields {
                    let name = f.get("name").and_then(Value::as_str).unwrap_or("");
                    let field_type = f.get("type").and_then(Value::as_i64).unwrap_or(0);

                    // Exact match first
                    if name == field_name_query {
                        found_field = f.get("value").and_then(Value::as_str).map(str::to_string);
                        found_field_type = field_type;
                        found_field_name = name.to_string();
                        break;
                    }
                    // Case-insensitive fallback
                    if name.to_lowercase() == field_name_lower {
                        found_field = f.get("value").and_then(Value::as_str).map(str::to_string);
                        found_field_type = field_type;
                        found_field_name = name.to_string();
                        break;
                    }
                }

                let field_value = match found_field {
                    Some(v) => v,
                    None => {
                        // List available custom fields for actionable error
                        let available: Vec<String> = item
                            .fields
                            .iter()
                            .filter_map(|f| {
                                f.get("name").and_then(Value::as_str).map(str::to_string)
                            })
                            .collect();
                        let error_msg = if available.is_empty() {
                            format!("Item '{}' has no custom fields", item.name)
                        } else {
                            format!(
                                "Custom field '{}' not found on item '{}'. Available fields: {}",
                                field_name_query,
                                item.name,
                                available.join(", ")
                            )
                        };
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": error_msg
                            }))
                            .unwrap()
                        );
                        return ExitCode::FAILURE;
                    }
                };

                let is_sensitive = found_field_type == 1; // Hidden fields are sensitive
                (found_field_name, field_value, is_sensitive)
            } else if password {
                let pwd = item
                    .login
                    .as_ref()
                    .and_then(|l| l.get("password"))
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                ("password".to_string(), pwd, true)
            } else {
                match item.type_name.as_str() {
                    "login" => {
                        let pwd = item
                            .login
                            .as_ref()
                            .and_then(|l| l.get("password"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        ("password".to_string(), pwd, true)
                    }
                    "ssh_key" => {
                        let privk = item
                            .ssh_key
                            .as_ref()
                            .and_then(|s| s.private_key.as_deref())
                            .unwrap_or_default()
                            .to_string();
                        ("private_key".to_string(), privk, true)
                    }
                    "card" => {
                        let num = item
                            .card
                            .as_ref()
                            .and_then(|c| c.get("number"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        ("card_number".to_string(), num, true)
                    }
                    "note" => (
                        "notes".to_string(),
                        item.notes.clone().unwrap_or_default(),
                        false,
                    ),
                    _ => {
                        let val = item
                            .login
                            .as_ref()
                            .and_then(|l| l.get("password"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        ("password".to_string(), val, true)
                    }
                }
            };

            if text_to_copy.is_empty() {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": format!("Field '{}' is empty for item '{}'", field_name, item.name)
                    }))
                    .unwrap()
                );
                return ExitCode::FAILURE;
            }

            let timeout_val = timeout.unwrap_or(cfg.clipboard_clear_seconds);
            let ok = guard.copy_vault_output(&text_to_copy, is_sensitive, timeout_val, &scope);
            if ok {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "name": item.name,
                        "copied": field_name,
                        "timeout": if is_sensitive { timeout_val } else { 0 }
                    }))
                    .unwrap()
                );
                ExitCode::SUCCESS
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": "Failed to copy content to clipboard"
                    }))
                    .unwrap()
                );
                ExitCode::FAILURE
            }
        }

        Commands::Totp { query, stdin, copy } => {
            let query = if stdin { None } else { query.as_deref() };
            if query.is_some_and(|q| {
                q.starts_with("otpauth://") || q.starts_with("otpauth-migration://")
            }) {
                eprintln!(
                    "Error: Passing otpauth URIs or secrets in CLI arguments is forbidden (violates Zero-Argv security policy).\nPipe secret via STDIN instead: echo '<otpauth_uri>' | omawarden totp --stdin"
                );
                return ExitCode::FAILURE;
            }

            let output = match totp_output(&cfg, query, copy) {
                Ok(Some(output)) => output,
                result => {
                    let error = result.err().unwrap_or_else(|| {
                        "Failed to generate TOTP: item not found or secret is invalid".into()
                    });
                    println!("{}", json!({ "ok": false, "error": error }));
                    return ExitCode::FAILURE;
                }
            };
            let res = output.result;
            if copy {
                let clipboard = ClipboardGuard::default();
                let copied = match output.scope {
                    Some(scope) => clipboard.copy_vault_output(&res.code, true, 30, &scope),
                    None => clipboard.copy(&res.code, true, 30),
                };
                if !copied {
                    println!(
                        "{}",
                        json!({
                            "ok": false, "error": "Could not copy TOTP. Verify the vault session and retry."
                        })
                    );
                    return ExitCode::FAILURE;
                }
            }

            let mut response =
                json!({ "ok": true, "code": res.code, "ttl": res.ttl, "period": res.period });
            if let Some((id, name)) = output.item {
                response["id"] = json!(id);
                response["name"] = json!(name);
            }
            if copy {
                response["copied"] = json!(true);
            }
            println!("{}", serde_json::to_string_pretty(&response).unwrap());
            ExitCode::SUCCESS
        }

        Commands::Attachment { action } => match action {
            AttachmentAction::Download {
                item_id,
                attachment_id,
                filename,
                output_dir,
                open,
                preview,
                expected_lock_generation,
            } => {
                let res = get_attachment(
                    &item_id,
                    &attachment_id,
                    &filename,
                    output_dir.as_deref(),
                    open,
                    preview,
                    None,
                    expected_lock_generation.as_deref(),
                    true,
                );
                println!("{}", serde_json::to_string_pretty(&res).unwrap());
                if res.ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            AttachmentAction::Clean { item_id } => {
                match omawarden::attachment::clean_previews(item_id.as_deref()) {
                    Ok(()) => {
                        println!("{}", json!({ "ok": true, "status": "cleaned" }));
                        ExitCode::SUCCESS
                    }
                    Err(error) => {
                        println!("{}", json!({ "ok": false, "error": error.to_string() }));
                        ExitCode::FAILURE
                    }
                }
            }
        },

        Commands::SshKey { action } => {
            let vault_mgr = VaultManager::with_identity_url(
                &cfg.server_url,
                cfg.identity_url.as_deref(),
                None,
                None,
            );
            match action {
                SshKeyAction::Create {
                    name,
                    algorithm,
                    comment,
                    notes,
                    folder,
                    out_dir,
                    ignore_server_capabilities,
                } => {
                    if let Err(e) = omawarden::capabilities::check_feature_gating(
                        &cfg.server_url,
                        "ssh-key-vault-item",
                        ignore_server_capabilities,
                    ) {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({ "ok": false, "error": e }))
                                .unwrap()
                        );
                        return ExitCode::FAILURE;
                    }

                    let _ = omawarden::daemon::ensure_daemon_running();
                    let keypair = match generate_keypair(algorithm, comment.as_deref()) {
                        Ok(k) => k,
                        Err(e) => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({ "ok": false, "error": e }))
                                    .unwrap()
                            );
                            return ExitCode::FAILURE;
                        }
                    };

                    let daemon_req = json!({
                        "action": "ssh_key_create_v2",
                        "name": name,
                        "private_key": keypair.private_key,
                        "public_key": keypair.public_key,
                        "fingerprint": keypair.fingerprint,
                        "notes": notes,
                        "folder_id": folder,
                    });

                    let mut receipt = match submit_ssh_cipher(&daemon_req) {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            println!("{error}");
                            return ExitCode::FAILURE;
                        }
                    };

                    let mut files_json = json!(null);
                    if let Some(dest_dir) =
                        out_dir.as_ref().filter(|_| receipt["outcome"] == "saved")
                    {
                        match write_keypair_files(
                            dest_dir,
                            algorithm.default_filename_prefix(),
                            &keypair.private_key,
                            &keypair.public_key,
                        ) {
                            Ok((priv_p, pub_p)) => {
                                files_json = json!({
                                    "private_key_path": priv_p.to_string_lossy(),
                                    "public_key_path": pub_p.to_string_lossy(),
                                });
                            }
                            Err(e) => {
                                omawarden::log_warn!(
                                    "omawarden:ssh",
                                    "Failed to write exported files to {:?}: {}",
                                    dest_dir,
                                    e
                                );
                            }
                        }
                    }

                    if out_dir.is_some() && files_json.is_null() {
                        receipt["warning"] = json!(
                            "No key files were exported. Sync the vault, then use ssh-key export."
                        );
                    }
                    receipt["files"] = files_json;
                    println!("{receipt}");
                    ExitCode::SUCCESS
                }

                SshKeyAction::Import {
                    name,
                    private_key,
                    public_key,
                    stdin,
                    notes,
                    folder,
                    ignore_server_capabilities,
                } => {
                    if let Err(e) = omawarden::capabilities::check_feature_gating(
                        &cfg.server_url,
                        "ssh-key-vault-item",
                        ignore_server_capabilities,
                    ) {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({ "ok": false, "error": e }))
                                .unwrap()
                        );
                        return ExitCode::FAILURE;
                    }

                    let _ = omawarden::daemon::ensure_daemon_running();
                    let raw_priv = if stdin || private_key.is_none() {
                        let mut buffer = String::new();
                        let _ = io::stdin().read_to_string(&mut buffer);
                        buffer
                    } else if let Some(ref p) = private_key {
                        match std::fs::read_to_string(p) {
                            Ok(c) => c,
                            Err(e) => {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&json!({
                                        "ok": false,
                                        "error": e.to_string()
                                    }))
                                    .unwrap()
                                );
                                return ExitCode::FAILURE;
                            }
                        }
                    } else {
                        String::new()
                    };

                    let mut keypair = match parse_private_key(&raw_priv) {
                        Ok(k) => k,
                        Err(e) => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({ "ok": false, "error": e }))
                                    .unwrap()
                            );
                            return ExitCode::FAILURE;
                        }
                    };

                    if let Some(ref pub_path) = public_key {
                        if let Ok(pub_content) = std::fs::read_to_string(pub_path) {
                            let trimmed_pub = pub_content.trim().to_string();
                            if !trimmed_pub.is_empty() {
                                keypair.public_key = trimmed_pub;
                            }
                        }
                    }

                    let daemon_req = json!({
                        "action": "ssh_key_create_v2",
                        "name": name,
                        "private_key": keypair.private_key,
                        "public_key": keypair.public_key,
                        "fingerprint": keypair.fingerprint,
                        "notes": notes,
                        "folder_id": folder,
                    });

                    let receipt = match submit_ssh_cipher(&daemon_req) {
                        Ok(receipt) => receipt,
                        Err(error) => {
                            println!("{error}");
                            return ExitCode::FAILURE;
                        }
                    };

                    println!("{receipt}");
                    ExitCode::SUCCESS
                }

                SshKeyAction::Export {
                    query,
                    out_dir,
                    private_key_file,
                    public_key_file,
                    stdout,
                    public_only,
                    private_only: _,
                } => {
                    let _ = omawarden::daemon::ensure_daemon_running();
                    let st = send_daemon_request(&json!({ "action": "status" }));
                    let is_unlocked = st
                        .as_ref()
                        .and_then(|v| v.get("is_unlocked"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let item: Option<omawarden::vault::VaultItem> = if is_unlocked {
                        let daemon_res = send_daemon_request(&json!({
                            "action": "get_ssh_key",
                            "query": query
                        }));
                        daemon_res
                            .filter(|r| r.get("ok").and_then(|v| v.as_bool()) == Some(true))
                            .and_then(|res| {
                                res.get("item")
                                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                            })
                    } else {
                        let storage = vault_mgr.storage_mgr.load();
                        match ensure_unlocked_user_key(&vault_mgr, &storage) {
                            Ok(user_key) => {
                                let items = omawarden::api::decrypt_sync_ciphers_with_context(
                                    &storage.ciphers,
                                    &storage.folders,
                                    &storage.organizations,
                                    &user_key,
                                    storage.enc_private_key.as_deref(),
                                );
                                items.into_iter().find(|i| {
                                    i.deleted_at.is_none()
                                        && i.type_name == "ssh_key"
                                        && (i.id == query
                                            || i.name.eq_ignore_ascii_case(&query)
                                            || i.name
                                                .to_lowercase()
                                                .contains(&query.to_lowercase()))
                                })
                            }
                            Err(e) => {
                                println!(
                                    "{}",
                                    serde_json::to_string_pretty(&json!({
                                        "ok": false,
                                        "error": e
                                    }))
                                    .unwrap()
                                );
                                return ExitCode::FAILURE;
                            }
                        }
                    };

                    let ssh_item = match item {
                        Some(i) => i,
                        None => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": format!("SSH key item '{}' not found in vault", query)
                                }))
                                .unwrap()
                            );
                            return ExitCode::FAILURE;
                        }
                    };

                    let ssh_meta = match ssh_item.ssh_key {
                        Some(s) => s,
                        None => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": "Item has no SSH key metadata"
                                }))
                                .unwrap()
                            );
                            return ExitCode::FAILURE;
                        }
                    };

                    if stdout {
                        if public_only {
                            if let Some(ref pubk) = ssh_meta.public_key {
                                println!("{}", pubk);
                            }
                        } else if let Some(ref privk) = ssh_meta.private_key {
                            print!("{}", privk);
                            if !privk.ends_with('\n') {
                                println!();
                            }
                        }
                        return ExitCode::SUCCESS;
                    }

                    let target_dir = out_dir.unwrap_or_else(|| PathBuf::from("."));
                    let priv_filename = private_key_file.unwrap_or_else(|| {
                        let safe_name = ssh_item.name.to_lowercase().replace([' ', '/'], "_");
                        if safe_name.is_empty() {
                            "id_ssh_key".to_string()
                        } else {
                            safe_name
                        }
                    });
                    let pub_filename =
                        public_key_file.unwrap_or_else(|| format!("{}.pub", priv_filename));

                    let priv_content = ssh_meta.private_key.unwrap_or_default();
                    let pub_content = ssh_meta.public_key.unwrap_or_default();

                    match write_keypair_files_named(
                        &target_dir,
                        &priv_filename,
                        &pub_filename,
                        &priv_content,
                        &pub_content,
                    ) {
                        Ok((priv_p, pub_p)) => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": true,
                                    "name": ssh_item.name,
                                    "private_key_path": priv_p.to_string_lossy(),
                                    "public_key_path": pub_p.to_string_lossy(),
                                }))
                                .unwrap()
                            );
                            ExitCode::SUCCESS
                        }
                        Err(e) => {
                            println!(
                                "{}",
                                serde_json::to_string_pretty(&json!({
                                    "ok": false,
                                    "error": e.to_string()
                                }))
                                .unwrap()
                            );
                            ExitCode::FAILURE
                        }
                    }
                }
            }
        }

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
        } => {
            let secret_res = if passphrase {
                let options = omawarden::generator::PassphraseOptions {
                    words,
                    separator,
                    capitalize,
                };
                omawarden::generator::generate_passphrase(&options)
            } else {
                let options = omawarden::generator::PasswordOptions {
                    length,
                    uppercase: !no_uppercase,
                    lowercase: !no_lowercase,
                    numbers: !no_numbers,
                    special: !no_special,
                    avoid_ambiguous,
                    min_numbers,
                    min_special,
                };
                omawarden::generator::generate_password(&options)
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

        Commands::Server { action } => match action {
            ServerAction::Capabilities { refresh, json } => {
                let client_ctx = omawarden::api::probe_plugin_context();
                let mut daemon_req = json!({
                    "action": "server_capabilities",
                    "refresh": refresh,
                });
                if let Some(ref ctx) = client_ctx {
                    daemon_req["client"] = json!(ctx);
                }

                let response_val = match omawarden::daemon::dispatch_daemon_request(&daemon_req) {
                    Ok(val) => val,
                    Err(_) => {
                        match omawarden::capabilities::get_or_discover_capabilities(
                            &cfg.server_url,
                            refresh,
                            client_ctx.as_ref(),
                            Some(&cfg),
                        ) {
                            Ok(c) => json!({
                                "ok": true,
                                "server_url": c.server_url,
                                "server_version": c.server_version,
                                "server_name": c.server_name,
                                "server_vendor_version": c.server_vendor_version,
                                "git_hash": c.git_hash,
                                "cached_at": c.cached_at,
                                "feature_states": c.feature_states,
                                "matrix": c.matrix,
                            }),
                            Err(e) => json!({
                                "ok": false,
                                "error": e,
                            }),
                        }
                    }
                };

                if response_val["ok"] == true {
                    if json {
                        println!("{}", serde_json::to_string_pretty(&response_val).unwrap());
                    } else {
                        let server_url = response_val["server_url"]
                            .as_str()
                            .unwrap_or(&cfg.server_url);
                        println!("Server URL:     {}", server_url);
                        if let Some(n) = response_val["server_name"].as_str() {
                            println!("Server Name:    {}", n);
                        }
                        if let Some(v) = response_val["server_version"].as_str() {
                            println!("Server Version: {}", v);
                        }
                        if let Some(v) = response_val["server_vendor_version"].as_str() {
                            println!("Vendor Version: {}", v);
                        }
                        if let Some(g) = response_val["git_hash"].as_str() {
                            println!("Git Hash:       {}", g);
                        }
                        if let Some(cat) = response_val["cached_at"].as_str() {
                            println!("Cached At:      {}", cat);
                        }
                        println!("\nCapabilities Matrix:");
                        if let Some(matrix) = response_val["matrix"].as_array() {
                            for item in matrix {
                                let name = item["name"].as_str().unwrap_or("");
                                let status = item["status"].as_str().unwrap_or("");
                                let desc = item["description"].as_str().unwrap_or("");
                                let status_str = match status {
                                    "supported" => "[OK] supported",
                                    "disabled" => "[--] disabled",
                                    "unsupported" => "[??] unsupported",
                                    "deprecated" => "[!!] deprecated",
                                    _ => "[??] unknown",
                                };
                                println!("  {:24} {:16} {}", name, status_str, desc);
                            }
                        }
                    }
                    ExitCode::SUCCESS
                } else {
                    let err = response_val["error"]
                        .as_str()
                        .unwrap_or("Failed to query server capabilities");
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": err,
                            }))
                            .unwrap()
                        );
                    } else {
                        eprintln!("Error: {}", err);
                    }
                    ExitCode::FAILURE
                }
            }
        },
    }
}

fn submit_cipher_mutation(request: &Value) -> Result<Value, Value> {
    use omawarden::daemon::{dispatch_daemon_request, DispatchError};
    let reject = |reason: &str| json!({"ok":false, "outcome":"rejected", "error":reason});
    if let Err(e @ DispatchError::IncompatibleProtocol { .. }) =
        omawarden::daemon::ensure_daemon_running()
    {
        return Err(reject(&e.to_string()));
    }
    let ping = match dispatch_daemon_request(&json!({"action":"ping"})) {
        Ok(p) => p,
        Err(DispatchError::IncompatibleProtocol { .. }) => {
            return Err(reject(
                "Daemon protocol version is incompatible with this client.",
            ));
        }
        Err(_) => return Err(reject("Daemon unavailable.")),
    };
    if ping["unlocked"] != true {
        let (password, ..) = read_auth_payload();
        if password.is_empty()
            || !send_daemon_request(&json!({"action":"unlock","password":password}))
                .is_some_and(|r| r["ok"] == true)
        {
            let verb = match request.get("action").and_then(|a| a.as_str()) {
                Some("cipher_delete") => "deleting",
                Some("cipher_delete_trash") => "permanently deleting from trash",
                Some("cipher_restore") => "restoring",
                Some("cipher_update") => "editing",
                Some("cipher_resolve") => match request.get("purpose").and_then(Value::as_str) {
                    Some("edit") | Some("editing") => "editing",
                    Some("restore") | Some("restoring") => "restoring",
                    Some("delete") | Some("deleting") => "deleting",
                    _ => "deleting",
                },
                _ => "creating",
            };
            return Err(reject(&format!("Unlock the vault before {verb} a cipher.")));
        }
    }
    let unknown = || json!({"ok":false, "outcome":"unknown", "error":"Could not confirm the mutation. Sync the vault before trying again."});
    let reply = dispatch_daemon_request(request).map_err(|e| match e {
        DispatchError::NotSent => reject("Could not send the request to the daemon."),
        DispatchError::Unconfirmed => unknown(),
        DispatchError::IncompatibleProtocol { .. } => {
            reject("Daemon protocol version is incompatible with this client.")
        }
        DispatchError::LaunchFailed(msg) => reject(&format!("Could not start the daemon: {msg}")),
    })?;
    if reply["ok"] == false {
        return Err(reply);
    }
    if reply["ok"] != true || reply["item"]["id"].as_str().is_none_or(str::is_empty) {
        return Err(unknown());
    }
    Ok(reply)
}

/// Unlock before dispatch when a caller provides the master password on stdin.
/// Once dispatched, a missing reply cannot justify another create.
fn submit_ssh_cipher(request: &Value) -> Result<Value, Value> {
    use omawarden::daemon::{dispatch_daemon_request, DispatchError};
    let reject = |reason: &str| json!({"ok":false, "outcome":"rejected", "error":reason});
    let ping = match dispatch_daemon_request(&json!({"action":"ping"})) {
        Ok(p) => p,
        Err(DispatchError::IncompatibleProtocol { .. }) => {
            return Err(reject(
                "Daemon protocol version is incompatible with this client.",
            ));
        }
        Err(_) => return Err(reject("Daemon unavailable.")),
    };
    if ping["ssh_write_receipt"] != true {
        return Err(reject(
            "Lock the vault and restart the daemon to enable safe cipher writes.",
        ));
    }
    submit_cipher_mutation(request)
}

struct VaultOutputItem {
    item: VaultItem,
    scope: Option<ClipboardScope>,
}

fn vault_output_item(
    cfg: &Config,
    query: &str,
    touch: bool,
) -> Result<Option<VaultOutputItem>, String> {
    let _ = ensure_daemon_running();
    let unlocked = send_daemon_request(&json!({ "action": "status" }))
        .is_some_and(|reply| reply["is_unlocked"] == true);
    if unlocked {
        let Some(mut reply) = send_daemon_request(&json!({
            "action": "get_item", "query": query, "touch": touch
        }))
        .filter(|reply| reply["ok"] == true) else {
            return Ok(None);
        };
        let scope = reply["lock_generation"]
            .as_u64()
            .map(ClipboardScope::Session);
        return Ok(serde_json::from_value(reply["item"].take())
            .ok()
            .map(|item| VaultOutputItem { item, scope }));
    }

    let vault =
        VaultManager::with_identity_url(&cfg.server_url, cfg.identity_url.as_deref(), None, None);
    let storage = vault.storage_mgr.load();
    let key = ensure_unlocked_user_key(&vault, &storage)?;
    let query_lower = query.to_lowercase();
    let item = omawarden::api::decrypt_sync_ciphers_with_context(
        &storage.ciphers,
        &storage.folders,
        &storage.organizations,
        &key,
        storage.enc_private_key.as_deref(),
    )
    .into_iter()
    .find(|item| {
        item.deleted_at.is_none()
            && (item.id == query
                || item.name.eq_ignore_ascii_case(query)
                || item.name.to_lowercase().contains(&query_lower))
    });
    Ok(item.map(|item| VaultOutputItem {
        item,
        scope: storage
            .credential_id
            .map(|credential_id| ClipboardScope::Cache {
                path: vault.storage_mgr.file_path,
                credential_id,
            }),
    }))
}

fn prompt_candidate_selection(candidates: &[Value], target: &str) -> Option<Value> {
    eprintln!("Multiple ciphers matched '{}':", target);
    for (idx, item) in candidates.iter().enumerate() {
        let num = idx + 1;
        let name = item["name"].as_str().unwrap_or("unnamed");
        let item_type = item["type"].as_str().unwrap_or("unknown");
        let id = item["id"].as_str().unwrap_or("");
        let sub = item
            .get("sub_title")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        if let Some(sub) = sub {
            eprintln!("  {num}) {name} ({item_type} - {sub}) [{id}]");
        } else {
            eprintln!("  {num}) {name} ({item_type}) [{id}]");
        }
    }
    eprint!(
        "Select cipher [1-{}] (or 'q' to cancel): ",
        candidates.len()
    );
    let _ = io::stderr().flush();

    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return None;
    }
    let trimmed = input.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("q") {
        return None;
    }
    if let Ok(choice) = trimmed.parse::<usize>() {
        if (1..=candidates.len()).contains(&choice) {
            return Some(candidates[choice - 1].clone());
        }
    }
    eprintln!("Invalid selection.");
    None
}

fn resolve_target_cipher(
    target: &str,
    purpose: &str,
    client_ctx: Option<&omawarden::api::ClientContext>,
    is_interactive: bool,
    json: bool,
    trash: bool,
) -> Result<Value, ExitCode> {
    let mut resolve_req = json!({
        "action": "cipher_resolve",
        "target": target,
        "purpose": purpose,
        "trash": trash,
    });
    if let Some(ctx) = client_ctx {
        resolve_req["client"] = json!(ctx);
    }

    match submit_cipher_mutation(&resolve_req) {
        Ok(res) => Ok(res["item"].clone()),
        Err(err_obj) => {
            if err_obj.get("ambiguous") == Some(&Value::Bool(true)) {
                if is_interactive {
                    let candidates = err_obj.get("candidates").and_then(Value::as_array);
                    if let Some(candidates) = candidates {
                        if let Some(selected) = prompt_candidate_selection(candidates, target) {
                            return Ok(selected);
                        }
                    }
                    eprintln!("Selection cancelled.");
                    return Err(ExitCode::FAILURE);
                } else {
                    let err_msg = err_obj
                        .get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("Multiple ciphers matched query.");
                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&json!({
                                "ok": false,
                                "error": err_msg,
                            }))
                            .unwrap()
                        );
                    } else {
                        eprintln!("Error: {err_msg}");
                    }
                    return Err(ExitCode::FAILURE);
                }
            }

            let err_msg = err_obj
                .get("error")
                .and_then(Value::as_str)
                .unwrap_or("Failed to resolve cipher");
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": false,
                        "error": err_msg,
                    }))
                    .unwrap()
                );
            } else {
                eprintln!("Error: {err_msg}");
            }
            Err(ExitCode::FAILURE)
        }
    }
}

#[derive(Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct ParsedEditorField {
    name: String,
    value: String,
    field_type: i64,
}

#[derive(Debug, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
struct ParsedEditorCipher {
    name: String,
    username: Option<String>,
    password: Option<String>,
    uris: Vec<String>,
    fields: Vec<ParsedEditorField>,
    folder_id: Option<String>,
    favorite: bool,
    notes: String,
}

fn format_editor_template(
    item_id: &str,
    item_name: &str,
    item_type: &str,
    item_details: Option<&VaultItem>,
) -> zeroize::Zeroizing<String> {
    use std::fmt::Write as _;
    let mut out = zeroize::Zeroizing::new(String::new());
    let _ = writeln!(out, "# Editing {item_type} cipher: {item_name} ({item_id})");
    out.push_str("# Lines starting with '#' before the notes section are ignored.\n");
    out.push_str(
        "# Save and exit the editor to apply changes, or exit without changes to abort.\n\n",
    );

    let _ = writeln!(out, "Name: {item_name}");
    if item_type == "login" {
        let username = item_details
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("username"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let password = item_details
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("password"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let _ = writeln!(out, "Username: {username}");
        let _ = writeln!(out, "Password: {password}");
        let uris = item_details
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("uris"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for uri in &uris {
            let value = uri.get("uri").and_then(Value::as_str).unwrap_or("");
            let _ = writeln!(out, "URI: {value}");
        }
    }
    let folder_id = item_details
        .and_then(|i| i.folder_id.as_deref())
        .unwrap_or("");
    let favorite = item_details.map(|i| i.favorite).unwrap_or(false);
    let _ = writeln!(out, "Folder: {folder_id}");
    let _ = writeln!(out, "Favorite: {favorite}");

    out.push_str("\n# Custom Fields:\n");
    if let Some(details) = item_details {
        for field in &details.fields {
            let name = field.get("name").and_then(Value::as_str).unwrap_or("");
            let value = field.get("value").and_then(Value::as_str).unwrap_or("");
            match field.get("type").and_then(Value::as_i64).unwrap_or(0) {
                0 => {
                    let _ = writeln!(out, "Field: {name} = {value}");
                }
                1 => {
                    let _ = writeln!(out, "Hidden Field: {name} = {value}");
                }
                2 => {
                    let _ = writeln!(out, "Bool Field: {name} = {value}");
                }
                // Linked custom fields are read-only here and preserved untouched.
                _ => {}
            }
        }
    }

    out.push_str("\n# Notes (everything below this line is treated as notes):\n");
    if let Some(notes) = item_details.and_then(|i| i.notes.as_deref()) {
        out.push_str(notes);
    }
    out
}

fn parse_editor_field(
    value: &str,
    field_type: i64,
    line_number: usize,
    key: &str,
) -> Result<ParsedEditorField, String> {
    let Some((name, field_value)) = value.split_once('=') else {
        return Err(format!(
            "Invalid custom field on line {line_number}: expected '{key}: NAME = VALUE'."
        ));
    };
    let name = name.trim();
    if name.is_empty() {
        return Err(format!(
            "Invalid custom field on line {line_number}: name cannot be empty."
        ));
    }
    let mut field_value = field_value.trim().to_string();
    if field_type == 2 {
        match parse_cli_bool(&field_value) {
            Ok(parsed) => field_value = parsed.to_string(),
            Err(_) => {
                return Err(format!(
                    "Invalid boolean value '{field_value}' for custom field '{name}' on line {line_number}: expected true or false."
                ));
            }
        }
    }
    Ok(ParsedEditorField {
        name: name.to_string(),
        value: field_value,
        field_type,
    })
}

fn parse_editor_template(content: &str, item_type: &str) -> Result<ParsedEditorCipher, String> {
    let mut in_notes = false;
    let mut notes_lines = Vec::new();

    let mut name = String::new();
    let mut username = String::new();
    let mut password = String::new();
    let mut uris: Vec<String> = Vec::new();
    let mut fields: Vec<ParsedEditorField> = Vec::new();
    let mut folder_id = String::new();
    let mut favorite = false;

    for (index, line) in content.lines().enumerate() {
        let line_number = index + 1;
        if in_notes {
            notes_lines.push(line);
            continue;
        }

        let trimmed = line.trim();
        if trimmed.starts_with("# Notes") {
            in_notes = true;
            continue;
        }

        if trimmed.starts_with('#') || trimmed.is_empty() {
            continue;
        }

        if let Some((key, val)) = line.split_once(':') {
            let key = key.trim().to_lowercase();
            let val = val.trim();
            match key.as_str() {
                "name" => name = val.to_string(),
                "username" => username = val.to_string(),
                "password" => password = val.to_string(),
                "uri" => {
                    if !val.is_empty() {
                        uris.push(val.to_string());
                    }
                }
                "field" => fields.push(parse_editor_field(val, 0, line_number, "Field")?),
                "hidden field" => {
                    fields.push(parse_editor_field(val, 1, line_number, "Hidden Field")?)
                }
                "bool field" => fields.push(parse_editor_field(val, 2, line_number, "Bool Field")?),
                "folder" | "folder_id" | "folder id" => folder_id = val.to_string(),
                "favorite" => {
                    favorite =
                        parse_cli_bool(val).map_err(|e| format!("Invalid favorite value: {e}"))?;
                }
                _ => {}
            }
        }
    }

    let has_login = item_type == "login";
    let notes = notes_lines.join("\n");
    let folder_opt = if folder_id.is_empty() {
        None
    } else {
        Some(folder_id)
    };

    Ok(ParsedEditorCipher {
        name,
        username: if has_login { Some(username) } else { None },
        password: if has_login { Some(password) } else { None },
        uris: if has_login { uris } else { Vec::new() },
        fields,
        folder_id: folder_opt,
        favorite,
        notes,
    })
}

fn spawn_editor(path: &std::path::Path) -> Result<std::process::ExitStatus, std::io::Error> {
    let editor = std::env::var("VISUAL")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("EDITOR")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
        .unwrap_or_else(|| {
            if which::which("nano").is_ok() {
                "nano".to_string()
            } else {
                "vi".to_string()
            }
        });

    let parts: Vec<&str> = editor.split_whitespace().collect();
    if parts.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "Editor not set",
        ));
    }

    let mut cmd = std::process::Command::new(parts[0]);
    for arg in &parts[1..] {
        cmd.arg(arg);
    }
    cmd.arg(path);
    cmd.status()
}

fn securely_wipe_and_remove(mut temp: tempfile::NamedTempFile) {
    use std::io::Seek;
    let path = temp.path().to_path_buf();

    // 1. Wipe the open file handle starting from offset 0
    if let Ok(meta) = temp.as_file().metadata() {
        let len = (meta.len() as usize).max(4096);
        let zeroes = vec![0u8; len];
        if temp.as_file_mut().seek(std::io::SeekFrom::Start(0)).is_ok() {
            let _ = temp.as_file_mut().write_all(&zeroes);
            let _ = temp.as_file_mut().flush();
            let _ = temp.as_file().sync_all();
        }
    }

    // 2. Also re-open path directly in case editor performed atomic save (new inode)
    if path.exists() {
        if let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(&path) {
            if let Ok(meta) = file.metadata() {
                let len = (meta.len() as usize).max(4096);
                let zeroes = vec![0u8; len];
                let _ = file.write_all(&zeroes);
                let _ = file.flush();
                let _ = file.sync_all();
            }
        }
    }

    // 3. Close handle and delete from disk
    let _ = temp.close();
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }
}

fn handle_editor_edit(
    cfg: &Config,
    resolved: &Value,
    client_ctx: Option<&omawarden::api::ClientContext>,
) -> ExitCode {
    let item_id = resolved["id"].as_str().unwrap_or("").to_string();
    let item_name = resolved["name"].as_str().unwrap_or("").to_string();
    let item_type = resolved["type"].as_str().unwrap_or("login");

    let full_item = vault_output_item(cfg, &item_id, false)
        .ok()
        .flatten()
        .map(|o| o.item);

    let initial_template =
        format_editor_template(&item_id, &item_name, item_type, full_item.as_ref());

    let mut builder = tempfile::Builder::new();
    builder.prefix("omawarden-edit-").suffix(".txt");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o600));
    }

    let mut temp_file = match builder.tempfile() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("Error: Failed to create temporary file for editor: {e}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(e) = temp_file.write_all(initial_template.as_bytes()) {
        securely_wipe_and_remove(temp_file);
        eprintln!("Error: Failed to write to temporary file: {e}");
        return ExitCode::FAILURE;
    }
    let _ = temp_file.flush();

    let status = match spawn_editor(temp_file.path()) {
        Ok(s) => s,
        Err(e) => {
            securely_wipe_and_remove(temp_file);
            eprintln!("Error: Failed to launch editor: {e}");
            return ExitCode::FAILURE;
        }
    };

    if !status.success() {
        securely_wipe_and_remove(temp_file);
        eprintln!("Editor exited with non-zero status.");
        return ExitCode::FAILURE;
    }

    let edited_content = match std::fs::read_to_string(temp_file.path()) {
        Ok(c) => zeroize::Zeroizing::new(c),
        Err(e) => {
            securely_wipe_and_remove(temp_file);
            eprintln!("Error: Failed to read edited temporary file: {e}");
            return ExitCode::FAILURE;
        }
    };

    let parsed = match parse_editor_template(&edited_content, item_type) {
        Ok(p) => p,
        Err(e) => {
            // A formatting mistake must never discard the user's draft: keep
            // the 0600 temp file and point the user at it instead of wiping.
            let draft_path = temp_file.path().to_path_buf();
            let _ = temp_file.keep();
            eprintln!("Error: {e}");
            eprintln!(
                "Your edits were kept at {} so no changes are lost; fix the format and re-run.",
                draft_path.display()
            );
            return ExitCode::FAILURE;
        }
    };

    if parsed.name.trim().is_empty() {
        let draft_path = temp_file.path().to_path_buf();
        let _ = temp_file.keep();
        eprintln!("Error: Cipher name cannot be empty.");
        eprintln!(
            "Your edits were kept at {} so no changes are lost; fix the name and re-run.",
            draft_path.display()
        );
        return ExitCode::FAILURE;
    }

    let orig_name = &item_name;
    let orig_notes = full_item
        .as_ref()
        .and_then(|i| i.notes.as_deref())
        .unwrap_or("");
    let orig_favorite = full_item.as_ref().map(|i| i.favorite).unwrap_or(false);
    let orig_folder_id = full_item.as_ref().and_then(|i| i.folder_id.as_deref());

    let (orig_user, orig_pass) = if item_type == "login" {
        let u = full_item
            .as_ref()
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("username"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let p = full_item
            .as_ref()
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("password"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        (u, p)
    } else {
        (String::new(), String::new())
    };

    let orig_uris: Vec<String> = if item_type == "login" {
        full_item
            .as_ref()
            .and_then(|i| i.login.as_ref())
            .and_then(|l| l.get("uris"))
            .and_then(Value::as_array)
            .map(|uris| {
                uris.iter()
                    .filter_map(|u| u.get("uri").and_then(Value::as_str).map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    } else {
        Vec::new()
    };

    // Only Text/Hidden/Boolean fields are editable here; Linked fields stay
    // read-only and are therefore excluded from both template and diff.
    let orig_fields: Vec<(String, String, i64)> = full_item
        .as_ref()
        .map(|item| {
            item.fields
                .iter()
                .filter_map(|field| {
                    let field_type = field.get("type").and_then(Value::as_i64).unwrap_or(0);
                    if field_type == 3 {
                        return None;
                    }
                    Some((
                        field.get("name").and_then(Value::as_str)?.to_string(),
                        field
                            .get("value")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                        field_type,
                    ))
                })
                .collect()
        })
        .unwrap_or_default();

    let name_changed = parsed.name != *orig_name;
    let username_changed =
        item_type == "login" && parsed.username.as_deref() != Some(orig_user.as_str());
    let password_changed =
        item_type == "login" && parsed.password.as_deref() != Some(orig_pass.as_str());
    let uris_changed = item_type == "login" && parsed.uris != orig_uris;
    let folder_changed = parsed.folder_id.as_deref() != orig_folder_id;
    let favorite_changed = parsed.favorite != orig_favorite;
    let notes_changed =
        parsed.notes.trim_end_matches(['\r', '\n']) != orig_notes.trim_end_matches(['\r', '\n']);

    // Fields absent from the edited buffer are removed; fields whose value or
    // type changed (or that are new) are upserted. Untouched and read-only
    // fields are left alone.
    let mut upsert_fields: Vec<Value> = Vec::new();
    for field in &parsed.fields {
        let unchanged = orig_fields.iter().any(|(name, value, field_type)| {
            *name == field.name && *value == field.value && *field_type == field.field_type
        });
        if !unchanged {
            upsert_fields.push(json!({
                "name": field.name,
                "value": field.value,
                "type": field.field_type,
            }));
        }
    }
    let remove_field_names: Vec<String> = orig_fields
        .iter()
        .filter(|(name, _, _)| !parsed.fields.iter().any(|f| f.name == *name))
        .map(|(name, _, _)| name.clone())
        .collect();
    let fields_changed = !upsert_fields.is_empty() || !remove_field_names.is_empty();

    if !name_changed
        && !username_changed
        && !password_changed
        && !uris_changed
        && !folder_changed
        && !favorite_changed
        && !notes_changed
        && !fields_changed
    {
        securely_wipe_and_remove(temp_file);
        println!("No changes made.");
        return ExitCode::SUCCESS;
    }

    let mut daemon_req = json!({
        "action": "cipher_update",
        "id": item_id,
    });
    if name_changed {
        daemon_req["name"] = json!(parsed.name);
    }
    if username_changed {
        daemon_req["username"] = json!(parsed.username);
    }
    if password_changed {
        daemon_req["password"] = json!(parsed.password);
    }
    if uris_changed {
        daemon_req["uris"] = json!(parsed.uris);
    }
    if !upsert_fields.is_empty() {
        daemon_req["fields"] = json!(upsert_fields);
    }
    if !remove_field_names.is_empty() {
        daemon_req["remove_fields"] = json!(remove_field_names);
    }
    if folder_changed {
        daemon_req["folder_id"] = json!(parsed.folder_id.as_deref().unwrap_or(""));
    }
    if favorite_changed {
        daemon_req["favorite"] = json!(parsed.favorite);
    }
    if notes_changed {
        daemon_req["notes"] = json!(parsed.notes.trim_end_matches(['\r', '\n']));
    }
    if let Some(ctx) = client_ctx {
        daemon_req["client"] = json!(ctx);
    }

    securely_wipe_and_remove(temp_file);

    match submit_cipher_mutation(&daemon_req) {
        Ok(receipt) => {
            let id = receipt["item"]["id"].as_str().unwrap_or(&item_id);
            let name = receipt["item"]["name"].as_str().unwrap_or(&parsed.name);
            println!("Updated cipher \"{}\" ({}).", name, id);
            ExitCode::SUCCESS
        }
        Err(error) => {
            let err_msg = error
                .get("error")
                .and_then(|v| v.as_str())
                .unwrap_or("Failed to update cipher");
            eprintln!("Error: {}", err_msg);
            ExitCode::FAILURE
        }
    }
}

struct TotpOutput {
    result: TotpResult,
    item: Option<(String, String)>,
    scope: Option<ClipboardScope>,
}

impl TotpOutput {
    fn standalone(secret: &str) -> Option<Self> {
        generate_totp(secret, None, 6, 30).map(|result| Self {
            result,
            item: None,
            scope: None,
        })
    }
}

fn totp_output(
    cfg: &Config,
    query: Option<&str>,
    copy: bool,
) -> Result<Option<TotpOutput>, String> {
    let unverified = || "Could not verify the clipboard source session.".to_string();
    if let Some(query) = query {
        let Some(found) = vault_output_item(cfg, query, false).ok().flatten() else {
            return Ok(TotpOutput::standalone(query));
        };
        if copy && found.scope.is_none() {
            return Err(unverified());
        }
        let output = found
            .item
            .login
            .as_ref()
            .and_then(|login| login["totp"].as_str())
            .and_then(|seed| generate_totp(seed, None, 6, 30));
        return Ok(output.map(|result| TotpOutput {
            result,
            item: Some((found.item.id, found.item.name)),
            scope: found.scope,
        }));
    }

    let text = read_secret_stdin();
    let input = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
    if let Some(secret) = input["secret"].as_str() {
        return Ok(TotpOutput::standalone(secret));
    }
    let Some(query) = input["query"].as_str().or_else(|| input["id"].as_str()) else {
        return Ok(TotpOutput::standalone(&text));
    };
    let Some(reply) = send_daemon_request(&json!({ "action": "totp", "query": query }))
        .filter(|reply| reply["ok"] == true)
    else {
        return Ok(None);
    };
    let scope = reply["lock_generation"]
        .as_u64()
        .map(ClipboardScope::Session);
    if copy && scope.is_none() {
        return Err(unverified());
    }
    Ok(reply["code"].as_str().map(|code| TotpOutput {
        result: TotpResult {
            code: code.to_owned(),
            ttl: reply["ttl"].as_u64().unwrap_or(30),
            period: reply["period"].as_u64().unwrap_or(30),
        },
        item: reply["id"]
            .as_str()
            .zip(reply["name"].as_str())
            .map(|(id, name)| (id.to_owned(), name.to_owned())),
        scope,
    }))
}

fn ensure_unlocked_user_key(
    vault_mgr: &VaultManager,
    st: &VaultStorage,
) -> Result<omawarden::crypto::SymmetricCryptoKey, String> {
    if st.enc_user_key.is_none() {
        return Err("Account not logged in. Please run 'omawarden auth login' first.".to_string());
    }
    st.check_unlock_credentials()?;
    if let Some(key) = vault_mgr.get_user_key() {
        return Ok(key);
    }

    let context = send_daemon_request(&json!({ "action": "ping" }))
        .and_then(|reply| reply["unlock_context"].as_str().map(str::to_owned));
    let (pwd, ..) = read_auth_payload();
    if pwd.is_empty() {
        return Err("Vault is locked. Please unlock the vault first using 'omawarden auth unlock' or provide Master Password.".to_string());
    }

    let user_key = vault_mgr
        .storage_mgr
        .unlock_user_key(&pwd, st)
        .map_err(|e| format!("Unlock failed: {:?}", e))?;

    if let Some(context) = context {
        let _ = send_daemon_request(&json!({
            "action": "unlock", "password": pwd, "expected_unlock_context": context,
            "expected_credential_id": st.credential_id
        }));
    }

    Ok(user_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_decryption_rejects_an_unscoped_cache_even_with_a_cached_key() {
        let dir = tempfile::tempdir().unwrap();
        let manager = omawarden::storage::StorageManager::new(dir.path().join("data.json"));
        manager
            .save(&omawarden::storage::VaultStorage {
                enc_user_key: Some("wrapped-fixture-key".into()),
                ..Default::default()
            })
            .unwrap();
        let vault = VaultManager::new("", Some(manager), None);
        *vault.is_unlocked.write().unwrap() = true;
        *vault.user_key.write().unwrap() =
            Some(omawarden::crypto::SymmetricCryptoKey::from_raw_bytes(&[42; 64]).unwrap());
        let result = ensure_unlocked_user_key(&vault, &vault.storage_mgr.load());
        assert!(matches!(result, Err(error) if error.contains("Sign in again")));
    }

    #[test]
    fn test_parse_cli_bool_accepts_known_values() {
        for v in ["true", "TRUE", "1", "yes", " Yes "] {
            assert!(matches!(parse_cli_bool(v), Ok(true)), "{v}");
        }
        for v in ["false", "0", "NO", " no "] {
            assert!(matches!(parse_cli_bool(v), Ok(false)), "{v}");
        }
    }

    #[test]
    fn test_parse_cli_bool_rejects_typos() {
        // "ture" must be a hard error: coerced to false it would persist a
        // disabled setting and wipe the retained quick-unlock key.
        for v in ["ture", "flase", "on", "off", ""] {
            assert!(parse_cli_bool(v).is_err(), "{v} should not parse");
        }
    }

    #[test]
    fn test_parse_auth_payload_plain() {
        let (pwd, code, provider, ndv) = parse_auth_payload("mypassword\n");
        assert_eq!(pwd, "mypassword");
        assert_eq!(code, None);
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_parse_auth_payload_json_with_code() {
        let (pwd, code, provider, ndv) =
            parse_auth_payload("{\"password\": \"secret123\", \"code\": \"654321\"}\n");
        assert_eq!(pwd, "secret123");
        assert_eq!(code.as_deref(), Some("654321"));
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_parse_auth_payload_json_with_new_device_otp() {
        let (pwd, code, provider, ndv) = parse_auth_payload(
            "{\"password\": \"secret123\", \"code\": \"111222\", \"new_device_otp\": \"111222\"}\n",
        );
        assert_eq!(pwd, "secret123");
        assert_eq!(code.as_deref(), Some("111222"));
        assert_eq!(provider, None);
        assert_eq!(ndv.as_deref(), Some("111222"));

        let (pwd2, code2, provider2, ndv2) =
            parse_auth_payload("{\"password\": \"secret123\", \"newDeviceOtp\": \"333444\"}\n");
        assert_eq!(pwd2, "secret123");
        assert_eq!(code2, None);
        assert_eq!(provider2, None);
        assert_eq!(ndv2.as_deref(), Some("333444"));
    }

    #[test]
    fn test_parse_auth_payload_json_with_provider() {
        let (pwd, code, provider, ndv) = parse_auth_payload(
            "{\"password\": \"secret123\", \"code\": \"123456\", \"two_factor_provider\": 1}\n",
        );
        assert_eq!(pwd, "secret123");
        assert_eq!(code.as_deref(), Some("123456"));
        assert_eq!(provider, Some(1));
        assert_eq!(ndv, None);

        let (pwd2, code2, provider2, ndv2) = parse_auth_payload(
            "{\"password\": \"secret123\", \"code\": \"999888\", \"provider\": \"3\"}\n",
        );
        assert_eq!(pwd2, "secret123");
        assert_eq!(code2.as_deref(), Some("999888"));
        assert_eq!(provider2, Some(3));
        assert_eq!(ndv2, None);
    }

    #[test]
    fn test_parse_auth_payload_json_without_code() {
        let (pwd, code, provider, ndv) = parse_auth_payload("{\"password\": \"secret123\"}\n");
        assert_eq!(pwd, "secret123");
        assert_eq!(code, None);
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

    #[test]
    fn test_parse_auth_payload_empty() {
        let (pwd, code, provider, ndv) = parse_auth_payload("  \r\n");
        assert_eq!(pwd, "");
        assert_eq!(code, None);
        assert_eq!(provider, None);
        assert_eq!(ndv, None);
    }

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
    fn test_format_editor_template_login() {
        let details = VaultItem {
            id: "uuid-1".into(),
            type_name: "login".into(),
            name: "GitHub".into(),
            notes: Some("Special note".into()),
            favorite: true,
            folder_id: Some("folder-1".into()),
            login: Some(json!({
                "username": "octocat",
                "password": "supersecret",
                "uris": [{"uri": "https://github.com"}]
            })),
            ..Default::default()
        };
        let tpl = format_editor_template("uuid-1", "GitHub", "login", Some(&details));
        assert!(tpl.contains("Name: GitHub"));
        assert!(tpl.contains("Username: octocat"));
        assert!(tpl.contains("Password: supersecret"));
        assert!(tpl.contains("URI: https://github.com"));
        assert!(tpl.contains("Folder: folder-1"));
        assert!(tpl.contains("Favorite: true"));
        assert!(tpl.contains("Special note"));
    }

    #[test]
    fn test_parse_editor_template_valid() {
        let content = "\
# Comment
Name: Updated Name
Username: updated_user
Password: new_password
URI: https://example.com/updated
Folder: folder-2
Favorite: true

# Notes (everything below this line is treated as notes):
Note line 1
Note line 2 with: colons and # symbols
";
        let parsed = parse_editor_template(content, "login").unwrap();
        assert_eq!(parsed.name, "Updated Name");
        assert_eq!(parsed.username.as_deref(), Some("updated_user"));
        assert_eq!(parsed.password.as_deref(), Some("new_password"));
        assert_eq!(parsed.uris, vec!["https://example.com/updated"]);
        assert_eq!(parsed.folder_id.as_deref(), Some("folder-2"));
        assert!(parsed.favorite);
        assert_eq!(
            parsed.notes,
            "Note line 1\nNote line 2 with: colons and # symbols"
        );
    }

    #[test]
    fn test_format_editor_template_multi_uri_and_fields() {
        let details = VaultItem {
            id: "uuid-1".into(),
            type_name: "login".into(),
            name: "GitHub".into(),
            notes: None,
            favorite: false,
            login: Some(json!({
                "username": "octocat",
                "password": "supersecret",
                "uris": [
                    {"uri": "https://github.com"},
                    {"uri": "https://api.github.com"}
                ]
            })),
            fields: vec![
                json!({"name": "PIN", "value": "1234", "type": 0}),
                json!({"name": "Recovery Code", "value": "sec-98765", "type": 1}),
                json!({"name": "Requires VPN", "value": "true", "type": 2}),
                json!({"name": "Linked", "value": "cipher-uuid", "type": 3}),
            ],
            ..Default::default()
        };
        let tpl = format_editor_template("uuid-1", "GitHub", "login", Some(&details));
        assert!(tpl.contains("URI: https://github.com\n"));
        assert!(tpl.contains("URI: https://api.github.com\n"));
        assert!(tpl.contains("# Custom Fields:\n"));
        assert!(tpl.contains("Field: PIN = 1234\n"));
        assert!(tpl.contains("Hidden Field: Recovery Code = sec-98765\n"));
        assert!(tpl.contains("Bool Field: Requires VPN = true\n"));
        // Linked fields are read-only and never rendered.
        assert!(!tpl.contains("Linked"));
    }

    #[test]
    fn test_parse_editor_template_multi_uri_and_fields() {
        let content = "\
Name: Updated
Username: user
Password: pass
URI: https://one.example
URI: https://two.example

# Custom Fields:
Field: PIN = 1234
Hidden Field: Recovery Code = sec-98765
Bool Field: Requires VPN = true
Bool Field: Retired = false

# Notes (everything below this line is treated as notes):
body
";
        let parsed = parse_editor_template(content, "login").unwrap();
        assert_eq!(
            parsed.uris,
            vec!["https://one.example", "https://two.example"]
        );
        assert_eq!(parsed.fields.len(), 4);
        assert_eq!(parsed.fields[0].name, "PIN");
        assert_eq!(parsed.fields[0].value, "1234");
        assert_eq!(parsed.fields[0].field_type, 0);
        assert_eq!(parsed.fields[1].name, "Recovery Code");
        assert_eq!(parsed.fields[1].field_type, 1);
        assert_eq!(parsed.fields[2].name, "Requires VPN");
        assert_eq!(parsed.fields[2].value, "true");
        assert_eq!(parsed.fields[2].field_type, 2);
        assert_eq!(parsed.fields[3].name, "Retired");
        assert_eq!(parsed.fields[3].value, "false");
        assert_eq!(parsed.notes, "body");
    }

    #[test]
    fn test_parse_editor_template_rejects_malformed_custom_field_with_line() {
        let content = "\
Name: Updated
# Custom Fields:
Field: NoSeparator
# Notes:
";
        let err = parse_editor_template(content, "login").unwrap_err();
        assert!(
            err.contains("line 3") && err.contains("Field: NAME = VALUE"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_parse_editor_template_rejects_invalid_bool_field_with_line() {
        let content = "\
Name: Updated
# Custom Fields:
Bool Field: Active = maybe
# Notes:
";
        let err = parse_editor_template(content, "login").unwrap_err();
        assert!(
            err.contains("line 3")
                && err.contains("Invalid boolean value 'maybe'")
                && err.contains("'Active'"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_parse_editor_template_rejects_invalid_favorite() {
        let content = "Name: Foo\nFavorite: not_a_bool\n# Notes:\n";
        let res = parse_editor_template(content, "login");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("Invalid favorite value"));
    }

    #[test]
    fn test_build_custom_fields_typed_flags() {
        let fields = build_custom_fields(
            &["Cluster=Prod".to_string()],
            &["API_KEY=secret-tok".to_string()],
            &["Requires VPN=true".to_string(), "Retired=false".to_string()],
        )
        .unwrap();
        assert_eq!(
            fields,
            vec![
                json!({"name": "Cluster", "value": "Prod", "type": 0}),
                json!({"name": "API_KEY", "value": "secret-tok", "type": 1}),
                json!({"name": "Requires VPN", "value": "true", "type": 2}),
                json!({"name": "Retired", "value": "false", "type": 2}),
            ]
        );
    }

    #[test]
    fn test_build_custom_fields_keeps_equals_in_value() {
        let fields = build_custom_fields(&["Equation=a=b".to_string()], &[], &[]).unwrap();
        assert_eq!(fields[0]["name"], "Equation");
        assert_eq!(fields[0]["value"], "a=b");
    }

    #[test]
    fn test_build_custom_fields_rejects_missing_separator() {
        let err = build_custom_fields(&["NoSeparator".to_string()], &[], &[]).unwrap_err();
        assert!(err.contains("expected NAME=VALUE"), "unexpected: {err}");
    }

    #[test]
    fn test_build_custom_fields_rejects_empty_name() {
        let err = build_custom_fields(&[], &["=oops".to_string()], &[]).unwrap_err();
        assert!(err.contains("name cannot be empty"), "unexpected: {err}");
    }

    #[test]
    fn test_build_custom_fields_rejects_malformed_boolean() {
        let err = build_custom_fields(&[], &[], &["Active=maybe".to_string()]).unwrap_err();
        assert!(
            err.contains("Invalid boolean value 'maybe' for custom field 'Active'"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn test_securely_wipe_and_remove() {
        let mut builder = tempfile::Builder::new();
        builder.prefix("test-wipe-").suffix(".txt");
        let mut temp = builder.tempfile().unwrap();
        let path = temp.path().to_path_buf();
        temp.write_all(b"SUPER_SECRET_PLAINTEXT_PASSWORD_12345")
            .unwrap();
        temp.flush().unwrap();

        securely_wipe_and_remove(temp);

        assert!(!path.exists());
    }
}

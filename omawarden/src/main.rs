use clap::{Parser, Subcommand};
use omawarden::attachment::get_attachment;
use omawarden::auth::AuthManager;
use omawarden::clipboard::ClipboardManager;
use omawarden::config::ConfigManager;
use omawarden::daemon::{run_daemon_server, send_daemon_request, DaemonState};
use omawarden::health::check_system_health;
use omawarden::hook::install_lock_hook;
use omawarden::ssh::{
    generate_keypair, parse_private_key, write_keypair_files, write_keypair_files_named,
    SshAlgorithm,
};
use omawarden::storage::StorageManager;
use omawarden::totp::generate_totp;
use omawarden::vault::VaultManager;
use serde_json::{json, Value};
use std::io::{self, BufRead, IsTerminal, Read, Write};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

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
enum Commands {
    #[command(about = "Manage configuration")]
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },
    #[command(about = "Check CLI health and installation")]
    Health {
        #[arg(long, help = "Override bw binary path to check")]
        bw_path: Option<String>,
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
    #[command(about = "Wayland clipboard integration")]
    Clipboard {
        #[command(subcommand)]
        action: ClipboardAction,
    },
    #[command(about = "Generate TOTP verification code")]
    Totp {
        #[command(subcommand)]
        action: TotpAction,
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
    #[command(about = "Run omawarden background daemon")]
    Daemon {
        #[arg(long, default_value = "15")]
        auto_lock: u64,
    },
}

#[derive(Subcommand)]
enum ConfigAction {
    #[command(about = "Get current configuration")]
    Get,
    #[command(about = "Set configuration options")]
    Set {
        #[arg(long)]
        server_url: Option<String>,
        #[arg(long)]
        bw_path: Option<String>,
        #[arg(long)]
        download_dir: Option<String>,
        #[arg(long)]
        auto_lock: Option<i64>,
        #[arg(long)]
        clipboard_clear: Option<i64>,
        #[arg(long)]
        max_output_mb: Option<i64>,
        #[arg(long)]
        email: Option<String>,
        #[arg(long)]
        remember_email: Option<String>,
        #[arg(long)]
        log_level: Option<String>,
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
    },
    #[command(about = "Login using API Key (client_secret read from stdin)")]
    LoginApikey {
        #[arg(long, required = true)]
        client_id: String,
    },
    #[command(about = "Unlock vault with master password (password read from stdin)")]
    Unlock,
    #[command(about = "Lock vault and clear session")]
    Lock,
    #[command(about = "Logout from Bitwarden account")]
    Logout,
}

#[derive(Subcommand)]
enum HookAction {
    #[command(about = "Install system-lock hook into Omarchy hooks directory")]
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
    },
    #[command(about = "Search vault items")]
    Search {
        #[arg(long, default_value = "")]
        query: String,
        #[arg(long = "filter")]
        category: Option<String>,
    },
}

#[derive(Subcommand)]
enum ClipboardAction {
    #[command(about = "Copy text to clipboard (text read securely from stdin)")]
    Copy {
        #[arg(long)]
        sensitive: bool,
        #[arg(long)]
        timeout: Option<i64>,
    },
    #[command(about = "Clear clipboard immediately")]
    Clear,
}

#[derive(Subcommand)]
enum TotpAction {
    #[command(
        about = "Generate TOTP code from secret or otpauth URI (supports stdin and --secret)"
    )]
    Generate {
        #[arg(index = 1)]
        positional_secret: Option<String>,
        #[arg(long)]
        secret: Option<String>,
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

fn read_auth_payload() -> (String, Option<String>) {
    let stdin = io::stdin();
    if stdin.is_terminal() {
        return (String::new(), None);
    }
    let mut raw = String::new();
    let _ = stdin.lock().read_line(&mut raw);
    let raw = raw.trim();
    if raw.is_empty() {
        return (String::new(), None);
    }

    if let Ok(val) = serde_json::from_str::<Value>(raw) {
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
            return (pwd, code_val);
        }
    }

    let mut lines = raw.splitn(2, '\n');
    let first = lines
        .next()
        .unwrap_or("")
        .trim_end_matches('\r')
        .to_string();
    if let Some(second) = lines.next() {
        let second_trimmed = second.trim().to_string();
        if !second_trimmed.is_empty() {
            return (first, Some(second_trimmed));
        }
    }
    (first, None)
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let config_mgr = ConfigManager::new(cli.config.as_deref());
    let mut cfg = config_mgr.load();

    match cli.command {
        Commands::Daemon { auto_lock } => {
            let storage_mgr = StorageManager::default();
            let state = Arc::new(DaemonState::new(storage_mgr, auto_lock));
            println!("Starting omawarden daemon (auto_lock: {}m)...", auto_lock);
            if let Err(e) = run_daemon_server(state) {
                eprintln!("Daemon server error: {}", e);
                ExitCode::FAILURE
            } else {
                ExitCode::SUCCESS
            }
        }

        Commands::Config { action } => match action {
            ConfigAction::Get => {
                println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
                ExitCode::SUCCESS
            }
            ConfigAction::Set {
                server_url,
                bw_path,
                download_dir,
                auto_lock,
                clipboard_clear,
                max_output_mb,
                email,
                remember_email,
                log_level,
            } => {
                if let Some(v) = server_url {
                    cfg.server_url = v;
                }
                if let Some(v) = bw_path {
                    cfg.bw_path = v;
                }
                if let Some(v) = download_dir {
                    cfg.download_dir = v;
                }
                if let Some(v) = auto_lock {
                    cfg.auto_lock_minutes = v;
                }
                if let Some(v) = clipboard_clear {
                    cfg.clipboard_clear_seconds = v;
                }
                if let Some(v) = max_output_mb {
                    cfg.max_output_mb = v;
                }
                if let Some(v) = email {
                    cfg.email = v;
                }
                if let Some(v) = remember_email {
                    let lower = v.trim().to_lowercase();
                    cfg.remember_email = matches!(lower.as_str(), "true" | "1" | "yes");
                }
                if let Some(v) = log_level {
                    cfg.log_level = v.to_lowercase();
                }
                let _ = config_mgr.save(&cfg);
                let safe_url = if cfg.server_url.is_empty() {
                    "default (official)".to_string()
                } else if cfg.server_url.contains("vault.bitwarden.com")
                    || cfg.server_url.contains("vault.bitwarden.eu")
                {
                    cfg.server_url.clone()
                } else {
                    "<REDACTED_CUSTOM_HOST>".to_string()
                };
                omawarden::log_info!(
                    "omawarden:config",
                    "Updated configuration (log_level: {}, server_url: {}).",
                    cfg.log_level,
                    safe_url
                );
                println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
                ExitCode::SUCCESS
            }
        },

        Commands::Health { bw_path: _ } => {
            let status = check_system_health(&cfg.server_url);
            println!("{}", serde_json::to_string_pretty(&status).unwrap());
            ExitCode::SUCCESS
        }

        Commands::Auth { action } => {
            let auth_mgr = AuthManager::new(&cfg.server_url, None, None);
            match action {
                AuthAction::Status => {
                    omawarden::daemon::ensure_daemon_running();
                    let st = auth_mgr.get_status(false);
                    println!("{}", serde_json::to_string_pretty(&st).unwrap());
                    ExitCode::SUCCESS
                }
                AuthAction::LoginPassword { email } => {
                    let (pwd, code_val) = read_auth_payload();
                    let res = auth_mgr.login_password(&email, &pwd, code_val.as_deref());
                    println!("{}", serde_json::to_string_pretty(&res).unwrap());
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::LoginApikey { client_id } => {
                    let raw_secret = read_secret_stdin();
                    let mut actual_secret = raw_secret.clone();
                    if raw_secret.starts_with('{') && raw_secret.ends_with('}') {
                        if let Ok(val) = serde_json::from_str::<Value>(&raw_secret) {
                            if let Some(s) = val.get("client_secret").and_then(|v| v.as_str()) {
                                actual_secret = s.to_string();
                            }
                        }
                    }
                    let res = auth_mgr.login_apikey(&client_id, &actual_secret);
                    println!("{}", serde_json::to_string_pretty(&res).unwrap());
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::Unlock => {
                    let pwd = if io::stdin().is_terminal() {
                        eprint!("Enter Master Password: ");
                        let _ = io::stderr().flush();
                        let mut buf = String::new();
                        let _ = io::stdin().read_line(&mut buf);
                        buf.trim_end_matches(&['\r', '\n'][..]).to_string()
                    } else {
                        read_secret_stdin()
                    };
                    omawarden::daemon::ensure_daemon_running();
                    let res = auth_mgr.unlock(&pwd);
                    println!("{}", serde_json::to_string_pretty(&res).unwrap());
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::Lock => {
                    let _ = send_daemon_request(&json!({ "action": "lock" }));
                    let res = auth_mgr.lock();
                    println!("{}", serde_json::to_string_pretty(&res).unwrap());
                    ExitCode::SUCCESS
                }
                AuthAction::Logout => {
                    let _ = send_daemon_request(&json!({ "action": "lock" }));
                    let res = auth_mgr.logout();
                    println!("{}", serde_json::to_string_pretty(&res).unwrap());
                    ExitCode::SUCCESS
                }
            }
        }

        Commands::Hook { action } => match action {
            HookAction::Install => match install_lock_hook(None, None) {
                Ok(path) => {
                    let json_val = serde_json::json!({
                        "ok": true,
                        "installed_path": path.to_string_lossy()
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
            let vault_mgr = VaultManager::new(&cfg.server_url, None, None);
            match action {
                VaultAction::Sync => {
                    omawarden::daemon::ensure_daemon_running();
                    let resp = send_daemon_request(&json!({ "action": "sync" }));
                    let ok = resp
                        .as_ref()
                        .and_then(|v| v.get("ok"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or_else(|| vault_mgr.sync().is_ok());
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({ "ok": ok })).unwrap()
                    );
                    if ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                VaultAction::List { category } => {
                    omawarden::daemon::ensure_daemon_running();
                    let st = send_daemon_request(&json!({ "action": "status" }));
                    let is_unlocked = st
                        .as_ref()
                        .and_then(|v| v.get("is_unlocked"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !is_unlocked && !vault_mgr.is_unlocked() {
                        println!(
                            "{}",
                            json!({ "ok": false, "error": "Vault is locked. Please unlock using 'omawarden auth unlock' first." })
                        );
                        return ExitCode::FAILURE;
                    }
                    let items = vault_mgr.get_items();
                    let filtered = vault_mgr.search(&items, "", category.as_deref());
                    println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
                    ExitCode::SUCCESS
                }
                VaultAction::Search { query, category } => {
                    omawarden::daemon::ensure_daemon_running();
                    let st = send_daemon_request(&json!({ "action": "status" }));
                    let is_unlocked = st
                        .as_ref()
                        .and_then(|v| v.get("is_unlocked"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if !is_unlocked && !vault_mgr.is_unlocked() {
                        println!(
                            "{}",
                            json!({ "ok": false, "error": "Vault is locked. Please unlock using 'omawarden auth unlock' first." })
                        );
                        return ExitCode::FAILURE;
                    }
                    let results = vault_mgr.search_items(&query, category.as_deref());
                    println!("{}", serde_json::to_string_pretty(&results).unwrap());
                    ExitCode::SUCCESS
                }
            }
        }

        Commands::Clipboard { action } => {
            let clip_mgr = ClipboardManager::default();
            match action {
                ClipboardAction::Copy { sensitive, timeout } => {
                    let text_val = read_clipboard_stdin();
                    let timeout_val = timeout.unwrap_or(cfg.clipboard_clear_seconds);
                    let ok = clip_mgr.copy(&text_val, sensitive, timeout_val);
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({ "ok": ok })).unwrap()
                    );
                    if ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                ClipboardAction::Clear => {
                    let ok = clip_mgr.clear();
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({ "ok": ok })).unwrap()
                    );
                    if ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
            }
        }

        Commands::Totp { action } => match action {
            TotpAction::Generate {
                positional_secret,
                secret,
            } => {
                let secret_val = secret
                    .or(positional_secret)
                    .unwrap_or_else(read_secret_stdin);
                match generate_totp(&secret_val, None, 6, 30) {
                    Some(res) => {
                        println!("{}", serde_json::to_string_pretty(&res).unwrap());
                        ExitCode::SUCCESS
                    }
                    None => {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(
                                &serde_json::json!({ "error": "Invalid TOTP secret" })
                            )
                            .unwrap()
                        );
                        ExitCode::FAILURE
                    }
                }
            }
        },

        Commands::Attachment { action } => match action {
            AttachmentAction::Download {
                item_id,
                attachment_id,
                filename,
                output_dir,
                open,
                preview,
            } => {
                let res = get_attachment(
                    &item_id,
                    &attachment_id,
                    &filename,
                    output_dir.as_deref(),
                    open,
                    preview,
                    None,
                    None,
                    true,
                );
                println!("{}", serde_json::to_string_pretty(&res).unwrap());
                if res.ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
        },

        Commands::SshKey { action } => {
            let vault_mgr = VaultManager::new(&cfg.server_url, None, None);
            match action {
                SshKeyAction::Create {
                    name,
                    algorithm,
                    comment,
                    notes,
                    folder,
                    out_dir,
                } => {
                    omawarden::daemon::ensure_daemon_running();
                    let keypair = match generate_keypair(algorithm, comment.as_deref()) {
                        Ok(k) => k,
                        Err(e) => {
                            println!("{}", json!({ "ok": false, "error": e }));
                            return ExitCode::FAILURE;
                        }
                    };

                    let daemon_req = json!({
                        "action": "ssh_key_create",
                        "name": name,
                        "private_key": keypair.private_key,
                        "public_key": keypair.public_key,
                        "fingerprint": keypair.fingerprint,
                        "notes": notes,
                        "folder_id": folder,
                    });

                    let daemon_res = send_daemon_request(&daemon_req);
                    let item_val = if let Some(res) =
                        daemon_res.filter(|r| r.get("ok").and_then(|v| v.as_bool()) == Some(true))
                    {
                        res.get("item").cloned()
                    } else {
                        match ensure_unlocked_user_key(&vault_mgr, &cfg.server_url) {
                            Ok(user_key) => {
                                match vault_mgr.create_ssh_key(
                                    &name,
                                    &keypair,
                                    notes.as_deref(),
                                    folder.as_deref(),
                                    &user_key,
                                ) {
                                    Ok(item) => Some(json!(item)),
                                    Err(e) => {
                                        println!("{}", json!({ "ok": false, "error": e }));
                                        return ExitCode::FAILURE;
                                    }
                                }
                            }
                            Err(e) => {
                                println!("{}", json!({ "ok": false, "error": e }));
                                return ExitCode::FAILURE;
                            }
                        }
                    };

                    let mut files_json = json!(null);
                    if let Some(ref dest_dir) = out_dir {
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

                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "item": item_val,
                            "files": files_json,
                        }))
                        .unwrap()
                    );
                    ExitCode::SUCCESS
                }

                SshKeyAction::Import {
                    name,
                    private_key,
                    public_key,
                    stdin,
                    notes,
                    folder,
                } => {
                    omawarden::daemon::ensure_daemon_running();
                    let raw_priv = if stdin || private_key.is_none() {
                        let mut buffer = String::new();
                        let _ = io::stdin().read_to_string(&mut buffer);
                        buffer
                    } else if let Some(ref p) = private_key {
                        match std::fs::read_to_string(p) {
                            Ok(c) => c,
                            Err(e) => {
                                println!("{}", json!({ "ok": false, "error": e.to_string() }));
                                return ExitCode::FAILURE;
                            }
                        }
                    } else {
                        String::new()
                    };

                    let mut keypair = match parse_private_key(&raw_priv) {
                        Ok(k) => k,
                        Err(e) => {
                            println!("{}", json!({ "ok": false, "error": e }));
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
                        "action": "ssh_key_create",
                        "name": name,
                        "private_key": keypair.private_key,
                        "public_key": keypair.public_key,
                        "fingerprint": keypair.fingerprint,
                        "notes": notes,
                        "folder_id": folder,
                    });

                    let daemon_res = send_daemon_request(&daemon_req);
                    let item_val = if let Some(res) =
                        daemon_res.filter(|r| r.get("ok").and_then(|v| v.as_bool()) == Some(true))
                    {
                        res.get("item").cloned()
                    } else {
                        match ensure_unlocked_user_key(&vault_mgr, &cfg.server_url) {
                            Ok(user_key) => {
                                match vault_mgr.create_ssh_key(
                                    &name,
                                    &keypair,
                                    notes.as_deref(),
                                    folder.as_deref(),
                                    &user_key,
                                ) {
                                    Ok(item) => Some(json!(item)),
                                    Err(e) => {
                                        println!("{}", json!({ "ok": false, "error": e }));
                                        return ExitCode::FAILURE;
                                    }
                                }
                            }
                            Err(e) => {
                                println!("{}", json!({ "ok": false, "error": e }));
                                return ExitCode::FAILURE;
                            }
                        }
                    };

                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({
                            "ok": true,
                            "item": item_val,
                        }))
                        .unwrap()
                    );
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
                    omawarden::daemon::ensure_daemon_running();
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
                        match ensure_unlocked_user_key(&vault_mgr, &cfg.server_url) {
                            Ok(user_key) => {
                                let storage = vault_mgr.storage_mgr.load();
                                let items = omawarden::api::decrypt_sync_ciphers_with_context(
                                    &storage.ciphers,
                                    &storage.folders,
                                    &storage.organizations,
                                    &user_key,
                                    storage.enc_private_key.as_deref(),
                                );
                                items.into_iter().find(|i| {
                                    i.type_name == "ssh_key"
                                        && (i.id == query
                                            || i.name.eq_ignore_ascii_case(&query)
                                            || i.name
                                                .to_lowercase()
                                                .contains(&query.to_lowercase()))
                                })
                            }
                            Err(e) => {
                                println!("{}", json!({ "ok": false, "error": e }));
                                return ExitCode::FAILURE;
                            }
                        }
                    };

                    let ssh_item = match item {
                        Some(i) => i,
                        None => {
                            println!(
                                "{}",
                                json!({ "ok": false, "error": format!("SSH key item '{}' not found in vault", query) })
                            );
                            return ExitCode::FAILURE;
                        }
                    };

                    let ssh_meta = match ssh_item.ssh_key {
                        Some(s) => s,
                        None => {
                            println!(
                                "{}",
                                json!({ "ok": false, "error": "Item has no SSH key metadata" })
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
                            println!("{}", json!({ "ok": false, "error": e.to_string() }));
                            ExitCode::FAILURE
                        }
                    }
                }
            }
        }
    }
}

fn ensure_unlocked_user_key(
    vault_mgr: &VaultManager,
    _server_url: &str,
) -> Result<omawarden::crypto::SymmetricCryptoKey, String> {
    if let Some(key) = vault_mgr.get_user_key() {
        return Ok(key);
    }

    let st = vault_mgr.storage_mgr.load();
    if st.enc_user_key.is_none() {
        return Err("Account not logged in. Please run 'omawarden auth login' first.".to_string());
    }

    let (pwd, _) = read_auth_payload();
    if pwd.is_empty() {
        return Err("Vault is locked. Please unlock the vault first using 'omawarden auth unlock' or provide Master Password.".to_string());
    }

    let user_key = vault_mgr
        .storage_mgr
        .unlock_user_key(&pwd, &st)
        .map_err(|e| format!("Unlock failed: {:?}", e))?;

    let _ = send_daemon_request(&json!({ "action": "unlock", "password": pwd }));

    Ok(user_key)
}

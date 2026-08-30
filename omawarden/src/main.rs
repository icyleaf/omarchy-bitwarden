use clap::{Parser, Subcommand};
use omawarden::attachment::get_attachment;
use omawarden::auth::AuthManager;
use omawarden::clipboard::ClipboardManager;
use omawarden::config::ConfigManager;
use omawarden::daemon::{run_daemon_server, send_daemon_request, DaemonState};
use omawarden::health::check_system_health;
use omawarden::hook::install_lock_hook;
use omawarden::storage::StorageManager;
use omawarden::totp::generate_totp;
use omawarden::vault::VaultManager;
use serde_json::{json, Value};
use std::io::{self, BufRead, IsTerminal};
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Parser)]
#[command(
    name = "omawarden",
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
    },
}

#[derive(Subcommand)]
enum AuthAction {
    #[command(about = "Get current authentication and vault lock status")]
    Status,
    #[command(about = "Login using Master Password")]
    LoginPassword {
        #[arg(long, required = true)]
        email: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        code: Option<String>,
    },
    #[command(about = "Login using API Key")]
    LoginApikey {
        #[arg(long, required = true)]
        client_id: String,
        #[arg(long)]
        client_secret: Option<String>,
    },
    #[command(about = "Unlock vault with master password")]
    Unlock {
        #[arg(long)]
        password: Option<String>,
    },
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
    #[command(about = "Copy text to clipboard")]
    Copy {
        #[arg(long)]
        text: Option<String>,
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
    #[command(about = "Generate TOTP code from secret or otpauth URI")]
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

fn read_secret_stdin(explicit_arg: Option<String>) -> String {
    if let Some(arg) = explicit_arg {
        return arg;
    }
    let stdin = io::stdin();
    if !stdin.is_terminal() {
        let mut buffer = String::new();
        if stdin.lock().read_line(&mut buffer).is_ok() {
            return buffer.trim_end_matches(&['\r', '\n'][..]).to_string();
        }
    }
    String::new()
}

fn read_auth_payload(
    explicit_password: Option<String>,
    explicit_code: Option<String>,
) -> (String, Option<String>) {
    if let Some(pwd) = explicit_password {
        return (pwd, explicit_code);
    }
    let stdin = io::stdin();
    let mut raw = String::new();
    if !stdin.is_terminal() {
        let _ = stdin.lock().read_line(&mut raw);
    }
    let raw = raw.trim();
    if raw.is_empty() {
        return (String::new(), explicit_code);
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
                .map(|s| s.to_string())
                .or(explicit_code);
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
    (first, explicit_code)
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
                let _ = config_mgr.save(&cfg);
                println!("{}", serde_json::to_string_pretty(&cfg).unwrap());
                ExitCode::SUCCESS
            }
        },

        Commands::Health { bw_path: _ } => {
            let status = check_system_health(&cfg.server_url);
            println!("{}", serde_json::to_string_pretty(&status).unwrap());
            if status.ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
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
                AuthAction::LoginPassword {
                    email,
                    password,
                    code,
                } => {
                    let (pwd, code_val) = read_auth_payload(password, code);
                    let res = auth_mgr.login_password(&email, &pwd, code_val.as_deref());
                    println!("{}", serde_json::to_string_pretty(&res).unwrap());
                    if res.ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                AuthAction::LoginApikey {
                    client_id,
                    client_secret,
                } => {
                    let raw_secret = read_secret_stdin(client_secret);
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
                AuthAction::Unlock { password } => {
                    let pwd = read_secret_stdin(password);
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
                        .unwrap_or_else(|| vault_mgr.sync(None));
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
                    if let Some(daemon_resp) = send_daemon_request(&json!({ "action": "list" })) {
                        if let Ok(items) =
                            serde_json::from_value::<Vec<omawarden::vault::VaultItem>>(daemon_resp)
                        {
                            let filtered = vault_mgr.search(&items, "", category.as_deref());
                            println!("{}", serde_json::to_string_pretty(&filtered).unwrap());
                            return ExitCode::SUCCESS;
                        }
                    }
                    println!("[]");
                    ExitCode::SUCCESS
                }
                VaultAction::Search { query, category } => {
                    omawarden::daemon::ensure_daemon_running();
                    if let Some(daemon_resp) = send_daemon_request(
                        &json!({ "action": "search", "query": query, "category": category }),
                    ) {
                        println!("{}", serde_json::to_string_pretty(&daemon_resp).unwrap());
                        return ExitCode::SUCCESS;
                    }
                    println!("[]");
                    ExitCode::SUCCESS
                }
            }
        }

        Commands::Clipboard { action } => {
            let clip_mgr = ClipboardManager::default();
            match action {
                ClipboardAction::Copy {
                    text,
                    sensitive,
                    timeout,
                } => {
                    let text_val = read_secret_stdin(text);
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
                    .unwrap_or_else(|| read_secret_stdin(None));
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
    }
}

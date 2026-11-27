use clap::{Subcommand, ValueEnum};
use omawarden_engine::config::Config;
use omawarden_engine::daemon::send_daemon_request;
use omawarden_engine::ssh::{
    generate_keypair, parse_private_key, write_keypair_files, write_keypair_files_named,
    SshAlgorithm,
};
use omawarden_engine::vault::VaultManager;
use serde_json::json;
use std::io::{self, Read};
use std::path::PathBuf;
use std::process::ExitCode;

use super::client::{ensure_unlocked_user_key, submit_ssh_cipher};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub(crate) enum CliSshAlgorithm {
    #[default]
    #[value(name = "ed25519", alias = "ED25519")]
    Ed25519,
    #[value(name = "rsa-2048", alias = "rsa2048", alias = "RSA-2048")]
    Rsa2048,
    #[value(name = "rsa-4096", alias = "rsa4096", alias = "RSA-4096")]
    Rsa4096,
    #[value(
        name = "ecdsa-p256",
        alias = "ecdsa256",
        alias = "p256",
        alias = "P-256"
    )]
    EcdsaP256,
    #[value(
        name = "ecdsa-p384",
        alias = "ecdsa384",
        alias = "p384",
        alias = "P-384"
    )]
    EcdsaP384,
}

impl From<CliSshAlgorithm> for SshAlgorithm {
    fn from(value: CliSshAlgorithm) -> Self {
        match value {
            CliSshAlgorithm::Ed25519 => SshAlgorithm::Ed25519,
            CliSshAlgorithm::Rsa2048 => SshAlgorithm::Rsa2048,
            CliSshAlgorithm::Rsa4096 => SshAlgorithm::Rsa4096,
            CliSshAlgorithm::EcdsaP256 => SshAlgorithm::EcdsaP256,
            CliSshAlgorithm::EcdsaP384 => SshAlgorithm::EcdsaP384,
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum SshKeyAction {
    #[command(about = "Generate a new SSH keypair and store it in Bitwarden")]
    Create {
        #[arg(long, required = true)]
        name: String,
        #[arg(long, default_value = "ed25519")]
        algorithm: CliSshAlgorithm,
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

pub(crate) fn run(action: SshKeyAction, cfg: &Config) -> ExitCode {
    let vault_mgr =
        VaultManager::with_identity_url(&cfg.server_url, cfg.identity_url.as_deref(), None, None);
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
            if let Err(e) = omawarden_engine::capabilities::check_feature_gating(
                &cfg.server_url,
                "ssh-key-vault-item",
                ignore_server_capabilities,
            ) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "ok": false, "error": e })).unwrap()
                );
                return ExitCode::FAILURE;
            }

            let _ = omawarden_engine::daemon::ensure_daemon_running();
            let keypair = match generate_keypair(algorithm.into(), comment.as_deref()) {
                Ok(k) => k,
                Err(e) => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&json!({ "ok": false, "error": e })).unwrap()
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
            if let Some(dest_dir) = out_dir.as_ref().filter(|_| receipt["outcome"] == "saved") {
                match write_keypair_files(
                    dest_dir,
                    SshAlgorithm::from(algorithm).default_filename_prefix(),
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
                        omawarden_engine::log_warn!(
                            "omawarden:ssh",
                            "Failed to write exported files to {:?}: {}",
                            dest_dir,
                            e
                        );
                    }
                }
            }

            if out_dir.is_some() && files_json.is_null() {
                receipt["warning"] =
                    json!("No key files were exported. Sync the vault, then use ssh-key export.");
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
            if let Err(e) = omawarden_engine::capabilities::check_feature_gating(
                &cfg.server_url,
                "ssh-key-vault-item",
                ignore_server_capabilities,
            ) {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({ "ok": false, "error": e })).unwrap()
                );
                return ExitCode::FAILURE;
            }

            let _ = omawarden_engine::daemon::ensure_daemon_running();
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
                        serde_json::to_string_pretty(&json!({ "ok": false, "error": e })).unwrap()
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
            let _ = omawarden_engine::daemon::ensure_daemon_running();
            let st = send_daemon_request(&json!({ "action": "status" }));
            let is_unlocked = st
                .as_ref()
                .and_then(|v| v.get("is_unlocked"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);

            let item: Option<omawarden_engine::vault::VaultItem> = if is_unlocked {
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
                        let items = omawarden_engine::api::decrypt_sync_ciphers_with_context(
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
                                    || i.name.to_lowercase().contains(&query.to_lowercase()))
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
            let pub_filename = public_key_file.unwrap_or_else(|| format!("{}.pub", priv_filename));

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

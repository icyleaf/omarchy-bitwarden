use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::{Engine, BASE64};

use super::protocol::{get_socket_path, CURRENT_PROTOCOL_VERSION};
use super::server::{get_peer_pid, verify_peer_credentials};
use super::state::{should_touch_activity, DaemonState};

pub fn handle_client(stream: UnixStream, state: Arc<DaemonState>) -> std::io::Result<()> {
    let peer_pid = get_peer_pid(&stream).ok();
    handle_client_with_peer(stream, state, peer_pid)
}

pub fn handle_client_with_peer(
    mut stream: UnixStream,
    state: Arc<DaemonState>,
    peer_pid: Option<u32>,
) -> std::io::Result<()> {
    if let Err(e) = verify_peer_credentials(&stream) {
        crate::log_error!(
            "omawarden:daemon",
            "Client connection rejected: peer credential check failed: {}",
            e
        );
        let err = json!({ "ok": false, "error": "Access denied: client UID mismatch" });
        let _ = writeln!(stream, "{}", err);
        return Ok(());
    }

    let mut reader = BufReader::new(stream.try_clone()?);
    let mut line = zeroize::Zeroizing::new(String::new());
    reader.read_line(&mut line)?;

    if line.trim().is_empty() {
        return Ok(());
    }

    let req: Value = match serde_json::from_str(&line) {
        Ok(v) => v,
        Err(_) => {
            let err = json!({ "ok": false, "error": "Malformed JSON request" });
            let _ = writeln!(stream, "{}", err);
            return Ok(());
        }
    };

    drop(line);
    let action = req.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action == "prepare_account_login" {
        return crate::account_activation::serve(&state, &mut stream, &mut reader, &req);
    }
    drop(reader);
    if action == "output_generation" {
        return writeln!(stream, "{}", json!(state.vault_mgr.output_session()));
    }
    let session = state.vault_mgr.cache_session().ok();
    let is_unlocked = session.is_some_and(|s| s.unlocked);

    let reads_plaintext = matches!(
        action,
        "list" | "search" | "get_item" | "get_ssh_key" | "get_attachment_key"
    ) || (action == "totp"
        && (req.get("query").is_some() || req.get("id").is_some()));
    let is_privileged = reads_plaintext
        || matches!(
            action,
            "ssh_key_create"
                | "ssh_key_create_v2"
                | "cipher_create"
                | "cipher_update"
                | "cipher_delete"
                | "cipher_resolve"
                | "sync"
        )
        || ((action == "stop" || action == "set_auto_lock") && is_unlocked);

    if is_privileged && !is_unlocked {
        if action == "ssh_key_create_v2" || action == "cipher_create" {
            writeln!(
                stream,
                "{}",
                json!({
                    "ok": false,
                    "outcome": "rejected",
                    "error": "Unlock the vault before creating a cipher.",
                    "protocol_version": CURRENT_PROTOCOL_VERSION
                })
            )?;
            return Ok(());
        }
        if action == "cipher_update" {
            writeln!(
                stream,
                "{}",
                json!({
                    "ok": false,
                    "outcome": "rejected",
                    "error": "Unlock the vault before editing a cipher.",
                    "protocol_version": CURRENT_PROTOCOL_VERSION
                })
            )?;
            return Ok(());
        }
        if action == "cipher_delete" {
            writeln!(
                stream,
                "{}",
                json!({
                    "ok": false,
                    "outcome": "rejected",
                    "error": "Unlock the vault before deleting a cipher.",
                    "protocol_version": CURRENT_PROTOCOL_VERSION
                })
            )?;
            return Ok(());
        }
        if action == "cipher_resolve" {
            let verb = match req.get("purpose").and_then(Value::as_str) {
                Some("edit") | Some("editing") => "editing",
                _ => "deleting",
            };
            writeln!(
                stream,
                "{}",
                json!({
                    "ok": false,
                    "outcome": "rejected",
                    "error": format!("Unlock the vault before {verb} a cipher."),
                    "protocol_version": CURRENT_PROTOCOL_VERSION
                })
            )?;
            return Ok(());
        }
        let _ = writeln!(
            stream,
            "{}",
            json!({
                "ok": false,
                "error": "Vault is locked. Please unlock the vault first.",
                "protocol_version": CURRENT_PROTOCOL_VERSION
            })
        );
        return Ok(());
    }
    if action == "get_attachment_key"
        && req
            .get("expected_lock_generation")
            .is_some_and(|expected| session.is_none_or(|s| expected.as_u64() != Some(s.generation)))
    {
        return writeln!(
            stream,
            "{}",
            json!({
                "ok": false,
                "error": "Vault session changed.",
                "protocol_version": CURRENT_PROTOCOL_VERSION
            })
        );
    }

    if should_touch_activity(action, &req) {
        state.touch_activity();
    }

    let client_context: Option<crate::api::ClientContext> = req
        .get("client")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .filter(|c: &crate::api::ClientContext| c.is_valid());

    let mut response = match action {
        "ping" => json!({
            "ok": true,
            "pong": true,
            "protocol_version": CURRENT_PROTOCOL_VERSION,
            "ssh_write_receipt": true,
            "account_activation_v1": true,
            "unlock_context": state.vault_mgr.unlock_context(),
            "version": env!("CARGO_PKG_VERSION"),
            "commit": env!("GIT_HASH"),
            "unlocked": is_unlocked,
            "quick_unlock": state.quick_unlock_ready(),
            // The daemon's cached setting, so `auth quick-unlock-check` can
            // report enabled/available from one source instead of the CLI
            // re-reading config.json (two sources that can disagree).
            "quick_unlock_enabled": state.quick_unlock_enabled(),
            // False means mlock failed at least once: the retained key sits
            // in unlocked memory (degraded, must be discoverable).
            "memory_locked": !crate::locked::mlock_fallback_active(),
        }),
        "stop" => {
            // Dual-tier authorization boundaries (ADR-0028):
            // 1. Host-Guarded In-Process Boundary:
            //    When hosted in-process inside an external application (e.g. GUI shell),
            //    daemon lifecycle is owned exclusively by that host process. External callers
            //    (detected via kernel SO_PEERCRED PID != current PID) are strictly rejected,
            //    even if `admin: true` is supplied.
            // 2. Standalone Same-UID Explicit-Intent Boundary:
            //    Standalone daemons serve all clients operating under the user's desktop UID.
            //    Normal cooperative clients (sync, search, totp) must not terminate the daemon.
            //    External callers must supply explicit administrative intent (`admin: true`),
            //    which is satisfied by the dedicated administrative CLI (`omawarden daemon stop`).
            // 3. Fail-Closed:
            //    If peer_pid is None (kernel error or unsupported platform), external callers
            //    fail closed (in-process denies all; standalone requires admin: true).
            let is_same_process = peer_pid.is_some_and(|pid| pid == std::process::id());
            let is_admin = req.get("admin").and_then(Value::as_bool).unwrap_or(false);

            if state.is_in_process() && !is_same_process {
                crate::log_warn!(
                    "omawarden:daemon",
                    "Rejected stop request from external PID {:?}: daemon is hosted in-process",
                    peer_pid
                );
                let _ = writeln!(
                    stream,
                    "{}",
                    json!({
                        "ok": false,
                        "error": "Access denied: cannot terminate in-process daemon hosted by an external application",
                        "protocol_version": CURRENT_PROTOCOL_VERSION
                    })
                );
                return Ok(());
            }

            if !is_same_process && !is_admin {
                crate::log_warn!(
                    "omawarden:daemon",
                    "Rejected unauthorized stop request from external PID {:?}: missing admin: true",
                    peer_pid
                );
                let _ = writeln!(
                    stream,
                    "{}",
                    json!({
                        "ok": false,
                        "error": "Access denied: stopping the daemon requires explicit administrative authorization (admin: true)",
                        "protocol_version": CURRENT_PROTOCOL_VERSION
                    })
                );
                return Ok(());
            }

            state.lock();
            crate::ssh_agent::stop(&state);
            let sock_path = state
                .socket_path
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
                .unwrap_or_else(get_socket_path);
            let _ = fs::remove_file(&sock_path);
            let _ = writeln!(
                stream,
                "{}",
                json!({ "ok": true, "protocol_version": CURRENT_PROTOCOL_VERSION })
            );
            let _ = stream.flush();
            state.shutdown.trigger();
            return Ok(());
        }
        "status" => state.vault_mgr.get_status(),
        // SSH agent confirmations: the overlay lists pending prompts and answers them.
        "ssh_agent_apply" => match crate::ssh_agent::apply(&state) {
            Ok(_) => json!({ "ok": true, "running": crate::ssh_agent::is_running(&state) }),
            Err(e) => json!({ "ok": false, "error": format!("SSH agent: {e}") }),
        },
        "ssh_agent_status" => json!({
            "ok": true,
            "running": crate::ssh_agent::is_running(&state),
            "socket": crate::ssh_agent::socket_path(),
        }),
        "ssh_agent_pending" => json!({ "ok": true, "prompts": state.ssh_agent.pending() }),
        "ssh_agent_reply" => {
            let id = req.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
            let decision = crate::ssh_agent::Decision {
                approve: req
                    .get("approve")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
            };
            json!({ "ok": true, "delivered": state.ssh_agent.reply(id, decision) })
        }
        "unlock" => {
            let pwd = req.get("password").and_then(|v| v.as_str()).unwrap_or("");
            let result = match (
                req.get("expected_unlock_context"),
                req.get("expected_credential_id"),
            ) {
                (Some(Value::String(context)), Some(Value::String(id))) => {
                    state.unlock_in_context(pwd, context, Some(id))
                }
                (Some(Value::String(context)), None) => state.unlock_in_context(pwd, context, None),
                (None, None) => state.unlock(pwd),
                _ => Err("Invalid unlock context".into()),
            };
            match result {
                Ok(count) => json!({
                    "ok": true,
                    "status": "unlocked",
                    "items_count": count,
                }),
                Err(e) => json!({ "ok": false, "status": "locked", "error": e }),
            }
        }
        // ADR-0025: system-authentication re-unlock from the retained key.
        "quick_unlock" => match state.perform_quick_unlock() {
            Ok(count) => json!({
                "ok": true,
                "status": "unlocked",
                "items_count": count,
            }),
            Err(reason) => json!({ "ok": false, "status": "locked", "error": reason }),
        },
        // Config side-effect: drop the retained key without locking.
        "wipe_quick_unlock" => {
            state.vault_mgr.wipe_quick_unlock();
            json!({ "ok": true })
        }
        // Refresh the daemon's cached quick_unlock setting; sent by
        // `config set --quick-unlock` after the config file is persisted so
        // the hot paths never re-read config.json (see
        // DaemonState::quick_unlock_setting).
        "set_quick_unlock" => {
            let enabled = req
                .get("enabled")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            state.set_quick_unlock_enabled(enabled);
            // The daemon owns every other wipe trigger (strikes, suspend,
            // session ceiling, logout); disabling the setting is one more, so
            // it happens here rather than depending on the caller to send a
            // separate wipe request.
            if !enabled {
                state.vault_mgr.wipe_quick_unlock();
            }
            json!({ "ok": true, "quick_unlock_enabled": enabled })
        }
        "lock" => {
            let outputs_cleared = state.lock();
            json!({ "ok": true, "status": "locked", "outputs_cleared": outputs_cleared })
        }
        "sync" => match state.sync_with_client(client_context.as_ref()) {
            Ok(count) => json!({ "ok": true, "ciphers_count": count }),
            Err(e) => json!({ "ok": false, "error": e }),
        },
        "list" => json!(state.vault_mgr.get_items()),
        "search" => {
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let category = req.get("category").and_then(|v| v.as_str());
            json!(state.vault_mgr.search_items(query, category))
        }
        // A legacy CLI may repeat the POST locally on any non-success reply.
        // Never dispatch a remote write for the legacy request.
        "ssh_key_create" => {
            json!({"ok":false, "outcome":"rejected", "error":"Update the CLI to create SSH keys safely."})
        }
        "ssh_key_create_v2" => match state.vault_mgr.write_ssh_key(req, client_context.as_ref()) {
            Ok(receipt) => receipt,
            Err(error) => error.response(),
        },
        "cipher_create" => match state.vault_mgr.create_cipher(req, client_context.as_ref()) {
            Ok(receipt) => receipt,
            Err(error) => error.response(),
        },
        "cipher_update" => match state.vault_mgr.update_cipher(req, client_context.as_ref()) {
            Ok(receipt) => receipt,
            Err(error) => error.response(),
        },
        "cipher_delete" => match state.vault_mgr.delete_cipher(req, client_context.as_ref()) {
            Ok(receipt) => receipt,
            Err(error) => error.response(),
        },
        "cipher_resolve" => {
            let target = req.get("target").and_then(|v| v.as_str()).unwrap_or("");
            match state.vault_mgr.resolve_cipher_target_candidates(target) {
                Ok(crate::vault::CipherTargetResolution::Exact(item)) => json!({
                    "ok": true,
                    "item": {
                        "id": item.id,
                        "name": item.name,
                        "type": item.type_name,
                        "organization_id": item.organization_id,
                    }
                }),
                Ok(crate::vault::CipherTargetResolution::Ambiguous(candidates)) => {
                    let candidate_items: Vec<Value> = candidates
                        .into_iter()
                        .map(|item| {
                            json!({
                                "id": item.id,
                                "name": item.name,
                                "type": item.type_name,
                                "sub_title": item.sub_title,
                                "organization_id": item.organization_id,
                            })
                        })
                        .collect();
                    let ids: Vec<&str> = candidate_items
                        .iter()
                        .filter_map(|c| c["id"].as_str())
                        .collect();
                    json!({
                        "ok": false,
                        "ambiguous": true,
                        "candidates": candidate_items,
                        "error": format!(
                            "Multiple ciphers matched '{}': [{}]. Specify by ID or narrower name.",
                            target,
                            ids.join(", ")
                        ),
                    })
                }
                Ok(crate::vault::CipherTargetResolution::NotFound(err)) => {
                    json!({ "ok": false, "error": err })
                }
                Err(err) => json!({ "ok": false, "error": err }),
            }
        }
        "get_item" => {
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let category = req.get("category").and_then(|v| v.as_str());
            if let Some(item) = state.vault_mgr.find_item(query, category) {
                json!({ "ok": true, "item": item, "lock_generation": session.map(|s| s.generation) })
            } else {
                json!({ "ok": false, "error": format!("Item '{}' not found in vault", query) })
            }
        }
        "get_ssh_key" => {
            let query = req.get("query").and_then(|v| v.as_str()).unwrap_or("");
            if let Some(item) = state.vault_mgr.find_ssh_key(query) {
                json!({ "ok": true, "item": item })
            } else {
                json!({ "ok": false, "error": format!("SSH key item '{}' not found", query) })
            }
        }
        "get_attachment_key" => {
            let item_id = req.get("item_id").and_then(|v| v.as_str()).unwrap_or("");
            let attachment_id = req
                .get("attachment_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if let Some(key) = state
                .vault_mgr
                .resolve_attachment_key(item_id, attachment_id)
            {
                let mut raw = Vec::new();
                raw.extend_from_slice(&key.enc_key);
                if let Some(mac_k) = key.mac_key {
                    raw.extend_from_slice(&mac_k);
                }
                json!({
                    "ok": true,
                    "key_b64": BASE64.encode(&raw)
                })
            } else {
                json!({ "ok": false, "error": "Unable to resolve attachment key (vault locked or missing item)" })
            }
        }
        "totp" => {
            let secret = req.get("secret").and_then(|v| v.as_str());
            let query = req
                .get("query")
                .or_else(|| req.get("id"))
                .and_then(|v| v.as_str());

            if let Some(q) = query {
                if let Some(item) = state.vault_mgr.find_item(q, None) {
                    let totp_seed = item
                        .login
                        .as_ref()
                        .and_then(|l| l.get("totp"))
                        .and_then(|v| v.as_str());
                    if let Some(seed) = totp_seed {
                        if let Some(res) = crate::totp::generate_totp(seed, None, 6, 30) {
                            json!({
                                "ok": true,
                                "code": res.code,
                                "ttl": res.ttl,
                                "period": res.period,
                                "lock_generation": session.map(|s| s.generation),
                                "id": item.id,
                                "name": item.name
                            })
                        } else {
                            json!({ "ok": false, "error": "Item has invalid TOTP configuration" })
                        }
                    } else {
                        json!({ "ok": false, "error": format!("Item '{}' has no TOTP configured", item.name) })
                    }
                } else {
                    json!({ "ok": false, "error": format!("Item '{}' not found in vault", q) })
                }
            } else if let Some(sec) = secret {
                if let Some(res) = crate::totp::generate_totp(sec, None, 6, 30) {
                    json!({ "ok": true, "code": res.code, "ttl": res.ttl, "period": res.period })
                } else {
                    json!({ "ok": false, "error": "Invalid TOTP secret" })
                }
            } else {
                json!({ "ok": false, "error": "Missing TOTP secret or item query" })
            }
        }
        "copy" => {
            let text = req.get("text").and_then(|v| v.as_str()).unwrap_or("");
            let sensitive = req
                .get("sensitive")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let timeout = req.get("timeout").and_then(|v| v.as_i64()).unwrap_or(30);
            let clip_mgr = crate::clipboard::ClipboardManager::default();
            if clip_mgr.copy(text, sensitive, timeout) {
                json!({ "ok": true })
            } else {
                json!({ "ok": false, "error": "Failed to copy to clipboard" })
            }
        }
        "generate_password" => {
            let is_passphrase = req
                .get("passphrase")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if is_passphrase {
                let options = crate::generator::PassphraseOptions {
                    words: req
                        .get("words")
                        .and_then(|v| v.as_u64())
                        .map(|w| w as usize)
                        .unwrap_or(crate::generator::DEFAULT_PASSPHRASE_WORDS),
                    separator: req
                        .get("separator")
                        .and_then(|v| v.as_str())
                        .unwrap_or("-")
                        .to_string(),
                    capitalize: req
                        .get("capitalize")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                };
                match crate::generator::generate_passphrase(&options) {
                    Ok(secret) => json!({
                        "ok": true,
                        "password": secret.value,
                        "entropy": secret.entropy,
                        "type": secret.secret_type,
                    }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            } else {
                let options = crate::generator::PasswordOptions {
                    length: req
                        .get("length")
                        .and_then(|v| v.as_u64())
                        .map(|l| l as usize)
                        .unwrap_or(crate::generator::DEFAULT_PASSWORD_LENGTH),
                    uppercase: req
                        .get("uppercase")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    lowercase: req
                        .get("lowercase")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    numbers: req.get("numbers").and_then(|v| v.as_bool()).unwrap_or(true),
                    special: req.get("special").and_then(|v| v.as_bool()).unwrap_or(true),
                    avoid_ambiguous: req
                        .get("avoid_ambiguous")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    min_numbers: req
                        .get("min_numbers")
                        .and_then(|v| v.as_u64())
                        .map(|n| n as usize)
                        .unwrap_or(1),
                    min_special: req
                        .get("min_special")
                        .and_then(|v| v.as_u64())
                        .map(|s| s as usize)
                        .unwrap_or(1),
                };
                match crate::generator::generate_password(&options) {
                    Ok(secret) => json!({
                        "ok": true,
                        "password": secret.value,
                        "entropy": secret.entropy,
                        "type": secret.secret_type,
                    }),
                    Err(e) => json!({ "ok": false, "error": e }),
                }
            }
        }
        "set_auto_lock" => {
            if let Some(secs) = req.get("auto_lock_seconds").and_then(|v| v.as_u64()) {
                state.set_auto_lock_duration(Duration::from_secs(secs));
                json!({ "ok": true, "auto_lock_seconds": secs })
            } else {
                let mins = req
                    .get("auto_lock")
                    .or_else(|| req.get("auto_lock_minutes"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(15);
                state.set_auto_lock_minutes(mins);
                json!({ "ok": true, "auto_lock_minutes": mins })
            }
        }
        other => json!({ "ok": false, "error": format!("Unknown action: {}", other) }),
    };

    if let Value::Object(ref mut map) = response {
        map.entry("protocol_version".to_string())
            .or_insert_with(|| json!(CURRENT_PROTOCOL_VERSION));
    }

    if reads_plaintext
        && state.vault_mgr.cache_session().ok().is_none_or(|now| {
            !now.unlocked || session.is_none_or(|then| now.generation != then.generation)
        })
    {
        let _ = writeln!(
            stream,
            "{}",
            json!({
                "ok": false,
                "error": "Vault session changed.",
                "protocol_version": CURRENT_PROTOCOL_VERSION
            })
        );
    } else {
        let _ = writeln!(stream, "{}", response);
    }
    Ok(())
}

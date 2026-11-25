//! End-to-end CLI ↔ Daemon IPC integration tests for `omawarden vault get`
//! and `ping.capabilities` (Daemon Capabilities) gating (#446, #447, #448, #449).

use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::os::unix::{
    fs::PermissionsExt,
    net::{UnixListener, UnixStream},
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

struct DaemonGuard(Child);
impl Drop for DaemonGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ipc(socket: &Path, request: Value) -> Value {
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut stream = loop {
        match UnixStream::connect(socket) {
            Ok(s) => break s,
            Err(e)
                if e.kind() == ErrorKind::ConnectionRefused || e.kind() == ErrorKind::NotFound =>
            {
                assert!(
                    Instant::now() < deadline,
                    "daemon socket not ready after 5s"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(e) => panic!("ipc connect failed: {e}"),
        }
    };
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    writeln!(stream, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

struct TestVaultEnv {
    temp: tempfile::TempDir,
    socket: PathBuf,
    _daemon: DaemonGuard,
}

impl TestVaultEnv {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();

        let keyring = dir.join("secret-tool");
        fs::write(
            &keyring,
            "#!/bin/sh\ncase \"$*\" in\nlookup*'kind access_token'*) echo fixture-token;;\n*) exit 1;;\nesac\n",
        )
        .unwrap();
        fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();

        let email = "user@fixture.invalid";
        let master_password = "fixture-master-password";
        let master = derive_master_key(
            email,
            master_password,
            KdfType::Pbkdf2Sha256,
            100_000,
            None,
            None,
        )
        .unwrap();
        let raw_user_key = [42u8; 64];
        let user_key = SymmetricCryptoKey::from_raw_bytes(&raw_user_key).unwrap();
        let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
            .encrypt(&raw_user_key)
            .unwrap();

        let enc = |s: &str| user_key.encrypt_string(s).unwrap();

        let folder_id = "folder-work-0001";
        let folders = vec![json!({
            "id": folder_id,
            "name": enc("Work")
        })];

        let ciphers = vec![
            // 1. Login cipher
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "organizationId": null,
                "folderId": folder_id,
                "type": 1,
                "name": enc("GitHub Production"),
                "notes": enc("Login operational notes"),
                "favorite": true,
                "creationDate": "2026-01-01T00:00:00Z",
                "revisionDate": "2026-02-01T00:00:00Z",
                "deletedDate": null,
                "login": {
                    "username": enc("octocat"),
                    "password": enc("super-secret-login-pw"),
                    "totp": enc("JBSWY3DPEHPK3PXP"),
                    "uris": [
                        { "uri": enc("https://github.com/login"), "match": 0 },
                        { "uri": enc("https://api.github.com"), "match": 1 }
                    ]
                },
                "fields": [
                    { "name": enc("Environment"), "value": enc("production"), "type": 0 },
                    { "name": enc("API Secret"), "value": enc("hidden-api-token-999"), "type": 1 },
                    { "name": enc("password"), "value": enc("custom-password-field-value"), "type": 0 }
                ]
            }),
            // 2. Secure Note cipher
            json!({
                "id": "22222222-2222-2222-2222-222222222222",
                "organizationId": null,
                "folderId": null,
                "type": 2,
                "name": enc("Recovery Codes"),
                "notes": enc("recovery-code-alpha-beta"),
                "favorite": false,
                "creationDate": "2026-01-02T00:00:00Z",
                "revisionDate": "2026-02-02T00:00:00Z",
                "deletedDate": null,
                "secureNote": { "type": 0 },
                "fields": []
            }),
            // 3. Card cipher
            json!({
                "id": "33333333-3333-3333-3333-333333333333",
                "organizationId": null,
                "folderId": null,
                "type": 3,
                "name": enc("Corporate Visa"),
                "notes": enc("Card billing note"),
                "favorite": false,
                "creationDate": "2026-01-03T00:00:00Z",
                "revisionDate": "2026-02-03T00:00:00Z",
                "deletedDate": null,
                "card": {
                    "cardholderName": enc("Alice Example"),
                    "brand": enc("Visa"),
                    "number": enc("4111222233334444"),
                    "expMonth": enc("12"),
                    "expYear": enc("2030"),
                    "code": enc("987")
                },
                "fields": []
            }),
            // 4. Identity cipher
            json!({
                "id": "44444444-4444-4444-4444-444444444444",
                "organizationId": null,
                "folderId": null,
                "type": 4,
                "name": enc("Alice Identity"),
                "notes": enc("Identity note"),
                "favorite": false,
                "creationDate": "2026-01-04T00:00:00Z",
                "revisionDate": "2026-02-04T00:00:00Z",
                "deletedDate": null,
                "identity": {
                    "title": enc("Dr"),
                    "firstName": enc("Alice"),
                    "middleName": enc("Marie"),
                    "lastName": enc("Example"),
                    "address1": enc("123 Main St"),
                    "address2": enc("Suite 400"),
                    "address3": enc("Floor 4"),
                    "city": enc("Tokyo"),
                    "state": enc("Tokyo"),
                    "postalCode": enc("100-0001"),
                    "country": enc("JP"),
                    "company": enc("Omarchy Corp"),
                    "email": enc("alice@example.com"),
                    "phone": enc("+81-3-0000-0000"),
                    "ssn": enc("123-45-6789"),
                    "username": enc("alice_id"),
                    "passportNumber": enc("P12345678"),
                    "licenseNumber": enc("DL-987654")
                },
                "fields": []
            }),
            // 5. SSH Key cipher (private key ends with \n)
            json!({
                "id": "55555555-5555-5555-5555-555555555555",
                "organizationId": null,
                "folderId": null,
                "type": 5,
                "name": enc("Prod Bastion Key"),
                "notes": enc("Bastion SSH note"),
                "favorite": false,
                "creationDate": "2026-01-05T00:00:00Z",
                "revisionDate": "2026-02-05T00:00:00Z",
                "deletedDate": null,
                "sshKey": {
                    "privateKey": enc("-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA-FAKE-KEY-BODY\n-----END OPENSSH PRIVATE KEY-----\n"),
                    "publicKey": enc("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKey alice@bastion"),
                    "keyFingerprint": enc("SHA256:FakeFingerprint123456")
                },
                "fields": [
                    { "name": enc("Passphrase"), "value": enc("ssh-passphrase-secret"), "type": 1 }
                ]
            }),
            // 6 & 7. Ambiguous same-name ciphers with different types
            json!({
                "id": "66666666-6666-6666-6666-666666666666",
                "organizationId": null,
                "folderId": null,
                "type": 1,
                "name": enc("Shared Name"),
                "notes": null,
                "favorite": false,
                "deletedDate": null,
                "login": {
                    "username": enc("shared_user"),
                    "password": enc("shared_pass"),
                    "uris": []
                },
                "fields": []
            }),
            json!({
                "id": "77777777-7777-7777-7777-777777777777",
                "organizationId": null,
                "folderId": null,
                "type": 2,
                "name": enc("Shared Name"),
                "notes": enc("shared note secret"),
                "favorite": false,
                "deletedDate": null,
                "secureNote": { "type": 0 },
                "fields": []
            }),
            // 8. Trashed cipher
            json!({
                "id": "88888888-8888-8888-8888-888888888888",
                "organizationId": null,
                "folderId": null,
                "type": 1,
                "name": enc("Archived Login"),
                "notes": null,
                "favorite": false,
                "deletedDate": "2026-02-10T00:00:00Z",
                "login": {
                    "username": enc("old_user"),
                    "password": enc("old_pass"),
                    "uris": []
                },
                "fields": []
            }),
        ];

        let data = json!({
            "user_id": "user-id-123",
            "user_email": email,
            "server_url": "http://127.0.0.1:1",
            "credential_id": "11111111111111111111111111111111",
            "enc_user_key": wrap,
            "kdf": 0,
            "kdf_iterations": 100_000,
            "folders": folders,
            "ciphers": ciphers
        });
        fs::write(dir.join("data.json"), data.to_string()).unwrap();

        let socket = dir.join("omawarden.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_omawarden"))
            .arg("daemon")
            .env_clear()
            .env("HOME", dir)
            .env("PATH", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMA_KEYRING_PROVIDER", "secret-tool")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let daemon = DaemonGuard(child);

        let unlock_res = ipc(
            &socket,
            json!({ "action": "unlock", "password": master_password }),
        );
        assert_eq!(unlock_res["ok"], true, "unlock failed: {unlock_res}");

        Self {
            temp,
            socket,
            _daemon: daemon,
        }
    }

    fn cli(&self, args: &[&str]) -> std::process::Output {
        let dir = self.temp.path();
        Command::new(env!("CARGO_BIN_EXE_omawarden"))
            .args(args)
            .env_clear()
            .env("HOME", dir)
            .env("PATH", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMA_KEYRING_PROVIDER", "secret-tool")
            .output()
            .unwrap()
    }
}

#[test]
fn vault_get_summary_card_and_json_envelope() {
    let env = TestVaultEnv::new();

    // Verify ping advertises capabilities including vault_get and Schema v3 capabilities
    let ping = ipc(&env.socket, json!({ "action": "ping" }));
    assert_eq!(ping["ok"], true);
    assert_eq!(ping["schema_version"], 3);
    let caps: Vec<&str> = ping["capabilities"]
        .as_array()
        .expect("ping.capabilities should be an array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(caps.contains(&"cipher_mutation_v3"));
    assert!(caps.contains(&"folder_crud"));
    assert!(caps.contains(&"login_totp_uri_match"));
    assert!(caps.contains(&"vault_get"));

    // Default text mode renders summary card on stdout
    let out = env.cli(&["vault", "get", "GitHub Production"]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("GitHub Production"));
    assert!(stdout.contains("octocat"));
    assert!(stdout.contains("super-secret-login-pw"));

    // --json returns unified { "ok": true, "item": <VaultItem> } envelope
    let json_out = env.cli(&["vault", "get", "GitHub Production", "--json"]);
    assert!(
        json_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let parsed: Value = serde_json::from_slice(&json_out.stdout).unwrap();
    assert_eq!(parsed["ok"], true);
    assert_eq!(parsed["item"]["id"], "11111111-1111-1111-1111-111111111111");
    assert_eq!(parsed["item"]["name"], "GitHub Production");
    assert_eq!(parsed["item"]["type_name"], "login");

    // --copy and -n / --no-newline must not exist
    let copy_flag = env.cli(&["vault", "get", "GitHub Production", "--copy"]);
    assert!(!copy_flag.status.success());
    let no_nl = env.cli(&["vault", "get", "GitHub Production", "--no-newline"]);
    assert!(!no_nl.status.success());
}

#[test]
fn vault_get_ambiguity_type_filter_and_trash_hints() {
    let env = TestVaultEnv::new();

    // Ambiguous name in --json returns candidates array and exits 1
    let amb_json = env.cli(&["vault", "get", "Shared Name", "--json"]);
    assert!(!amb_json.status.success());
    let parsed: Value = serde_json::from_slice(&amb_json.stdout).unwrap();
    assert_eq!(parsed["ok"], false);
    let candidates = parsed["candidates"]
        .as_array()
        .expect("expected candidates array");
    assert_eq!(candidates.len(), 2);

    // Ambiguous name in text mode prints candidates to stderr and exits 1
    let amb_txt = env.cli(&["vault", "get", "Shared Name"]);
    assert!(!amb_txt.status.success());
    assert!(amb_txt.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&amb_txt.stderr);
    assert!(stderr.contains("66666666-6666-6666-6666-666666666666"));
    assert!(stderr.contains("77777777-7777-7777-7777-777777777777"));

    // --type narrows the collision
    let narrow = env.cli(&["vault", "get", "Shared Name", "--type", "note", "--json"]);
    assert!(
        narrow.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&narrow.stderr)
    );
    let narrow_val: Value = serde_json::from_slice(&narrow.stdout).unwrap();
    assert_eq!(
        narrow_val["item"]["id"],
        "77777777-7777-7777-7777-777777777777"
    );

    // Active lookup for trashed item gives cross-state --trash hint
    let trashed_miss = env.cli(&["vault", "get", "Archived Login"]);
    assert!(!trashed_miss.status.success());
    let miss_stderr = String::from_utf8_lossy(&trashed_miss.stderr);
    assert!(
        miss_stderr.contains("--trash"),
        "expected --trash hint, got: {miss_stderr}"
    );

    // --trash retrieves the trashed item
    let trashed_hit = env.cli(&["vault", "get", "Archived Login", "--trash", "--json"]);
    assert!(
        trashed_hit.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&trashed_hit.stderr)
    );
    let hit_val: Value = serde_json::from_slice(&trashed_hit.stdout).unwrap();
    assert_eq!(
        hit_val["item"]["id"],
        "88888888-8888-8888-8888-888888888888"
    );

    // --trash for an active item gives cross-state active hint
    let active_in_trash = env.cli(&["vault", "get", "GitHub Production", "--trash"]);
    assert!(!active_in_trash.status.success());
    let active_stderr = String::from_utf8_lossy(&active_in_trash.stderr);
    assert!(
        active_stderr.to_lowercase().contains("not in the trash"),
        "expected not-in-trash hint, got: {active_stderr}"
    );
}

#[test]
fn vault_get_in_process_daemon_without_capability_fails_closed() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let sock_path = dir.join("omawarden.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();
    fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600)).unwrap();

    let saw_vault_get = Arc::new(AtomicBool::new(false));
    let saw_get_item = Arc::new(AtomicBool::new(false));
    let done = Arc::new(AtomicBool::new(false));

    let saw_vg = saw_vault_get.clone();
    let saw_gi = saw_get_item.clone();
    let done_flag = done.clone();
    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !done_flag.load(Ordering::Relaxed) && Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut line = String::new();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        continue;
                    }
                    let req: Value = serde_json::from_str(&line).unwrap_or_default();
                    let action = req["action"].as_str().unwrap_or("");
                    let reply = match action {
                        "ping" => json!({
                            "ok": true,
                            "pong": true,
                            "protocol_version": 1,
                            "schema_version": 3,
                            "unlocked": true
                        }),
                        "stop" => json!({
                            "ok": false,
                            "error": "Access denied: cannot terminate in-process daemon hosted by an external application",
                            "protocol_version": 1
                        }),
                        "vault_get" => {
                            saw_vg.store(true, Ordering::Relaxed);
                            json!({ "ok": false, "error": "Unknown action" })
                        }
                        "get_item" => {
                            saw_gi.store(true, Ordering::Relaxed);
                            json!({ "ok": false, "error": "should never fall back" })
                        }
                        _ => json!({ "ok": false, "error": "unexpected" }),
                    };
                    let _ = writeln!(stream, "{reply}");
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["vault", "get", "GitHub Production", "--json"])
        .env("XDG_RUNTIME_DIR", dir)
        .env("XDG_DATA_HOME", dir)
        .env("XDG_CONFIG_HOME", dir)
        .output()
        .unwrap();

    done.store(true, Ordering::Relaxed);
    let _ = server.join();

    assert!(!out.status.success());
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["ok"], false);
    let err = parsed["error"].as_str().unwrap_or("");
    assert!(
        err.contains("vault_get"),
        "expected error naming missing capability 'vault_get', got: {err}"
    );
    assert!(
        !saw_vault_get.load(Ordering::Relaxed),
        "must not send vault_get to incapable daemon"
    );
    assert!(
        !saw_get_item.load(Ordering::Relaxed),
        "must not silently fall back to get_item"
    );
}

#[test]
fn vault_get_missing_capability_auto_restarts_standalone_daemon() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let sock_path = dir.join("omawarden.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();
    fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600)).unwrap();

    // Seed minimal data.json so the restarted real daemon starts cleanly
    let data = json!({
        "user_id": "user-id-123",
        "user_email": "user@fixture.invalid",
        "server_url": "http://127.0.0.1:1",
        "ciphers": []
    });
    fs::write(dir.join("data.json"), data.to_string()).unwrap();

    let saw_stop_admin = Arc::new(AtomicBool::new(false));
    let saw_stop_flag = saw_stop_admin.clone();
    let sock_for_thread = sock_path.clone();

    let server = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut line = String::new();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        continue;
                    }
                    let req: Value = serde_json::from_str(&line).unwrap_or_default();
                    let action = req["action"].as_str().unwrap_or("");
                    match action {
                        "ping" => {
                            let _ = writeln!(
                                stream,
                                "{}",
                                json!({
                                    "ok": true,
                                    "pong": true,
                                    "protocol_version": 1,
                                    "schema_version": 3,
                                    "unlocked": true
                                })
                            );
                        }
                        "stop" => {
                            if req["admin"] == true {
                                saw_stop_flag.store(true, Ordering::Relaxed);
                            }
                            let _ = writeln!(
                                stream,
                                "{}",
                                json!({ "ok": true, "protocol_version": 1 })
                            );
                            let _ = fs::remove_file(&sock_for_thread);
                            break;
                        }
                        _ => {
                            let _ = writeln!(stream, "{}", json!({ "ok": false, "error": "old" }));
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    // After auto-restart, the newly spawned real daemon is locked (not incapable!),
    // so vault get should proceed past capability check and report locked vault rather than missing capability.
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(["vault", "get", "Anything", "--json"])
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_KEYRING_PROVIDER", "secret-tool")
        .output()
        .unwrap();

    let _ = server.join();
    // Clean up the newly spawned real daemon
    let _ = ipc(&sock_path, json!({ "action": "stop", "admin": true }));

    assert!(
        saw_stop_admin.load(Ordering::Relaxed),
        "expected CLI to issue stop(admin: true) to stale standalone daemon"
    );
    let parsed: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(parsed["ok"], false);
    let err = parsed["error"].as_str().unwrap_or("").to_lowercase();
    assert!(
        err.contains("lock") || err.contains("unlock"),
        "after auto-restart, expected locked-vault error (proving capability check passed), got: {err}"
    );
}

#[test]
fn vault_get_login_common_shorthand_and_custom_field_selectors() {
    let env = TestVaultEnv::new();

    // Mutually exclusive selector flags fail
    let conflict = env.cli(&[
        "vault",
        "get",
        "GitHub Production",
        "--password",
        "--username",
    ]);
    assert!(!conflict.status.success());
    let conflict2 = env.cli(&[
        "vault",
        "get",
        "GitHub Production",
        "--field",
        "username",
        "--password",
    ]);
    assert!(!conflict2.status.success());

    // Shorthand flags
    let pw = env.cli(&["vault", "get", "GitHub Production", "--password"]);
    assert!(pw.status.success());
    assert_eq!(
        String::from_utf8_lossy(&pw.stdout),
        "super-secret-login-pw\n"
    );

    let user = env.cli(&["vault", "get", "GitHub Production", "--username"]);
    assert!(user.status.success());
    assert_eq!(String::from_utf8_lossy(&user.stdout), "octocat\n");

    let uri = env.cli(&["vault", "get", "GitHub Production", "--uri"]);
    assert!(uri.status.success());
    assert_eq!(
        String::from_utf8_lossy(&uri.stdout),
        "https://github.com/login\n"
    );

    let notes = env.cli(&["vault", "get", "GitHub Production", "--notes"]);
    assert!(notes.status.success());
    assert_eq!(
        String::from_utf8_lossy(&notes.stdout),
        "Login operational notes\n"
    );

    // Live TOTP (text + --json with ttl & period)
    let totp_txt = env.cli(&["vault", "get", "GitHub Production", "--totp"]);
    assert!(totp_txt.status.success());
    let code = String::from_utf8_lossy(&totp_txt.stdout);
    assert_eq!(code.trim().len(), 6);
    assert!(code.ends_with('\n'));

    let totp_json = env.cli(&["vault", "get", "GitHub Production", "-f", "totp", "--json"]);
    assert!(totp_json.status.success());
    let tj: Value = serde_json::from_slice(&totp_json.stdout).unwrap();
    assert_eq!(tj["ok"], true);
    assert_eq!(tj["field"], "totp");
    assert_eq!(tj["sensitive"], true);
    assert_eq!(tj["period"], 30);
    assert!(tj["ttl"].as_u64().is_some());
    assert_eq!(tj["value"].as_str().unwrap().len(), 6);

    // Raw totp_secret
    let secret = env.cli(&["vault", "get", "GitHub Production", "-f", "totp-secret"]);
    assert!(secret.status.success());
    assert_eq!(
        String::from_utf8_lossy(&secret.stdout),
        "JBSWY3DPEHPK3PXP\n"
    );

    // Multi-valued uris (text: one per line; --json: structured { uri, match } array)
    let uris_txt = env.cli(&["vault", "get", "GitHub Production", "-f", "uris"]);
    assert!(uris_txt.status.success());
    assert_eq!(
        String::from_utf8_lossy(&uris_txt.stdout),
        "https://github.com/login\nhttps://api.github.com\n"
    );

    let uris_json = env.cli(&["vault", "get", "GitHub Production", "-f", "uris", "--json"]);
    assert!(uris_json.status.success());
    let uj: Value = serde_json::from_slice(&uris_json.stdout).unwrap();
    assert_eq!(uj["ok"], true);
    assert_eq!(uj["field"], "uris");
    assert_eq!(uj["sensitive"], false);
    assert_eq!(uj["value"].as_array().unwrap().len(), 2);
    assert_eq!(uj["value"][0]["uri"], "https://github.com/login");
    assert_eq!(uj["value"][0]["match"], 0);
    assert_eq!(uj["value"][1]["uri"], "https://api.github.com");
    assert_eq!(uj["value"][1]["match"], 1);

    // Common metadata selectors
    for (sel, expected) in [
        ("id", "11111111-1111-1111-1111-111111111111"),
        ("name", "GitHub Production"),
        ("type", "login"),
        ("folder", "Work"),
        ("folder_id", "folder-work-0001"),
        ("favorite", "true"),
        ("created_at", "2026-01-01T00:00:00Z"),
        ("updated_at", "2026-02-01T00:00:00Z"),
    ] {
        let out = env.cli(&["vault", "get", "GitHub Production", "-f", sel]);
        assert!(
            out.status.success(),
            "selector {sel} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{expected}\n")
        );
    }

    // Custom field collision: built-in `password` wins; `custom.password` forces custom field
    let builtin_pw = env.cli(&["vault", "get", "GitHub Production", "-f", "password"]);
    assert_eq!(
        String::from_utf8_lossy(&builtin_pw.stdout),
        "super-secret-login-pw\n"
    );
    let custom_pw = env.cli(&["vault", "get", "GitHub Production", "-f", "custom.password"]);
    assert!(custom_pw.status.success());
    assert_eq!(
        String::from_utf8_lossy(&custom_pw.stdout),
        "custom-password-field-value\n"
    );

    // Fallback custom field lookup (exact & case-insensitive) + hidden sensitivity in --json
    let custom_env = env.cli(&["vault", "get", "GitHub Production", "-f", "environment"]);
    assert!(custom_env.status.success());
    assert_eq!(String::from_utf8_lossy(&custom_env.stdout), "production\n");

    let custom_hidden = env.cli(&[
        "vault",
        "get",
        "GitHub Production",
        "-f",
        "api secret",
        "--json",
    ]);
    assert!(custom_hidden.status.success());
    let ch: Value = serde_json::from_slice(&custom_hidden.stdout).unwrap();
    assert_eq!(ch["ok"], true);
    assert_eq!(ch["sensitive"], true);
    assert_eq!(ch["value"], "hidden-api-token-999");

    // Missing / empty / type-mismatched fields fail closed with exit 1 and empty stdout
    for (target, sel) in [
        ("GitHub Production", "organization_id"),
        ("GitHub Production", "card.number"),
        ("GitHub Production", "nonexistent_field"),
        ("GitHub Production", "custom."),
        ("GitHub Production", "密码密码密码"),
        ("Corporate Visa", "username"),
        ("Recovery Codes", "folder"),
    ] {
        let out = env.cli(&["vault", "get", target, "-f", sel]);
        assert!(
            !out.status.success(),
            "expected failure for {target} -f {sel}"
        );
        assert!(
            out.stdout.is_empty(),
            "stdout must be empty on error for {target} -f {sel}"
        );
    }
}

#[test]
fn vault_get_note_card_identity_and_ssh_key_selectors() {
    let env = TestVaultEnv::new();

    // Secure Note
    let note = env.cli(&["vault", "get", "Recovery Codes", "--notes", "--json"]);
    assert!(note.status.success());
    let nj: Value = serde_json::from_slice(&note.stdout).unwrap();
    assert_eq!(nj["sensitive"], true);
    assert_eq!(nj["value"], "recovery-code-alpha-beta");

    // Card (all 6 fields + hyphen normalization)
    for (sel, expected) in [
        ("card.cardholder-name", "Alice Example"),
        ("card.brand", "Visa"),
        ("card.number", "4111222233334444"),
        ("card.exp-month", "12"),
        ("card.exp_year", "2030"),
        ("card.code", "987"),
    ] {
        let out = env.cli(&["vault", "get", "Corporate Visa", "-f", sel]);
        assert!(
            out.status.success(),
            "card selector {sel} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{expected}\n")
        );
    }

    // Identity (all 18 fields + hyphen normalization)
    for (sel, expected) in [
        ("identity.title", "Dr"),
        ("identity.first-name", "Alice"),
        ("identity.middle_name", "Marie"),
        ("identity.last_name", "Example"),
        ("identity.address1", "123 Main St"),
        ("identity.address2", "Suite 400"),
        ("identity.address3", "Floor 4"),
        ("identity.city", "Tokyo"),
        ("identity.state", "Tokyo"),
        ("identity.postal-code", "100-0001"),
        ("identity.country", "JP"),
        ("identity.company", "Omarchy Corp"),
        ("identity.email", "alice@example.com"),
        ("identity.phone", "+81-3-0000-0000"),
        ("identity.ssn", "123-45-6789"),
        ("identity.username", "alice_id"),
        ("identity.passport-number", "P12345678"),
        ("identity.license_number", "DL-987654"),
    ] {
        let out = env.cli(&["vault", "get", "Alice Identity", "-f", sel]);
        assert!(
            out.status.success(),
            "identity selector {sel} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{expected}\n")
        );
    }

    // SSH Key (ssh.* and short aliases, plus single trailing newline on PEM ending in \n)
    let expected_pem =
        "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA-FAKE-KEY-BODY\n-----END OPENSSH PRIVATE KEY-----\n";
    for sel in ["ssh.private_key", "private_key"] {
        let out = env.cli(&["vault", "get", "Prod Bastion Key", "-f", sel]);
        assert!(out.status.success());
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert_eq!(
            stdout, expected_pem,
            "must not double-append newline on PEM"
        );
    }
    for (sel, expected) in [
        (
            "ssh.public_key",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKey alice@bastion",
        ),
        (
            "public_key",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakePublicKey alice@bastion",
        ),
        ("ssh.fingerprint", "SHA256:FakeFingerprint123456"),
        ("fingerprint", "SHA256:FakeFingerprint123456"),
        ("ssh.passphrase", "ssh-passphrase-secret"),
        ("passphrase", "ssh-passphrase-secret"),
    ] {
        let out = env.cli(&["vault", "get", "Prod Bastion Key", "-f", sel]);
        assert!(
            out.status.success(),
            "ssh selector {sel} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            String::from_utf8_lossy(&out.stdout),
            format!("{expected}\n")
        );
    }
}

#[cfg(unix)]
fn run_cli_in_pty(env: &TestVaultEnv, args: &[&str]) -> (std::process::ExitStatus, String, String) {
    use std::ffi::CStr;
    use std::io::Read;
    use std::os::fd::{FromRawFd, IntoRawFd};

    let dir = env.temp.path();

    // Create a real kernel PTY pair via POSIX openpt/grantpt/unlockpt/ptsname
    let (master_file, slave_file) = unsafe {
        let master_fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master_fd >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master_fd), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master_fd), 0, "unlockpt failed");
        let name_ptr = libc::ptsname(master_fd);
        assert!(!name_ptr.is_null(), "ptsname failed");
        let slave_name = CStr::from_ptr(name_ptr).to_str().unwrap().to_string();
        let slave = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&slave_name)
            .expect("open PTY slave");
        (fs::File::from_raw_fd(master_fd), slave)
    };

    let mut child = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args(args)
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_KEYRING_PROVIDER", "secret-tool")
        .stdin(Stdio::null())
        .stdout(Stdio::from(slave_file))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    // Drain PTY master concurrently so the child never blocks on a full PTY buffer
    let master_fd_raw = master_file.into_raw_fd();
    let reader_handle = thread::spawn(move || {
        let mut f = unsafe { fs::File::from_raw_fd(master_fd_raw) };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        loop {
            match f.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).replace("\r\n", "\n")
    });

    let mut stderr_buf = String::new();
    if let Some(mut err) = child.stderr.take() {
        let _ = err.read_to_string(&mut stderr_buf);
    }
    let status = child.wait().unwrap();
    let stdout_str = reader_handle.join().unwrap();
    (status, stdout_str, stderr_buf)
}

#[cfg(unix)]
#[test]
fn vault_get_tty_safety_guard_redaction_and_reveal() {
    let env = TestVaultEnv::new();
    let expected_hint =
        "Pass --reveal to display in a terminal, pipe stdout, or use 'omawarden copy'";

    // 1. Summary card on TTY redacts sensitive fields by default
    let (status, stdout, stderr) = run_cli_in_pty(&env, &["vault", "get", "GitHub Production"]);
    assert!(status.success(), "stderr: {stderr}");
    assert!(stdout.contains("octocat"));
    assert!(stdout.contains("Login operational notes"));
    assert!(stdout.contains("production"));
    assert!(stdout.contains("••••••••"));
    assert!(!stdout.contains("super-secret-login-pw"));
    assert!(!stdout.contains("hidden-api-token-999"));

    // Summary card on Secure Note redacts notes on TTY
    let (status, stdout, _) = run_cli_in_pty(&env, &["vault", "get", "Recovery Codes"]);
    assert!(status.success());
    assert!(stdout.contains("••••••••"));
    assert!(!stdout.contains("recovery-code-alpha-beta"));

    // 2. Summary card on TTY with --reveal displays unredacted secrets
    let (status, stdout, stderr) =
        run_cli_in_pty(&env, &["vault", "get", "GitHub Production", "--reveal"]);
    assert!(status.success(), "stderr: {stderr}");
    assert!(stdout.contains("super-secret-login-pw"));
    assert!(stdout.contains("hidden-api-token-999"));

    let (status, stdout, _) = run_cli_in_pty(&env, &["vault", "get", "Recovery Codes", "--reveal"]);
    assert!(status.success());
    assert!(stdout.contains("recovery-code-alpha-beta"));

    // 3. Sensitive single fields refuse on TTY without --reveal
    for (target, flag_args) in [
        ("GitHub Production", vec!["--password"]),
        ("GitHub Production", vec!["--totp"]),
        ("GitHub Production", vec!["-f", "totp_secret"]),
        ("GitHub Production", vec!["-f", "api secret"]),
        ("Recovery Codes", vec!["--notes"]),
        ("Corporate Visa", vec!["-f", "card.number"]),
        ("Corporate Visa", vec!["-f", "card.code"]),
        ("Alice Identity", vec!["-f", "identity.ssn"]),
        ("Alice Identity", vec!["-f", "identity.passport_number"]),
        ("Alice Identity", vec!["-f", "identity.license_number"]),
        ("Prod Bastion Key", vec!["-f", "ssh.private_key"]),
        ("Prod Bastion Key", vec!["-f", "ssh.passphrase"]),
    ] {
        let mut args = vec!["vault", "get", target];
        args.extend(flag_args.iter().copied());
        let (status, stdout, stderr) = run_cli_in_pty(&env, &args);
        assert!(
            !status.success(),
            "expected TTY refusal for {:?}, stdout={stdout}",
            args
        );
        assert!(
            stdout.is_empty(),
            "TTY refusal must not leak secret on stdout for {:?}",
            args
        );
        assert!(
            stderr.contains(expected_hint),
            "expected TTY hint in stderr for {:?}, got: {stderr}",
            args
        );
    }

    // 4. Sensitive single fields succeed on TTY with --reveal
    let (status, stdout, _) = run_cli_in_pty(
        &env,
        &[
            "vault",
            "get",
            "GitHub Production",
            "--password",
            "--reveal",
        ],
    );
    assert!(status.success());
    assert_eq!(stdout, "super-secret-login-pw\n");

    let (status, stdout, _) = run_cli_in_pty(
        &env,
        &["vault", "get", "Recovery Codes", "--notes", "--reveal"],
    );
    assert!(status.success());
    assert_eq!(stdout, "recovery-code-alpha-beta\n");

    // 5. Non-sensitive single fields succeed on TTY WITHOUT --reveal
    for (target, flag_args, expected) in [
        ("GitHub Production", vec!["--username"], "octocat\n"),
        (
            "GitHub Production",
            vec!["--notes"],
            "Login operational notes\n",
        ),
        (
            "GitHub Production",
            vec!["-f", "environment"],
            "production\n",
        ),
        ("Corporate Visa", vec!["-f", "card.brand"], "Visa\n"),
        ("Corporate Visa", vec!["--notes"], "Card billing note\n"),
        (
            "Alice Identity",
            vec!["-f", "identity.email"],
            "alice@example.com\n",
        ),
        ("Alice Identity", vec!["--notes"], "Identity note\n"),
        (
            "Prod Bastion Key",
            vec!["-f", "ssh.fingerprint"],
            "SHA256:FakeFingerprint123456\n",
        ),
        ("Prod Bastion Key", vec!["--notes"], "Bastion SSH note\n"),
    ] {
        let mut args = vec!["vault", "get", target];
        args.extend(flag_args.iter().copied());
        let (status, stdout, stderr) = run_cli_in_pty(&env, &args);
        assert!(
            status.success(),
            "non-sensitive {:?} should succeed on TTY, stderr: {stderr}",
            args
        );
        assert_eq!(stdout, expected);
    }

    // 6. --json refuses on TTY without --reveal, succeeds with --reveal
    let (status, stdout, _) =
        run_cli_in_pty(&env, &["vault", "get", "GitHub Production", "--json"]);
    assert!(!status.success());
    let refused: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(refused["ok"], false);
    assert!(refused["error"]
        .as_str()
        .unwrap_or("")
        .contains(expected_hint));

    let (status, stdout, stderr) = run_cli_in_pty(
        &env,
        &["vault", "get", "GitHub Production", "--json", "--reveal"],
    );
    assert!(status.success(), "stderr: {stderr}");
    let revealed: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(revealed["ok"], true);
    assert_eq!(revealed["item"]["name"], "GitHub Production");
}

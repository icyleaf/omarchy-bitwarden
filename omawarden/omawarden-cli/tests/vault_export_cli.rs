//! End-to-end CLI ↔ Daemon IPC & PTY integration tests for `omawarden vault export` (#481).

use omawarden_engine::crypto::{
    derive_export_key, derive_master_key, parse_symmetric_key_from_decrypted_bytes, EncString,
    ExportKdfConfig, KdfType, SymmetricCryptoKey,
};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::os::unix::{
    fs::PermissionsExt,
    net::{UnixListener, UnixStream},
};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
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
    fn new(unlock: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();

        let keyring = dir.join("secret-tool");
        fs::write(
            &keyring,
            "#!/bin/sh\ncase \"$*\" in\nlookup*'kind access_token'*) echo fixture-token;;\n*) exit 1;;\nesac\n",
        )
        .unwrap();
        fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();

        let email = "export@fixture.invalid";
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

        let item_key_raw = [99u8; 64];
        let item_key = SymmetricCryptoKey::from_raw_bytes(&item_key_raw).unwrap();
        let enc_item_key = user_key.encrypt(&item_key_raw).unwrap();

        let enc = |s: &str| user_key.encrypt_string(s).unwrap();
        let enc_item = |s: &str| item_key.encrypt_string(s).unwrap();

        let folder_id = "folder-work-0001";
        let folders = vec![json!({
            "id": folder_id,
            "name": enc("Work")
        })];

        let ciphers = vec![
            // 1. Login with per-item key, URIs/match, TOTP, passkey, httpAuthenticationEnabled,
            //    all 4 custom field types, passwordHistory, attachments (excluded)
            json!({
                "id": "11111111-1111-1111-1111-111111111111",
                "organizationId": null,
                "folderId": folder_id,
                "type": 1,
                "reprompt": 1,
                "key": enc_item_key,
                "name": enc_item("GitHub Production"),
                "notes": enc_item("Login notes"),
                "favorite": true,
                "creationDate": "2026-01-01T00:00:00Z",
                "revisionDate": "2026-02-01T00:00:00Z",
                "deletedDate": null,
                "login": {
                    "username": enc_item("octocat"),
                    "password": enc_item("super-secret-login-pw"),
                    "totp": enc_item("JBSWY3DPEHPK3PXP"),
                    "httpAuthenticationEnabled": true,
                    "uris": [
                        { "uri": enc_item("https://github.com/login"), "match": 0 },
                        { "uri": enc_item("https://api.github.com"), "match": 1 }
                    ],
                    "fido2Credentials": [
                        {
                            "credentialId": enc_item("cred-abc"),
                            "keyType": enc_item("public-key"),
                            "keyAlgorithm": enc_item("ECDSA"),
                            "keyCurve": enc_item("P-256"),
                            "keyValue": enc_item("pkcs8-b64"),
                            "rpId": enc_item("github.com"),
                            "userHandle": enc_item("uh-1"),
                            "userName": enc_item("octocat"),
                            "counter": enc_item("1"),
                            "rpName": enc_item("GitHub"),
                            "userDisplayName": enc_item("Octo Cat"),
                            "discoverable": enc_item("true"),
                            "creationDate": "2026-01-10T00:00:00Z"
                        }
                    ]
                },
                "fields": [
                    { "name": enc_item("Env"), "value": enc_item("production"), "type": 0, "linkedId": null },
                    { "name": enc_item("API Secret"), "value": enc_item("hidden-999"), "type": 1, "linkedId": null },
                    { "name": enc_item("MFA"), "value": enc_item("true"), "type": 2, "linkedId": null },
                    { "name": enc_item("LinkedUser"), "value": null, "type": 3, "linkedId": 100 }
                ],
                "passwordHistory": [
                    { "lastUsedDate": "2025-11-01T00:00:00Z", "password": enc_item("old-pw-1") }
                ],
                "attachments": [
                    { "id": "att-1", "fileName": enc_item("backup.bin"), "size": "128" }
                ]
            }),
            // 2. Secure Note
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
                "secureNote": { "type": 0 }
            }),
            // 3. Card
            json!({
                "id": "33333333-3333-3333-3333-333333333333",
                "organizationId": null,
                "folderId": null,
                "type": 3,
                "name": enc("Corporate Visa"),
                "notes": null,
                "favorite": false,
                "deletedDate": null,
                "card": {
                    "cardholderName": enc("Alice Example"),
                    "brand": enc("Visa"),
                    "number": enc("4111222233334444"),
                    "expMonth": enc("12"),
                    "expYear": enc("2030"),
                    "code": enc("987")
                }
            }),
            // 4. Identity
            json!({
                "id": "44444444-4444-4444-4444-444444444444",
                "organizationId": null,
                "folderId": null,
                "type": 4,
                "name": enc("Alice Identity"),
                "notes": null,
                "favorite": false,
                "deletedDate": null,
                "identity": {
                    "firstName": enc("Alice"),
                    "lastName": enc("Example"),
                    "email": enc("alice@example.com"),
                    "ssn": enc("123-45-6789")
                }
            }),
            // 5. SSH Key
            json!({
                "id": "55555555-5555-5555-5555-555555555555",
                "organizationId": null,
                "folderId": null,
                "type": 5,
                "name": enc("Prod Bastion Key"),
                "notes": enc("Bastion SSH note"),
                "favorite": false,
                "deletedDate": null,
                "sshKey": {
                    "privateKey": enc("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE-KEY\n-----END OPENSSH PRIVATE KEY-----\n"),
                    "publicKey": enc("ssh-ed25519 AAAAFakeKey alice@bastion"),
                    "keyFingerprint": enc("SHA256:FakeFingerprint123456")
                }
            }),
            // 6. Trash cipher (excluded)
            json!({
                "id": "88888888-8888-8888-8888-888888888888",
                "organizationId": null,
                "folderId": null,
                "type": 1,
                "name": enc("Trashed Login"),
                "deletedDate": "2026-02-10T00:00:00Z",
                "login": { "username": enc("old"), "password": enc("old") }
            }),
            // 7. Organization cipher (excluded)
            json!({
                "id": "99999999-9999-9999-9999-999999999999",
                "organizationId": "org-aaaa-bbbb",
                "folderId": null,
                "type": 1,
                "name": enc("Org Secret"),
                "deletedDate": null,
                "login": { "username": enc("org"), "password": enc("org") }
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

        // Wait for daemon socket to become ready
        let ping = ipc(&socket, json!({ "action": "ping" }));
        assert_eq!(ping["ok"], true);

        if unlock {
            let unlock_res = ipc(
                &socket,
                json!({ "action": "unlock", "password": master_password }),
            );
            assert_eq!(unlock_res["ok"], true, "unlock failed: {unlock_res}");
        }

        Self {
            temp,
            socket,
            _daemon: daemon,
        }
    }

    fn run_cli(&self, args: &[&str], cwd: Option<&Path>) -> Output {
        let dir = self.temp.path();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        cmd.args(args)
            .env_clear()
            .env("HOME", dir)
            .env("PATH", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMA_KEYRING_PROVIDER", "secret-tool")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(wd) = cwd {
            cmd.current_dir(wd);
        }
        cmd.output().unwrap()
    }

    fn run_cli_with_stdin(&self, args: &[&str], cwd: Option<&Path>, stdin_data: &[u8]) -> Output {
        let dir = self.temp.path();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        cmd.args(args)
            .env_clear()
            .env("HOME", dir)
            .env("PATH", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMA_KEYRING_PROVIDER", "secret-tool")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(wd) = cwd {
            cmd.current_dir(wd);
        }
        let mut child = cmd.spawn().unwrap();
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(stdin_data);
        }
        child.wait_with_output().unwrap()
    }
}

#[cfg(unix)]
fn run_cli_in_pty(
    env: &TestVaultEnv,
    args: &[&str],
    stdin_input: Option<&str>,
) -> (std::process::ExitStatus, String, String) {
    use std::ffi::CStr;
    use std::os::fd::{FromRawFd, IntoRawFd};

    let dir = env.temp.path();

    let (master_file, slave_in, slave_out) = unsafe {
        use std::os::unix::fs::OpenOptionsExt;
        let master_fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master_fd >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master_fd), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master_fd), 0, "unlockpt failed");
        let name_ptr = libc::ptsname(master_fd);
        assert!(!name_ptr.is_null(), "ptsname failed");
        let slave_name = CStr::from_ptr(name_ptr).to_str().unwrap().to_string();
        let slave_a = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&slave_name)
            .expect("open PTY slave");
        let slave_b = slave_a.try_clone().expect("clone PTY slave");
        (fs::File::from_raw_fd(master_fd), slave_a, slave_b)
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
        .stdin(Stdio::from(slave_in))
        .stdout(Stdio::from(slave_out))
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut master_writer = master_file.try_clone().unwrap();
    if let Some(input) = stdin_input {
        let payload = input.to_string();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(80));
            let _ = master_writer.write_all(payload.as_bytes());
            let _ = master_writer.flush();
        });
    }

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

#[test]
fn ping_advertises_vault_export_import_capability_on_schema_v3() {
    let env = TestVaultEnv::new(true);
    let ping = ipc(&env.socket, json!({ "action": "ping" }));
    assert_eq!(ping["ok"], true);
    assert_eq!(ping["schema_version"], 3);
    let caps = ping["capabilities"].as_array().unwrap();
    assert!(
        caps.iter()
            .any(|c| c.as_str() == Some("vault_export_import")),
        "expected vault_export_import in capabilities: {caps:?}"
    );
}

#[test]
fn vault_export_fails_closed_when_vault_is_locked() {
    let env = TestVaultEnv::new(false);

    // Direct daemon IPC rejects locked vault
    let reply = ipc(
        &env.socket,
        json!({ "action": "vault_export", "format": "json" }),
    );
    assert_eq!(reply["ok"], false);
    assert!(reply["error"]
        .as_str()
        .unwrap_or("")
        .to_lowercase()
        .contains("locked"));

    // CLI fails closed and does not create target file
    let out_file = env.temp.path().join("locked_export.json");
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            out_file.to_str().unwrap(),
            "--allow-plaintext",
            "--json",
        ],
        None,
    );
    assert!(!out.status.success());
    let payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], false);
    assert!(payload["error"]
        .as_str()
        .unwrap_or("")
        .to_lowercase()
        .contains("locked"));
    assert!(!out_file.exists());
}

#[test]
fn vault_export_plaintext_json_file_0600_schema_and_exclusions() {
    let env = TestVaultEnv::new(true);
    let out_file = env.temp.path().join("personal_backup.json");

    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            out_file.to_str().unwrap(),
            "--allow-plaintext",
            "--json",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "export failed: stdout={} stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["format"], "json");
    assert_eq!(envelope["output"], out_file.display().to_string());
    assert_eq!(envelope["item_count"], 5);
    assert_eq!(envelope["folder_count"], 1);

    // Rule 5: Atomic 0600 permissions
    let mode = fs::metadata(&out_file).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0600 permissions, got {:o}", mode);

    let raw = fs::read_to_string(&out_file).unwrap();
    assert!(
        raw.starts_with("{\n  \"encrypted\": false,\n"),
        "expected 2-space pretty-printed JSON"
    );

    let doc: Value = serde_json::from_str(&raw).unwrap();
    assert_eq!(doc["encrypted"], false);
    assert_eq!(doc["folders"].as_array().unwrap().len(), 1);
    assert_eq!(doc["folders"][0]["name"], "Work");

    let items = doc["items"].as_array().unwrap();
    assert_eq!(items.len(), 5);
    for item in items {
        assert_eq!(item["organizationId"], Value::Null);
        assert_eq!(item["collectionIds"], Value::Null);
        assert!(item.get("key").is_none());
        assert!(item.get("attachments").is_none());
    }

    assert_eq!(items[0]["login"]["username"], "octocat");
    assert_eq!(items[0]["login"]["httpAuthenticationEnabled"], true);
    assert_eq!(
        items[0]["login"]["fido2Credentials"][0]["credentialId"],
        "cred-abc"
    );
    assert_eq!(items[0]["fields"][3]["type"], 3);
    assert_eq!(items[0]["fields"][3]["linkedId"], 100);
    assert_eq!(items[0]["passwordHistory"][0]["password"], "old-pw-1");
    assert_eq!(
        items[4]["sshKey"]["keyFingerprint"],
        "SHA256:FakeFingerprint123456"
    );
}

#[test]
fn vault_export_default_filename_when_output_omitted_or_directory() {
    let env = TestVaultEnv::new(true);

    // 1. Omitted --output writes bitwarden_export_YYYYMMDDHHMMSS.json in CWD
    let cwd_dir = env.temp.path().join("cwd_export");
    fs::create_dir_all(&cwd_dir).unwrap();
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--allow-plaintext",
            "--json",
        ],
        Some(&cwd_dir),
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    let generated_name = payload["output"].as_str().unwrap();
    assert!(generated_name.starts_with("bitwarden_export_"));
    assert!(generated_name.ends_with(".json"));
    let generated_path = cwd_dir.join(generated_name);
    assert!(generated_path.is_file());
    assert_eq!(
        fs::metadata(&generated_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // 2. Directory --output writes bitwarden_export_YYYYMMDDHHMMSS.json inside directory
    let target_dir = env.temp.path().join("dir_export");
    fs::create_dir_all(&target_dir).unwrap();
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            target_dir.to_str().unwrap(),
            "--allow-plaintext",
            "--json",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    let dir_out_path = PathBuf::from(payload["output"].as_str().unwrap());
    assert_eq!(dir_out_path.parent().unwrap(), target_dir);
    assert!(dir_out_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("bitwarden_export_"));
    assert!(dir_out_path.is_file());
}

#[test]
fn vault_export_overwrite_protection_and_force_override() {
    let env = TestVaultEnv::new(true);
    let out_file = env.temp.path().join("existing.json");
    fs::write(&out_file, "SENTINEL-DO-NOT-CLOBBER").unwrap();

    // Without --force: fails closed and preserves sentinel
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            out_file.to_str().unwrap(),
            "--allow-plaintext",
        ],
        None,
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--force"));
    assert_eq!(
        fs::read_to_string(&out_file).unwrap(),
        "SENTINEL-DO-NOT-CLOBBER"
    );

    // With --force: overwrites atomically with 0600
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            out_file.to_str().unwrap(),
            "--allow-plaintext",
            "--force",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: Value = serde_json::from_str(&fs::read_to_string(&out_file).unwrap()).unwrap();
    assert_eq!(doc["encrypted"], false);
    assert_eq!(
        fs::metadata(&out_file).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn vault_export_security_guards_non_interactive_stdout_and_zero_argv() {
    let env = TestVaultEnv::new(true);
    let out_file = env.temp.path().join("should_not_exist.json");

    // 1. Non-interactive plaintext export without --allow-plaintext fails closed
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            out_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--allow-plaintext"));
    assert!(!out_file.exists());

    // 2. --output - + --json mutual exclusion fails closed
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            "-",
            "--allow-plaintext",
            "--json",
        ],
        None,
    );
    assert!(!out.status.success());
    let err_env: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(err_env["ok"], false);
    assert!(err_env["error"]
        .as_str()
        .unwrap_or("")
        .contains("--output -"));

    // 3. --output - piped (non-TTY) succeeds and outputs valid Plaintext JSON to stdout
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            "-",
            "--allow-plaintext",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let doc: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(doc["encrypted"], false);
    assert_eq!(doc["items"].as_array().unwrap().len(), 5);

    // 4. Rule 11 Zero-Argv: --password CLI flag is rejected fail-closed
    let out = env.run_cli(&["vault", "export", "--password", "leak-in-argv"], None);
    assert!(!out.status.success());
}

#[cfg(unix)]
#[test]
fn vault_export_interactive_tty_confirmation_and_stdout_refusal() {
    let env = TestVaultEnv::new(true);

    // 1. Interactive y/N prompt: 'n' aborts without creating file
    let declined_file = env.temp.path().join("declined.json");
    let (status, _stdout, stderr) = run_cli_in_pty(
        &env,
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            declined_file.to_str().unwrap(),
        ],
        Some("n\n"),
    );
    assert!(!status.success());
    assert!(stderr.contains("Continue? [y/N]"), "stderr: {stderr}");
    assert!(!declined_file.exists());

    // 2. Interactive y/N prompt: 'y' confirms and creates 0600 file
    let confirmed_file = env.temp.path().join("confirmed.json");
    let (status, _stdout, stderr) = run_cli_in_pty(
        &env,
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            confirmed_file.to_str().unwrap(),
        ],
        Some("y\n"),
    );
    assert!(status.success(), "stderr: {stderr}");
    assert!(confirmed_file.is_file());
    assert_eq!(
        fs::metadata(&confirmed_file).unwrap().permissions().mode() & 0o777,
        0o600
    );

    // 3. Interactive TTY stdout dump (--output -) refuses without --force
    let (status, stdout, stderr) = run_cli_in_pty(
        &env,
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            "-",
            "--allow-plaintext",
        ],
        None,
    );
    assert!(!status.success());
    assert!(stdout.is_empty(), "must not dump secrets to TTY: {stdout}");
    assert!(stderr.contains("--force"), "stderr: {stderr}");

    // 4. Interactive TTY stdout dump (--output -) succeeds with --force
    let (status, stdout, stderr) = run_cli_in_pty(
        &env,
        &[
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            "-",
            "--allow-plaintext",
            "--force",
        ],
        None,
    );
    assert!(status.success(), "stderr: {stderr}");
    let doc: Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(doc["encrypted"], false);
    assert_eq!(doc["items"].as_array().unwrap().len(), 5);
}

#[test]
fn vault_export_fails_closed_when_in_process_daemon_lacks_capability() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let sock_path = dir.join("omawarden.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();
    listener.set_nonblocking(true).unwrap();

    let stop_flag = Arc::new(AtomicBool::new(false));
    let stop_clone = Arc::clone(&stop_flag);
    let server_thread = thread::spawn(move || {
        while !stop_clone.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut line = String::new();
                    let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut line);
                    let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                    let resp = match req.get("action").and_then(Value::as_str) {
                        Some("ping") => json!({
                            "ok": true,
                            "pong": true,
                            "protocol_version": 1,
                            "schema_version": 3,
                            "capabilities": ["cipher_mutation_v3", "vault_get"],
                            "unlocked": true
                        }),
                        Some("stop") => json!({
                            "ok": false,
                            "error": "Access denied: cannot terminate in-process daemon hosted by an external application",
                            "protocol_version": 1
                        }),
                        _ => json!({ "ok": false, "error": "unsupported" }),
                    };
                    let _ = writeln!(stream, "{resp}");
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let out_file = dir.join("stale_export.json");
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            out_file.to_str().unwrap(),
            "--allow-plaintext",
            "--json",
        ])
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    stop_flag.store(true, Ordering::Relaxed);
    let _ = server_thread.join();

    assert!(!out.status.success());
    let payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], false);
    assert!(
        payload["error"]
            .as_str()
            .unwrap_or("")
            .contains("vault_export_import"),
        "expected missing capability name in error: {payload}"
    );
    assert!(!out_file.exists());
}

#[test]
fn vault_export_auto_restarts_stale_standalone_daemon_lacking_capability() {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let sock_path = dir.join("omawarden.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();
    listener.set_nonblocking(true).unwrap();

    let saw_admin_stop = Arc::new(AtomicBool::new(false));
    let saw_stop_clone = Arc::clone(&saw_admin_stop);
    let sock_clone = sock_path.clone();
    let server_thread = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let mut line = String::new();
                    let _ = BufReader::new(stream.try_clone().unwrap()).read_line(&mut line);
                    let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
                    match req.get("action").and_then(Value::as_str) {
                        Some("ping") => {
                            let resp = json!({
                                "ok": true,
                                "pong": true,
                                "protocol_version": 1,
                                "schema_version": 3,
                                "capabilities": ["cipher_mutation_v3", "vault_get"],
                                "unlocked": true
                            });
                            let _ = writeln!(stream, "{resp}");
                        }
                        Some("stop") if req.get("admin").and_then(Value::as_bool) == Some(true) => {
                            saw_stop_clone.store(true, Ordering::SeqCst);
                            let _ = writeln!(
                                stream,
                                "{}",
                                json!({ "ok": true, "protocol_version": 1 })
                            );
                            let _ = fs::remove_file(&sock_clone);
                            break;
                        }
                        _ => {
                            let _ = writeln!(
                                stream,
                                "{}",
                                json!({ "ok": false, "error": "unsupported" })
                            );
                        }
                    }
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    let out_file = dir.join("restarted_export.json");
    let out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "vault",
            "export",
            "--format",
            "json",
            "--output",
            out_file.to_str().unwrap(),
            "--allow-plaintext",
            "--json",
        ])
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_DAEMON_BIN", env!("CARGO_BIN_EXE_omawarden"))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap();

    let _ = server_thread.join();

    // Stale standalone daemon must have received admin stop and been replaced by fresh daemon
    assert!(
        saw_admin_stop.load(Ordering::SeqCst),
        "expected stale standalone daemon to receive admin stop"
    );

    // Fresh restarted daemon advertises vault_export_import and starts locked
    let ping = ipc(&sock_path, json!({ "action": "ping" }));
    assert_eq!(ping["ok"], true);
    assert!(ping["capabilities"]
        .as_array()
        .unwrap()
        .iter()
        .any(|c| c.as_str() == Some("vault_export_import")));

    // Stop the spawned fresh daemon cleanly before tempdir drops
    let _ = ipc(&sock_path, json!({ "action": "stop", "admin": true }));

    // Fresh daemon is locked, so vault export fails closed with locked error (not missing capability)
    assert!(!out.status.success());
    let payload: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(payload["ok"], false);
    assert!(
        payload["error"]
            .as_str()
            .unwrap_or("")
            .to_lowercase()
            .contains("locked"),
        "expected locked error after auto-restart, got: {payload}"
    );
}

#[test]
fn vault_export_defaults_to_encrypted_json_with_password_stdin_and_default_filename() {
    let env = TestVaultEnv::new(true);

    // 1. Omitted --format and omitted --output -> defaults to encrypted_json + bitwarden_encrypted_export_YYYYMMDDHHMMSS.json
    let cwd_dir = env.temp.path().join("cwd-encrypted");
    fs::create_dir_all(&cwd_dir).unwrap();
    let out = env.run_cli_with_stdin(
        &["vault", "export", "--password-stdin", "--json"],
        Some(&cwd_dir),
        b"my-export-passphrase\n",
    );
    assert!(
        out.status.success(),
        "default encrypted_json export failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["format"], "encrypted_json");
    assert_eq!(envelope["item_count"], 5);
    assert_eq!(envelope["folder_count"], 1);

    let out_name = envelope["output"].as_str().unwrap();
    assert!(
        out_name.starts_with("bitwarden_encrypted_export_") && out_name.ends_with(".json"),
        "unexpected default filename: {out_name}"
    );
    let ts = &out_name["bitwarden_encrypted_export_".len()..out_name.len() - ".json".len()];
    assert_eq!(ts.len(), 14);
    assert!(ts.chars().all(|c| c.is_ascii_digit()));

    let written_path = cwd_dir.join(out_name);
    let mode = fs::metadata(&written_path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "encrypted export file must be 0600");

    // Verify Bitwarden-compatible decryption using independent derive_export_key
    let doc: Value = serde_json::from_str(&fs::read_to_string(&written_path).unwrap()).unwrap();
    assert_eq!(doc["encrypted"], true);
    assert_eq!(doc["passwordProtected"], true);
    assert_eq!(doc["kdfType"], 0);
    assert_eq!(doc["kdfIterations"], 100_000);
    let salt = doc["salt"].as_str().unwrap();
    assert_eq!(salt.len(), 24);

    let export_key = derive_export_key(
        "my-export-passphrase",
        salt,
        &ExportKdfConfig::Pbkdf2Sha256 {
            iterations: 100_000,
        },
    )
    .unwrap();
    let val_enc = EncString::parse(doc["encKeyValidation_DO_NOT_EDIT"].as_str().unwrap()).unwrap();
    assert_eq!(val_enc.enc_type, 2);
    let uuid = val_enc.decrypt_string(&export_key).unwrap();
    assert_eq!(uuid.len(), 36);

    let data_enc = EncString::parse(doc["data"].as_str().unwrap()).unwrap();
    assert_eq!(data_enc.enc_type, 2);
    let inner_str = data_enc.decrypt_string(&export_key).unwrap();
    assert!(inner_str.starts_with("{\n  \"encrypted\": false,\n"));
    let inner: Value = serde_json::from_str(&inner_str).unwrap();
    assert_eq!(inner["items"].as_array().unwrap().len(), 5);
    assert_eq!(
        inner["items"][0]["login"]["password"],
        "super-secret-login-pw"
    );

    // 2. --output <directory> also generates bitwarden_encrypted_export_YYYYMMDDHHMMSS.json inside directory
    let target_dir = env.temp.path().join("dir-encrypted");
    fs::create_dir_all(&target_dir).unwrap();
    let out_dir = env.run_cli_with_stdin(
        &[
            "vault",
            "export",
            "--output",
            target_dir.to_str().unwrap(),
            "--password-stdin",
            "--json",
        ],
        None,
        b"dir-passphrase\r\n",
    );
    assert!(out_dir.status.success());
    let dir_env: Value = serde_json::from_slice(&out_dir.stdout).unwrap();
    let dir_out_path = PathBuf::from(dir_env["output"].as_str().unwrap());
    assert_eq!(dir_out_path.parent().unwrap(), target_dir.as_path());
    assert!(dir_out_path
        .file_name()
        .unwrap()
        .to_str()
        .unwrap()
        .starts_with("bitwarden_encrypted_export_"));
    assert_eq!(
        fs::metadata(&dir_out_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn vault_export_encrypted_json_with_password_file_and_rule11_guards() {
    let env = TestVaultEnv::new(true);

    // 1. Valid --password-file with trailing CRLF
    let pw_file = env.temp.path().join("export.pw");
    fs::write(&pw_file, "file-export-secret\r\n").unwrap();
    let out_file = env.temp.path().join("from_pw_file.json");
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--output",
            out_file.to_str().unwrap(),
            "--password-file",
            pw_file.to_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert!(
        out.status.success(),
        "password-file export failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::metadata(&out_file).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let doc: Value = serde_json::from_str(&fs::read_to_string(&out_file).unwrap()).unwrap();
    let export_key = derive_export_key(
        "file-export-secret",
        doc["salt"].as_str().unwrap(),
        &ExportKdfConfig::Pbkdf2Sha256 {
            iterations: 100_000,
        },
    )
    .unwrap();
    let inner_str = EncString::parse(doc["data"].as_str().unwrap())
        .unwrap()
        .decrypt_string(&export_key)
        .unwrap();
    let inner: Value = serde_json::from_str(&inner_str).unwrap();
    assert_eq!(inner["items"].as_array().unwrap().len(), 5);

    // 2. --password-file pointing to a directory MUST fail closed
    let pw_dir = env.temp.path().join("pw-dir");
    fs::create_dir_all(&pw_dir).unwrap();
    let bad_dir_out = env.run_cli(
        &[
            "vault",
            "export",
            "--output",
            env.temp.path().join("nope1.json").to_str().unwrap(),
            "--password-file",
            pw_dir.to_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert!(!bad_dir_out.status.success());
    let payload: Value = serde_json::from_slice(&bad_dir_out.stdout).unwrap();
    assert_eq!(payload["ok"], false);
    assert!(payload["error"]
        .as_str()
        .unwrap_or("")
        .to_lowercase()
        .contains("directory"));

    // 3. --password-file exceeding 4 KiB cap MUST fail closed
    let big_pw_file = env.temp.path().join("big.pw");
    fs::write(&big_pw_file, vec![b'a'; 4097]).unwrap();
    let bad_big_out = env.run_cli(
        &[
            "vault",
            "export",
            "--output",
            env.temp.path().join("nope2.json").to_str().unwrap(),
            "--password-file",
            big_pw_file.to_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert!(!bad_big_out.status.success());
    let payload: Value = serde_json::from_slice(&bad_big_out.stdout).unwrap();
    assert_eq!(payload["ok"], false);
    assert!(payload["error"]
        .as_str()
        .unwrap_or("")
        .to_lowercase()
        .contains("maximum allowed size"));

    // 4. --password-stdin and --password-file are mutually exclusive
    let conflict = env.run_cli(
        &[
            "vault",
            "export",
            "--password-stdin",
            "--password-file",
            pw_file.to_str().unwrap(),
        ],
        None,
    );
    assert!(!conflict.status.success());

    // 5. Rule 11 Zero-Argv: --password in argv MUST be rejected fail-closed
    let argv_pw = env.run_cli(&["vault", "export", "--password", "leaked"], None);
    assert!(!argv_pw.status.success());

    // 6. Non-interactive encrypted_json without --password-stdin or --password-file fails closed
    let missing_pw = env.run_cli(
        &[
            "vault",
            "export",
            "--output",
            env.temp.path().join("nope3.json").to_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert!(!missing_pw.status.success());

    // 7. --password-file with account_encrypted_json fails closed
    let wrong_fmt_pw = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "account_encrypted_json",
            "--password-file",
            pw_file.to_str().unwrap(),
            "--json",
        ],
        None,
    );
    assert!(!wrong_fmt_pw.status.success());
}

#[test]
fn vault_export_account_encrypted_json_v1_0600_schema_and_exclusions() {
    let env = TestVaultEnv::new(true);
    let cwd_dir = env.temp.path().join("cwd-account-enc");
    fs::create_dir_all(&cwd_dir).unwrap();

    // Does NOT require --allow-plaintext and uses bitwarden_encrypted_export_YYYYMMDDHHMMSS.json
    let out = env.run_cli(
        &[
            "vault",
            "export",
            "--format",
            "account_encrypted_json",
            "--json",
        ],
        Some(&cwd_dir),
    );
    assert!(
        out.status.success(),
        "account_encrypted_json export failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );

    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["format"], "account_encrypted_json");
    assert_eq!(envelope["item_count"], 5);
    assert_eq!(envelope["folder_count"], 1);

    let out_name = envelope["output"].as_str().unwrap();
    assert!(out_name.starts_with("bitwarden_encrypted_export_") && out_name.ends_with(".json"));
    let written_path = cwd_dir.join(out_name);
    assert_eq!(
        fs::metadata(&written_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let doc: Value = serde_json::from_str(&fs::read_to_string(&written_path).unwrap()).unwrap();
    assert_eq!(doc["encrypted"], true);
    assert!(doc.get("passwordProtected").is_none());

    let user_key = SymmetricCryptoKey::from_raw_bytes(&[42u8; 64]).unwrap();
    let val_enc = EncString::parse(doc["encKeyValidation_DO_NOT_EDIT"].as_str().unwrap()).unwrap();
    assert_eq!(val_enc.enc_type, 2);
    let uuid = val_enc.decrypt_string(&user_key).unwrap();
    assert_eq!(uuid.len(), 36);

    // Folder remains encrypted under user_key
    assert_eq!(
        EncString::parse(doc["folders"][0]["name"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&user_key)
            .unwrap(),
        "Work"
    );

    let items = doc["items"].as_array().unwrap();
    assert_eq!(items.len(), 5);
    assert!(!items
        .iter()
        .any(|i| i["id"] == "88888888-8888-8888-8888-888888888888"));
    assert!(!items
        .iter()
        .any(|i| i["id"] == "99999999-9999-9999-9999-999999999999"));

    // Login preserves per-item key and excludes attachments
    assert!(items[0].get("attachments").is_none());
    let wrapped_item_key = EncString::parse(items[0]["key"].as_str().unwrap()).unwrap();
    let item_key =
        parse_symmetric_key_from_decrypted_bytes(&wrapped_item_key.decrypt(&user_key).unwrap())
            .unwrap();
    assert_eq!(
        EncString::parse(items[0]["login"]["password"].as_str().unwrap())
            .unwrap()
            .decrypt_string(&item_key)
            .unwrap(),
        "super-secret-login-pw"
    );
}

#[cfg(unix)]
fn run_cli_in_controlling_pty(
    env: &TestVaultEnv,
    args: &[&str],
    prompt_responses: &[(&str, &str)],
) -> (std::process::ExitStatus, String) {
    use std::ffi::CStr;
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::os::unix::process::CommandExt;

    let dir = env.temp.path();

    let (master_file, slave_in, slave_out, slave_err) = unsafe {
        use std::os::unix::fs::OpenOptionsExt;
        let master_fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master_fd >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master_fd), 0, "grantpt failed");
        assert_eq!(libc::unlockpt(master_fd), 0, "unlockpt failed");
        let name_ptr = libc::ptsname(master_fd);
        assert!(!name_ptr.is_null(), "ptsname failed");
        let slave_name = CStr::from_ptr(name_ptr).to_str().unwrap().to_string();
        let slave_a = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOCTTY)
            .open(&slave_name)
            .expect("open PTY slave");
        let slave_b = slave_a.try_clone().expect("clone PTY slave");
        let slave_c = slave_a.try_clone().expect("clone PTY slave");
        (fs::File::from_raw_fd(master_fd), slave_a, slave_b, slave_c)
    };

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
    cmd.args(args)
        .env_clear()
        .env("HOME", dir)
        .env("PATH", dir)
        .env("XDG_RUNTIME_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMA_KEYRING_PROVIDER", "secret-tool")
        .stdin(Stdio::from(slave_in))
        .stdout(Stdio::from(slave_out))
        .stderr(Stdio::from(slave_err));
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().unwrap();
    drop(cmd);

    let mut master_writer = master_file.try_clone().unwrap();
    let expected: Vec<(String, String)> = prompt_responses
        .iter()
        .map(|(p, r)| ((*p).to_string(), (*r).to_string()))
        .collect();

    let master_fd_raw = master_file.into_raw_fd();
    let reader_handle = thread::spawn(move || {
        let mut f = unsafe { fs::File::from_raw_fd(master_fd_raw) };
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        let mut next_idx = 0usize;
        let mut search_from = 0usize;
        loop {
            match f.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if next_idx < expected.len() {
                        let text = String::from_utf8_lossy(&buf);
                        if let Some(pos) = text[search_from..].find(&expected[next_idx].0) {
                            search_from += pos + expected[next_idx].0.len();
                            // Brief yield so rpassword finishes tcsetattr(TCSAFLUSH) before we write
                            thread::sleep(Duration::from_millis(25));
                            let _ = master_writer.write_all(expected[next_idx].1.as_bytes());
                            let _ = master_writer.flush();
                            next_idx += 1;
                        }
                    }
                }
                Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).replace("\r\n", "\n")
    });

    let status = child.wait().unwrap();
    let pty_output = reader_handle.join().unwrap();
    (status, pty_output)
}

#[cfg(unix)]
#[test]
fn vault_export_encrypted_json_interactive_tty_password_prompt_and_mismatch() {
    let env = TestVaultEnv::new(true);

    // 1. Mismatched password confirmation fails closed without writing output file
    let bad_file = env.temp.path().join("tty_mismatch.json");
    let (status_bad, out_bad) = run_cli_in_controlling_pty(
        &env,
        &["vault", "export", "--output", bad_file.to_str().unwrap()],
        &[
            ("Export password:", "first-secret\n"),
            ("Confirm export password:", "different-secret\n"),
        ],
    );
    assert!(!status_bad.success());
    assert!(
        out_bad.contains("do not match"),
        "expected mismatch error in PTY output, got: {out_bad}"
    );
    assert!(!bad_file.exists());

    // 2. Matching password confirmation succeeds and does NOT echo password to PTY
    let ok_file = env.temp.path().join("tty_encrypted.json");
    let (status_ok, out_ok) = run_cli_in_controlling_pty(
        &env,
        &["vault", "export", "--output", ok_file.to_str().unwrap()],
        &[
            ("Export password:", "tty-secret-pass\n"),
            ("Confirm export password:", "tty-secret-pass\n"),
        ],
    );
    assert!(
        status_ok.success(),
        "interactive encrypted_json export failed: out={out_ok}"
    );
    assert!(
        !out_ok.contains("tty-secret-pass"),
        "password must not be echoed to terminal output"
    );
    assert_eq!(
        fs::metadata(&ok_file).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let doc: Value = serde_json::from_str(&fs::read_to_string(&ok_file).unwrap()).unwrap();
    let export_key = derive_export_key(
        "tty-secret-pass",
        doc["salt"].as_str().unwrap(),
        &ExportKdfConfig::Pbkdf2Sha256 {
            iterations: 100_000,
        },
    )
    .unwrap();
    let inner_str = EncString::parse(doc["data"].as_str().unwrap())
        .unwrap()
        .decrypt_string(&export_key)
        .unwrap();
    let inner: Value = serde_json::from_str(&inner_str).unwrap();
    assert_eq!(inner["items"].as_array().unwrap().len(), 5);
}

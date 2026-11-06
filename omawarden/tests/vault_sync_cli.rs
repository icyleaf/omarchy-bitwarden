//! A lost daemon reply must not start an independent CLI cache writer.
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::{fs::PermissionsExt, net::UnixListener};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct Daemon(std::process::Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ipc(socket: &std::path::Path, request: Value) -> Value {
    let mut stream = std::os::unix::net::UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    writeln!(stream, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum LoginCase {
    WarmLock,
    WarmLockThenUnlock,
    ColdLock,
    ColdSuccess,
    WarmApiKey,
    ClipboardCleanupFailure,
    PreviewCleanupFailure,
    WarmPassword,
    LockAfterActivation,
    LostActivationReceipt,
    LostLiveActivationReceipt,
    LostRejectedReceipt,
}

struct DaemonSocket(std::path::PathBuf);
impl Drop for DaemonSocket {
    fn drop(&mut self) {
        if let Ok(mut stream) = std::os::unix::net::UnixStream::connect(&self.0) {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let _ = writeln!(stream, "{}", json!({"action":"stop"}));
            let mut reply = String::new();
            let _ = BufReader::new(stream).read_line(&mut reply);
        }
    }
}

struct ActivationProxy {
    runtime: tempfile::TempDir,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}

impl ActivationProxy {
    fn new(target: std::path::PathBuf, case: LoginCase) -> Self {
        use std::os::unix::net::UnixStream;

        let runtime = tempfile::tempdir().unwrap();
        let path = runtime.path().join("omawarden.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = Arc::clone(&stop);
        let worker = thread::spawn(move || {
            let relay = |from: &mut BufReader<UnixStream>, to: &mut UnixStream| {
                let mut line = String::new();
                assert_ne!(from.read_line(&mut line).unwrap(), 0);
                to.write_all(line.as_bytes()).unwrap();
                serde_json::from_str::<Value>(&line).unwrap()
            };
            while !done.load(Ordering::Relaxed) {
                let (client, _) = match listener.accept() {
                    Ok(client) => client,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                let daemon = UnixStream::connect(&target).unwrap();
                for stream in [&client, &daemon] {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(15)))
                        .unwrap();
                }
                let mut client = BufReader::new(client);
                let mut daemon = BufReader::new(daemon);
                let request = relay(&mut client, daemon.get_mut());
                relay(&mut daemon, client.get_mut());
                if request["action"] != "prepare_account_login" {
                    continue;
                }
                let activation = relay(&mut client, daemon.get_mut());
                assert_eq!(activation["action"], "activate_account");
                let mut receipt = String::new();
                assert_ne!(daemon.read_line(&mut receipt).unwrap(), 0);
                let reply: Value = serde_json::from_str(&receipt).unwrap();
                assert_eq!(reply["attempt_id"], activation["attempt_id"]);
                if case == LoginCase::LostRejectedReceipt {
                    assert_eq!(reply["outcome"], "rejected");
                } else {
                    assert_eq!(reply["outcome"], "committed");
                    if case == LoginCase::LostActivationReceipt {
                        assert_eq!(ipc(&target, json!({"action":"stop"}))["ok"], true);
                    }
                    if case == LoginCase::LockAfterActivation {
                        assert_eq!(ipc(&target, json!({"action":"lock"}))["ok"], true);
                    }
                    if matches!(
                        case,
                        LoginCase::LostActivationReceipt | LoginCase::LostLiveActivationReceipt
                    ) {
                        // Model a snapshot left after rename but before the
                        // daemon removes the candidate and acknowledges it.
                        let dir = target.parent().unwrap();
                        let id = activation["attempt_id"].as_str().unwrap();
                        std::fs::copy(
                            dir.join("data.json"),
                            dir.join("data.credentials").join(format!("{id}.candidate")),
                        )
                        .unwrap();
                    }
                }
                if case == LoginCase::LockAfterActivation {
                    client.get_mut().write_all(receipt.as_bytes()).unwrap();
                }
            }
        });
        Self {
            runtime,
            stop,
            worker: Some(worker),
        }
    }
}

impl Drop for ActivationProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn a_second_daemon_cannot_replace_the_live_login_authority() {
    use std::process::Stdio;
    use std::time::Instant;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let spawn = |runtime: &std::path::Path| {
        Daemon(
            Command::new(env!("CARGO_BIN_EXE_omawarden"))
                .arg("daemon")
                .env_clear()
                .env("HOME", root)
                .env("PATH", root)
                .env("XDG_RUNTIME_DIR", runtime)
                .env("OMAWARDEN_DATA_DIR", root)
                .env("OMAWARDEN_CONFIG_DIR", root)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        )
    };
    let _first = spawn(root);
    let socket = root.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        thread::sleep(Duration::from_millis(5));
    }
    let context = ipc(&socket, json!({"action":"ping"}))["unlock_context"].clone();
    let alternate_runtime = root.join("another-runtime");
    std::fs::create_dir(&alternate_runtime).unwrap();
    for runtime in [root, &alternate_runtime] {
        let mut duplicate = spawn(runtime);
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if let Some(status) = duplicate.0.try_wait().unwrap() {
                assert!(!status.success());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "duplicate daemon took over the live cache"
            );
            thread::sleep(Duration::from_millis(10));
        }
    }
    assert_eq!(
        ipc(&socket, json!({"action":"ping"}))["unlock_context"],
        context
    );
}

#[test]
fn legacy_cache_requires_sign_in_for_cli_and_daemon_unlock() {
    use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
    use std::process::Stdio;
    use std::time::Instant;

    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let cache = root.join("data.json");
    let server = "https://fixture.invalid";
    let email = "legacy@example.invalid";
    let master =
        derive_master_key(email, "fixture", KdfType::Pbkdf2Sha256, 100_000, None, None).unwrap();
    let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
        .encrypt(&[42; 64])
        .unwrap();
    let user_key = SymmetricCryptoKey::from_raw_bytes(&[42; 64]).unwrap();
    let legacy = json!({
        "server_url": server, "user_email": email, "enc_user_key": wrap,
        "kdf": 0, "kdf_iterations": 100_000,
        "ciphers": [{
            "id": "legacy-item", "type": 1, "name": user_key.encrypt_string("Legacy item").unwrap(),
            "login": {"password": user_key.encrypt_string("fixture secret").unwrap()}
        }]
    });
    std::fs::write(&cache, legacy.to_string()).unwrap();
    std::fs::write(
        root.join("config.json"),
        json!({"server_url":server}).to_string(),
    )
    .unwrap();
    for (program, script) in [
        ("secret-tool", "#!/bin/sh\necho fixture-legacy-token\n"),
        ("wl-copy", "#!/bin/sh\n/bin/cat >/dev/null\n"),
    ] {
        let path = root.join(program);
        std::fs::write(&path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let command = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        cmd.env_clear()
            .env("HOME", root)
            .env("PATH", root)
            .env("XDG_RUNTIME_DIR", root)
            .env("OMAWARDEN_DATA_DIR", root)
            .env("OMAWARDEN_CONFIG_DIR", root);
        cmd
    };
    let _daemon = Daemon(
        command()
            .arg("daemon")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let socket = root.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        thread::sleep(Duration::from_millis(5));
    }

    let run_with_password = |args: &[&str]| {
        let mut cli = command()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        writeln!(cli.stdin.take().unwrap(), "fixture").unwrap();
        let output = cli.wait_with_output().unwrap();
        (
            output.status.success(),
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
        )
    };

    let (cli_ok, cli) = run_with_password(&["auth", "unlock"]);
    ipc(&socket, json!({"action":"lock"}));
    let (copy_ok, copy) =
        run_with_password(&["copy", "legacy-item", "--password", "--timeout", "0"]);
    ipc(&socket, json!({"action":"lock"}));
    let (export_ok, export) = run_with_password(&["ssh-key", "export", "legacy-item", "--stdout"]);
    ipc(&socket, json!({"action":"lock"}));
    let daemon = ipc(&socket, json!({"action":"unlock","password":"fixture"}));
    let listed = ipc(&socket, json!({"action":"list"}));
    let locked = ipc(&socket, json!({"action":"ping"}))["unlocked"] == false;
    assert!(
        !cli_ok && !copy_ok && !export_ok && locked,
        "CLI unlock: {cli}; daemon unlock: {daemon}; copy ok: {copy_ok}; export ok: {export_ok}; locked: {locked}"
    );
    for reply in [cli, daemon, copy, export] {
        assert_eq!(reply["ok"], false);
        assert!(reply["error"].as_str().unwrap().contains("Sign in again"));
    }
    assert_eq!(listed["ok"], false, "locked IPC list returned {listed}");
    assert!(listed["error"]
        .as_str()
        .unwrap()
        .contains("Vault is locked"));
    assert_eq!(std::fs::read_to_string(&cache).unwrap(), legacy.to_string());

    // A scoped cache can still be read offline when the keyring is unavailable.
    let mut scoped = legacy;
    scoped["credential_id"] = json!("11111111111111111111111111111111");
    std::fs::write(&cache, scoped.to_string()).unwrap();
    std::fs::remove_file(root.join("secret-tool")).unwrap();
    let (ok, result) = run_with_password(&["auth", "unlock"]);
    assert!(ok, "{result}");
    let status = ipc(&socket, json!({"action":"status"}));
    assert_eq!(status["is_unlocked"], true);
    assert_eq!(status["has_session"], false);
    assert_eq!(
        ipc(&socket, json!({"action":"list"}))[0]["id"],
        "legacy-item"
    );
}

#[test]
fn locking_during_password_login_cancels_the_late_snapshot_and_auto_unlock() {
    password_login_case(LoginCase::WarmLock);
}

#[test]
fn cold_password_login_starts_the_daemon_and_auto_unlocks() {
    password_login_case(LoginCase::ColdSuccess);
}

#[test]
fn locking_a_cold_login_does_not_allow_late_auto_unlock() {
    password_login_case(LoginCase::ColdLock);
}

#[test]
fn apikey_login_revokes_the_previous_accounts_unlocked_index() {
    password_login_case(LoginCase::WarmApiKey);
}

#[test]
fn activation_retains_the_previous_account_when_output_cleanup_fails() {
    for case in [
        LoginCase::ClipboardCleanupFailure,
        LoginCase::PreviewCleanupFailure,
    ] {
        password_login_case(case);
    }
}

#[test]
fn password_login_auto_unlocks_only_the_new_account() {
    password_login_case(LoginCase::WarmPassword);
}

#[test]
fn locking_and_reopening_the_old_account_cancels_a_prepared_login() {
    password_login_case(LoginCase::WarmLockThenUnlock);
}

#[test]
fn a_lock_after_activation_wins_over_password_auto_unlock() {
    password_login_case(LoginCase::LockAfterActivation);
}

#[test]
fn a_lost_activation_receipt_confirms_the_new_account_without_unlocking() {
    password_login_case(LoginCase::LostActivationReceipt);
}

#[test]
fn a_live_daemon_with_a_lost_receipt_leaves_the_new_account_locked() {
    password_login_case(LoginCase::LostLiveActivationReceipt);
}

#[test]
fn a_lost_rejection_keeps_the_attempt_for_safe_cleanup() {
    password_login_case(LoginCase::LostRejectedReceipt);
}

fn password_login_case(case: LoginCase) {
    use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
    use std::process::Stdio;
    use std::time::Instant;
    let dir = tempfile::tempdir().unwrap();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    api.set_nonblocking(true).unwrap();
    let url = format!("http://{}", api.local_addr().unwrap());
    let old_email = "fixture@example.invalid";
    let email = "other@example.invalid";
    let wrap_key = |email: &str, bytes: &[u8; 64]| {
        let master =
            derive_master_key(email, "fixture", KdfType::Pbkdf2Sha256, 100_000, None, None)
                .unwrap();
        SymmetricCryptoKey::from_master_key(master.as_slice())
            .encrypt(bytes)
            .unwrap()
    };
    let old_wrap = wrap_key(old_email, &[42; 64]);
    let wrap = wrap_key(email, &[43; 64]);
    let new_key = SymmetricCryptoKey::from_raw_bytes(&[43; 64]).unwrap();
    let new_name = new_key.encrypt_string("New account item").unwrap();
    let cache = dir.path().join("data.json");
    let mut original = json!({"server_url":url,"user_email":old_email,"user_id":"fixture","enc_user_key":old_wrap,"kdf":0,"kdf_iterations":100_000});
    let cleanup_failure = matches!(
        case,
        LoginCase::ClipboardCleanupFailure | LoginCase::PreviewCleanupFailure
    );
    let api_key = case == LoginCase::WarmApiKey || cleanup_failure;
    let warm = !matches!(case, LoginCase::ColdLock | LoginCase::ColdSuccess);
    if api_key {
        original["server_url"] = json!("https://old-vault.fixture.invalid");
    }
    if warm {
        original["credential_id"] = json!("11111111111111111111111111111111");
        let key = SymmetricCryptoKey::from_raw_bytes(&[42; 64]).unwrap();
        original["ciphers"] = json!([
            {"id":"old-only", "type":1, "name":key.encrypt_string("Previous account item").unwrap()}
        ]);
    }
    std::fs::write(&cache, original.to_string()).unwrap();
    std::fs::write(
        dir.path().join("config.json"),
        json!({"server_url":url}).to_string(),
    )
    .unwrap();
    let keyring = dir.path().join("secret-tool");
    std::fs::write(&keyring, "#!/bin/sh\ncase \"$*\" in\nlookup*'kind access_token'*) echo fixture-token;;\nstore*) read value; exit 0;;\n*) exit 1;;\nesac\n").unwrap();
    std::fs::set_permissions(&keyring, std::fs::Permissions::from_mode(0o700)).unwrap();
    if api_key {
        let clipboard = dir.path().join("wl-copy");
        std::fs::write(
            &clipboard,
            "#!/bin/sh\nselection=\"$XDG_RUNTIME_DIR/selection\"\nif [ \"${1:-}\" = --clear ]; then\n  [ -e \"$XDG_RUNTIME_DIR/fail-clear\" ] && exit 1\n  exec /usr/bin/rm -f \"$selection\"\nfi\nexec /usr/bin/cat > \"$selection\"\n",
        )
        .unwrap();
        std::fs::set_permissions(clipboard, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let command = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        cmd.env_clear()
            .env("HOME", dir.path())
            .env("PATH", dir.path())
            .env("XDG_RUNTIME_DIR", dir.path())
            .env("OMAWARDEN_DATA_DIR", dir.path())
            .env("OMAWARDEN_CONFIG_DIR", dir.path());
        cmd
    };
    let socket = dir.path().join("omawarden.sock");
    let _shutdown = DaemonSocket(socket.clone());
    let deadline = Instant::now() + Duration::from_secs(15);
    let start_daemon = || {
        let daemon = Daemon(
            command()
                .arg("daemon")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        while !socket.exists() {
            assert!(Instant::now() < deadline, "daemon did not start");
            thread::sleep(Duration::from_millis(5));
        }
        daemon
    };
    let mut daemon = if warm {
        let daemon = start_daemon();
        assert_eq!(
            ipc(&socket, json!({"action":"unlock","password":"fixture"}))["ok"],
            true
        );
        assert_eq!(ipc(&socket, json!({"action":"list"}))[0]["id"], "old-only");
        Some(daemon)
    } else {
        assert!(!socket.exists());
        None
    };
    let pending_copy = if api_key {
        let status = ipc(&socket, json!({"action":"status"}));
        let generation = status["lock_generation"].as_str().unwrap();
        let spawn_copy = || {
            command()
                .env("WAYLAND_DISPLAY", "fixture-wayland")
                .args([
                    "copy",
                    "--stdin",
                    "--sensitive",
                    "--timeout",
                    "0",
                    "--expected-lock-generation",
                    generation,
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap()
        };
        let mut initial = spawn_copy();
        writeln!(initial.stdin.take().unwrap(), "fixture-old").unwrap();
        assert!(initial.wait_with_output().unwrap().status.success());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("selection")).unwrap(),
            "fixture-old"
        );
        let previews = dir.path().join(
            "omarchy-bitwarden/scoped-attachments/11111111111111111111111111111111/old-only/attachment",
        );
        std::fs::create_dir_all(&previews).unwrap();
        std::fs::write(previews.join("old-preview.txt"), "fixture-old").unwrap();
        match case {
            LoginCase::ClipboardCleanupFailure => {
                std::fs::write(dir.path().join("fail-clear"), "").unwrap();
                None
            }
            LoginCase::PreviewCleanupFailure => {
                // A regular file where the legacy preview directory should
                // be makes remove_dir_all fail even as root.
                std::fs::write(dir.path().join("omarchy-bitwarden/attachments"), "").unwrap();
                None
            }
            _ => Some(spawn_copy()),
        }
    } else {
        None
    };
    let mut old_context = None;
    let before = std::fs::read(&cache).unwrap();
    let proxy = matches!(
        case,
        LoginCase::LockAfterActivation
            | LoginCase::LostActivationReceipt
            | LoginCase::LostLiveActivationReceipt
            | LoginCase::LostRejectedReceipt
    )
    .then(|| ActivationProxy::new(socket.clone(), case));
    let args = if api_key {
        ["auth", "login-apikey", "--client-id", "user.other"]
    } else {
        ["auth", "login-password", "--email", email]
    };
    let mut login_command = command();
    if let Some(proxy) = &proxy {
        login_command.env("XDG_RUNTIME_DIR", proxy.runtime.path());
    }
    let mut login = login_command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(login.stdin.take().unwrap(), "fixture").unwrap();
    loop {
        let mut stream = match api.accept() {
            Ok((stream, _)) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "login did not send sync");
                thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut reader = BufReader::new(&mut stream);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let path = line.split_whitespace().nth(1).unwrap().to_string();
        let mut size = 0;
        loop {
            line.clear();
            assert_ne!(reader.read_line(&mut line).unwrap(), 0);
            if line == "\r\n" {
                break;
            }
            if let Some(length) = line.to_lowercase().strip_prefix("content-length:") {
                size = length.trim().parse().unwrap();
            }
        }
        reader.read_exact(&mut vec![0; size]).unwrap();
        let synced = path == "/api/sync";
        let body = if synced {
            assert!(socket.exists(), "login_password must start the daemon before sampling its context");
            old_context = Some(ipc(&socket, json!({"action":"ping"}))["unlock_context"].clone());
            if matches!(case, LoginCase::WarmLock | LoginCase::ColdLock | LoginCase::WarmLockThenUnlock | LoginCase::LostRejectedReceipt) {
                assert_eq!(ipc(&socket, json!({"action":"lock"}))["ok"], true);
            }
            if case == LoginCase::WarmLockThenUnlock {
                assert_eq!(ipc(&socket, json!({"action":"unlock","password":"fixture"}))["ok"], true);
            }
            json!({"ciphers":[{"id":"new-only","type":1,"name":new_name}],
                   "profile":{"id":"other-account","email":email}})
        } else if path.ends_with("/connect/token") {
            json!({"access_token":"new", "expires_in":3600,"key":wrap,"kdf":0,"kdf_iterations":100_000})
        } else {
            assert!(path.ends_with("/prelogin"), "{path}");
            json!({"kdf":0,"kdfIterations":100_000})
        }.to_string();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        if synced {
            break;
        }
    }
    let output = login.wait_with_output().unwrap();
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    if case == LoginCase::LostActivationReceipt {
        assert!(daemon.as_mut().unwrap().0.wait().unwrap().success());
        if socket.exists() {
            std::fs::remove_file(&socket).unwrap();
        }
        daemon = Some(start_daemon());
    }
    let success = !cleanup_failure
        && !matches!(
            case,
            LoginCase::WarmLock
                | LoginCase::ColdLock
                | LoginCase::WarmLockThenUnlock
                | LoginCase::LostRejectedReceipt
        );
    assert_eq!(output.status.success(), success, "{result}");
    assert_eq!(result["ok"], success);
    let unlocked = cleanup_failure
        || matches!(
            case,
            LoginCase::ColdSuccess | LoginCase::WarmPassword | LoginCase::WarmLockThenUnlock
        );
    assert_eq!(ipc(&socket, json!({"action":"ping"}))["unlocked"], unlocked);
    if success {
        assert_eq!(
            result["status"],
            if unlocked { "unlocked" } else { "locked" }
        );
        assert!(
            serde_json::from_slice::<Value>(&std::fs::read(&cache).unwrap()).unwrap()["last_sync"]
                .is_string()
        );
        let status = ipc(&socket, json!({"action":"status"}));
        assert_eq!(status["user_id"], "other-account");
        assert_eq!(status["server_url"], url);
        assert_eq!(status["is_unlocked"], unlocked);
        if let Some(mut copy) = pending_copy {
            let selection = dir.path().join("selection");
            assert!(
                !selection.exists(),
                "activation left the old selection available"
            );
            assert!(!dir
                .path()
                .join("omarchy-bitwarden/scoped-attachments")
                .exists());
            writeln!(copy.stdin.take().unwrap(), "late-old-copy").unwrap();
            assert!(!copy.wait_with_output().unwrap().status.success());
            assert!(
                !selection.exists(),
                "the old helper replaced the cleared selection"
            );
        }
        if matches!(
            case,
            LoginCase::LostActivationReceipt | LoginCase::LostLiveActivationReceipt
        ) {
            let id = status["credential_id"].as_str().unwrap();
            assert!(!dir
                .path()
                .join("data.credentials")
                .join(format!("{id}.candidate"))
                .exists());
        }
        if unlocked {
            let list = ipc(&socket, json!({"action":"list"}));
            assert_eq!(list.as_array().unwrap().len(), 1);
            assert_eq!(list[0]["id"], "new-only");
        } else {
            assert_eq!(ipc(&socket, json!({"action":"list"}))["ok"], false);
        }
    } else {
        assert_eq!(std::fs::read(&cache).unwrap(), before);
        if cleanup_failure {
            assert_eq!(
                ipc(&socket, json!({"action":"ping"}))["unlock_context"],
                old_context.unwrap()
            );
            let error = result["error"].as_str().unwrap();
            let expected = if case == LoginCase::ClipboardCleanupFailure {
                assert!(dir.path().join("selection").exists());
                "Wayland clipboard cleanup failed"
            } else {
                assert!(!dir.path().join("selection").exists());
                "Attachment preview cleanup failed"
            };
            assert!(error.contains(expected), "{error}");
            assert!(!std::fs::read_dir(dir.path().join("data.credentials"))
                .unwrap()
                .any(|entry| {
                    entry
                        .unwrap()
                        .path()
                        .extension()
                        .is_some_and(|ext| ext == "candidate")
                }));
        } else {
            assert_eq!(
                ipc(
                    &socket,
                    json!({"action":"unlock","password":"fixture","expected_unlock_context":old_context.unwrap()})
                )["ok"],
                false
            );
        }
        if cleanup_failure || case == LoginCase::WarmLockThenUnlock {
            assert_eq!(ipc(&socket, json!({"action":"list"}))[0]["id"], "old-only");
        }
        if case == LoginCase::LostRejectedReceipt {
            assert!(result["error"]
                .as_str()
                .unwrap()
                .contains("Could not confirm sign-in"));
            let candidates: Vec<_> = std::fs::read_dir(dir.path().join("data.credentials"))
                .unwrap()
                .map(|entry| entry.unwrap().path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "candidate"))
                .collect();
            assert_eq!(candidates.len(), 1);
            assert!(candidates[0].with_extension("").is_file());
        }
    }
    drop(daemon);
}

#[test]
fn missing_or_malformed_sync_receipts_never_start_a_local_sync() {
    for disconnect_before_sync in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let api = TcpListener::bind("127.0.0.1:0").unwrap();
        api.set_nonblocking(true).unwrap();
        let storage = dir.path().join("data.json");
        let before = json!({
            "server_url":format!("http://{}", api.local_addr().unwrap()),
            "credential_id":"11111111111111111111111111111111",
            "access_token":"fixture", "ciphers":[{"id":"retained"}]
        })
        .to_string();
        std::fs::write(&storage, &before).unwrap();
        let socket = dir.path().join("omawarden.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).unwrap();
        let daemon = thread::spawn(move || {
            let (mut ping, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(ping.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert_eq!(
                serde_json::from_str::<Value>(&line).unwrap()["action"],
                "ping"
            );
            if disconnect_before_sync {
                std::fs::remove_file(&socket).unwrap();
            }
            writeln!(
                ping,
                "{}",
                json!({"ok":true, "unlocked":true, "commit":"old"})
            )
            .unwrap();
            if !disconnect_before_sync {
                let (mut sync, _) = listener.accept().unwrap();
                line.clear();
                BufReader::new(sync.try_clone().unwrap())
                    .read_line(&mut line)
                    .unwrap();
                assert_eq!(
                    serde_json::from_str::<Value>(&line).unwrap()["action"],
                    "sync"
                );
                writeln!(sync, "{{").unwrap();
            }
        });
        let stop = Arc::new(AtomicBool::new(false));
        let gets = Arc::new(AtomicUsize::new(0));
        let api_stop = Arc::clone(&stop);
        let api_gets = Arc::clone(&gets);
        let api_task = thread::spawn(move || {
            while !api_stop.load(Ordering::SeqCst) {
                match api.accept() {
                    Ok((mut stream, _)) => {
                        stream
                            .set_read_timeout(Some(Duration::from_secs(5)))
                            .unwrap();
                        let _ = stream.read(&mut [0; 4096]);
                        api_gets.fetch_add(1, Ordering::SeqCst);
                        let body = "{\"ciphers\":[]}";
                        write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => panic!("{e}"),
                }
            }
        });
        let output = Command::new(env!("CARGO_BIN_EXE_omawarden"))
            .args(["vault", "sync"])
            .env_clear()
            .env("HOME", dir.path())
            .env("PATH", dir.path())
            .env("XDG_RUNTIME_DIR", dir.path())
            .env("OMAWARDEN_DATA_DIR", dir.path())
            .env("OMAWARDEN_CONFIG_DIR", dir.path())
            .output()
            .unwrap();
        stop.store(true, Ordering::SeqCst);
        api_task.join().unwrap();
        daemon.join().unwrap();
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(!output.status.success(), "{result}");
        assert_eq!(result["ok"], false);
        assert_eq!(gets.load(Ordering::SeqCst), 0);
        assert_eq!(std::fs::read_to_string(&storage).unwrap(), before);
    }
}

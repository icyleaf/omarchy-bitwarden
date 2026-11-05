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
    ColdLock,
    ColdSuccess,
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

fn password_login_case(case: LoginCase) {
    use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
    use std::process::Stdio;
    use std::time::Instant;
    let dir = tempfile::tempdir().unwrap();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    api.set_nonblocking(true).unwrap();
    let url = format!("http://{}", api.local_addr().unwrap());
    let email = "fixture@example.invalid";
    let master =
        derive_master_key(email, "fixture", KdfType::Pbkdf2Sha256, 100_000, None, None).unwrap();
    let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
        .encrypt(&[42; 64])
        .unwrap();
    let cache = dir.path().join("data.json");
    std::fs::write(&cache, json!({"server_url":url,"user_email":email,"user_id":"fixture","enc_user_key":wrap,"kdf":0,"kdf_iterations":100_000}).to_string()).unwrap();
    std::fs::write(
        dir.path().join("config.json"),
        json!({"server_url":url}).to_string(),
    )
    .unwrap();
    let keyring = dir.path().join("secret-tool");
    std::fs::write(&keyring, "#!/bin/sh\ncase \"$*\" in\nlookup*'kind access_token'*) echo fixture-token;;\nstore*) read value; exit 0;;\n*) exit 1;;\nesac\n").unwrap();
    std::fs::set_permissions(&keyring, std::fs::Permissions::from_mode(0o700)).unwrap();
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
    let _daemon = if case == LoginCase::WarmLock {
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
        assert_eq!(
            ipc(&socket, json!({"action":"unlock","password":"fixture"}))["ok"],
            true
        );
        Some(daemon)
    } else {
        assert!(!socket.exists());
        None
    };
    let mut old_context = None;
    let before = std::fs::read(&cache).unwrap();
    let mut login = command()
        .args(["auth", "login-password", "--email", email])
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
            if case != LoginCase::ColdSuccess {
                assert_eq!(ipc(&socket, json!({"action":"lock"}))["ok"], true);
            }
            json!({"ciphers":[]})
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
    let success = case == LoginCase::ColdSuccess;
    assert_eq!(output.status.success(), success, "{result}");
    assert_eq!(result["ok"], success);
    assert_eq!(ipc(&socket, json!({"action":"ping"}))["unlocked"], success);
    if success {
        assert_eq!(result["status"], "unlocked");
        assert!(
            serde_json::from_slice::<Value>(&std::fs::read(&cache).unwrap()).unwrap()["last_sync"]
                .is_string()
        );
    } else {
        assert_eq!(std::fs::read(&cache).unwrap(), before);
        assert_eq!(
            ipc(
                &socket,
                json!({"action":"unlock","password":"fixture","expected_unlock_context":old_context.unwrap()})
            )["ok"],
            false
        );
    }
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

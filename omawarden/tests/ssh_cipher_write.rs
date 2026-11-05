//! Real CLI + daemon, with synthetic encrypted storage and a loopback API.
//! Hold or truncate the server reply to force the otherwise timing-sensitive paths.
use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::{fs::PermissionsExt, net::UnixStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

struct Daemon(Child);
impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn ipc(socket: &Path, request: Value) -> Value {
    let mut stream = UnixStream::connect(socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    writeln!(stream, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    serde_json::from_str(&line).unwrap()
}

fn read_request(stream: &mut TcpStream) -> (String, Vec<u8>) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let path = line.split_whitespace().nth(1).unwrap().to_owned();
    let mut size = 0;
    loop {
        line.clear();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        if line == "\r\n" {
            break;
        }
        if let Some(value) = line.to_lowercase().strip_prefix("content-length:") {
            size = value.trim().parse().unwrap();
        }
    }
    let mut body = vec![0; size];
    reader.read_exact(&mut body).unwrap();
    (path, body)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Case {
    Save,
    SlowKeyring,
    Renew401,
    LockCycle,
    LegacyProfile,
    KeyringFailure,
    Lock,
    BadReceipt,
    Forbidden,
    Redirect,
    AccountChange,
}

fn exercise(case: Case) {
    let temp = tempfile::tempdir().unwrap();
    let dir = temp.path();
    let api = TcpListener::bind("127.0.0.1:0").unwrap();
    api.set_nonblocking(true).unwrap();
    let server_url = format!("http://{}", api.local_addr().unwrap());
    let keyring = dir.join("secret-tool");
    let keyring_actions = match case {
        Case::SlowKeyring => {
            r#"lookup*'kind refresh_token'*) echo fixture-refresh;;
store*) : > "$HOME/storing"; n=0; while ! test -e "$HOME/release"; do n=$((n+1)); [ "$n" -lt 1200 ] || exit 1; /bin/sleep 0.01; done; /bin/cat >/dev/null;;"#
        }
        Case::KeyringFailure => "lookup*'kind refresh_token'*) echo fixture-refresh;;",
        Case::Renew401 => "lookup*) echo fixture-token;; store*) /bin/cat >/dev/null;;",
        Case::LegacyProfile => "lookup*'kind access_token'*) echo x.eyJzdWIiOiJ1c2VyLWlkIn0.x;;",
        _ => "lookup*'kind access_token'*) echo fixture-token;;",
    };
    fs::write(
        &keyring,
        format!("#!/bin/sh\ncase \"$*\" in\n{keyring_actions}\n*) exit 1;;\nesac\n"),
    )
    .unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();

    let email = "user@fixture.invalid";
    let master =
        derive_master_key(email, "fixture", KdfType::Pbkdf2Sha256, 100_000, None, None).unwrap();
    let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
        .encrypt(&[42; 64])
        .unwrap();
    let cache = dir.join("data.json");
    let mut data = json!({
        "user_id": "user-id", "user_email": email, "server_url": server_url,
        "enc_user_key": wrap, "kdf": 0, "kdf_iterations": 100_000
    });
    if case == Case::LegacyProfile {
        data.as_object_mut().unwrap().remove("user_id");
    }
    fs::write(&cache, data.to_string()).unwrap();
    let command = || {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        cmd.env_clear()
            .env("HOME", dir)
            .env("PATH", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir);
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
    let socket = dir.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(25);
    while !socket.exists() {
        assert!(Instant::now() < deadline, "daemon did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        ipc(&socket, json!({"action":"unlock","password":"fixture"}))["ok"],
        true
    );
    if case == Case::Save {
        let legacy = ipc(&socket, json!({"action":"ssh_key_create"}));
        assert_eq!(legacy["outcome"], "rejected");
    }
    let mut cli = command()
        .args(["ssh-key", "create", "--name", "test-key"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    // This used to authorize a second, local POST after a lost daemon receipt.
    writeln!(cli.stdin.take().unwrap(), "fixture").unwrap();
    let mut posts = 0;
    let mut grants = 0;
    while cli.try_wait().unwrap().is_none() {
        assert!(Instant::now() < deadline, "CLI did not finish");
        if case == Case::SlowKeyring
            && dir.join("storing").exists()
            && !dir.join("release").exists()
        {
            // A lock must complete while secret-tool is still waiting.
            let locked = ipc(&socket, json!({"action":"lock"}));
            fs::write(dir.join("release"), "").unwrap();
            assert_eq!(locked["ok"], true);
        }
        let (mut stream, _) = match api.accept() {
            Ok(stream) => stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(5));
                continue;
            }
            Err(e) => panic!("{e}"),
        };
        let (path, body) = read_request(&mut stream);
        let mut headers = String::new();
        let (status, reply) = if path.ends_with("/connect/token") {
            grants += 1;
            (
                "200 OK",
                json!({"access_token":"new","refresh_token":"refresh","expires_in":3600})
                    .to_string(),
            )
        } else {
            assert_eq!(path, "/api/ciphers");
            posts += 1;
            let mut cipher: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(cipher["encryptedFor"], "user-id");
            assert!(cipher["sshKey"]["privateKey"]
                .as_str()
                .unwrap()
                .starts_with("2."));
            cipher["id"] = json!("created");
            cipher["revisionDate"] = json!("2026-01-01T00:00:00Z");
            match case {
                Case::Renew401 if posts == 1 => ("401 Unauthorized", "{}".into()),
                Case::Forbidden => ("403 Forbidden", "{}".into()),
                Case::Redirect => {
                    headers = format!("Location: {server_url}/api/ciphers\r\n");
                    ("307 Temporary Redirect", "".into())
                }
                Case::BadReceipt => ("200 OK", "{".into()),
                Case::Lock | Case::LockCycle => {
                    assert_eq!(ipc(&socket, json!({"action":"lock"}))["ok"], true);
                    if case == Case::LockCycle {
                        assert_eq!(
                            ipc(&socket, json!({"action":"unlock","password":"fixture"}))["ok"],
                            true
                        );
                    }
                    ("200 OK", cipher.to_string())
                }
                Case::AccountChange => {
                    fs::write(
                        &cache,
                        json!({"user_id":"other","server_url":"https://other.invalid"}).to_string(),
                    )
                    .unwrap();
                    ("200 OK", cipher.to_string())
                }
                _ => ("200 OK", cipher.to_string()),
            }
        };
        write!(
            stream,
            "HTTP/1.1 {status}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n{reply}",
            reply.len()
        )
        .unwrap();
    }
    let out = cli.wait_with_output().unwrap();
    let receipt: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        grants,
        usize::from(matches!(
            case,
            Case::KeyringFailure | Case::Renew401 | Case::SlowKeyring
        ))
    );
    assert_eq!(
        posts,
        usize::from(!matches!(case, Case::KeyringFailure | Case::SlowKeyring))
            + usize::from(case == Case::Renew401)
    );
    let expected = match case {
        Case::Save | Case::Renew401 | Case::LegacyProfile => "saved",
        Case::AccountChange | Case::Lock | Case::LockCycle => "saved_needs_sync",
        Case::Forbidden | Case::KeyringFailure | Case::SlowKeyring => "rejected",
        Case::BadReceipt | Case::Redirect => "unknown",
    };
    assert_eq!(receipt["outcome"], expected, "{receipt}");
    assert_eq!(out.status.success(), expected.starts_with("saved"));
    if out.status.success() {
        assert_eq!(
            receipt["item"],
            json!({"id":"created","revisionDate":"2026-01-01T00:00:00Z"})
        );
    }
    if matches!(case, Case::Lock | Case::KeyringFailure) {
        assert_eq!(ipc(&socket, json!({"action":"ping"}))["unlocked"], false);
    }
    let disk: Value = serde_json::from_str(&fs::read_to_string(cache).unwrap()).unwrap();
    assert_eq!(
        disk["ciphers"].as_array().map_or(0, Vec::len),
        usize::from(expected == "saved")
    );
    if case == Case::Save {
        assert_eq!(
            ipc(&socket, json!({"action":"list"}))[0]["name"],
            "test-key"
        );
    }
}

#[test]
fn confirmed_write_returns_only_metadata() {
    exercise(Case::Save);
}
#[test]
fn keyring_failure_prevents_dispatch() {
    exercise(Case::KeyringFailure);
}
#[test]
fn late_receipt_does_not_repopulate_locked_vault() {
    exercise(Case::Lock);
}
#[test]
fn a_new_account_rejects_an_old_receipt() {
    exercise(Case::AccountChange);
}
#[test]
fn malformed_receipt_is_not_replayed() {
    exercise(Case::BadReceipt);
}
#[test]
fn forbidden_is_not_retried_as_authentication() {
    exercise(Case::Forbidden);
}
#[test]
fn redirects_do_not_replay_post() {
    exercise(Case::Redirect);
}

#[test]
fn stale_credentials_allow_one_confirmed_401_retry() {
    exercise(Case::Renew401);
}
#[test]
fn a_full_lock_cycle_invalidates_an_inflight_receipt() {
    exercise(Case::LockCycle);
}
#[test]
fn legacy_profile_uses_subject_from_scoped_access_token() {
    exercise(Case::LegacyProfile);
}

#[test]
fn waiting_on_secret_service_does_not_block_lock() {
    exercise(Case::SlowKeyring);
}

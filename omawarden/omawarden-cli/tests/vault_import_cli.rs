//! End-to-end CLI ↔ Resident Daemon ↔ Loopback Mock Server integration tests
//! for `omawarden vault import` (#484).

use omawarden_engine::api::decrypt_cipher_string;
use omawarden_engine::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};
use omawarden_engine::vault_import::MAX_IMPORT_FILE_BYTES;
use serde_json::{json, Value};
use std::fs;
use std::io::{BufRead, BufReader, ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::unix::{
    fs::PermissionsExt,
    net::{UnixListener, UnixStream},
    process::CommandExt,
};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
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

#[derive(Default)]
struct MockServerState {
    folders: Vec<Value>,
    ciphers: Vec<Value>,
    import_requests: Vec<Value>,
    import_calls: usize,
    sync_calls: usize,
    token_refresh_calls: usize,
    fail_first_import_with_401: bool,
    validation_error_response: Option<String>,
}

struct MockBitwardenServer {
    base_url: String,
    state: Arc<Mutex<MockServerState>>,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl Drop for MockBitwardenServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.base_url.trim_start_matches("http://"));
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn read_http_request(stream: &mut TcpStream) -> Option<(String, String, Vec<u8>)> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut req_line = String::new();
    if reader.read_line(&mut req_line).ok()? == 0 {
        return None;
    }
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return None;
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

    let mut content_length: usize = 0;
    loop {
        let mut hdr = String::new();
        if reader.read_line(&mut hdr).ok()? == 0 {
            break;
        }
        let trimmed = hdr.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }

    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    Some((method, path, body))
}

fn write_http_response(stream: &mut TcpStream, status: u16, reason: &str, body: &str) {
    let resp = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

impl MockBitwardenServer {
    fn start(initial_folders: Vec<Value>, initial_ciphers: Vec<Value>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();

        let state = Arc::new(Mutex::new(MockServerState {
            folders: initial_folders,
            ciphers: initial_ciphers,
            ..Default::default()
        }));
        let stop = Arc::new(AtomicBool::new(false));
        let next_id = Arc::new(AtomicUsize::new(100));

        let s_clone = Arc::clone(&state);
        let stop_clone = Arc::clone(&stop);
        let handle = thread::spawn(move || {
            while !stop_clone.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_nonblocking(false);
                        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                        let Some((method, path, body)) = read_http_request(&mut stream) else {
                            continue;
                        };
                        let mut st = s_clone.lock().unwrap();
                        if method == "POST" && path == "/api/ciphers/import" {
                            st.import_calls += 1;
                            if st.fail_first_import_with_401 && st.import_calls == 1 {
                                write_http_response(
                                    &mut stream,
                                    401,
                                    "Unauthorized",
                                    r#"{"error":"expired_token"}"#,
                                );
                                continue;
                            }
                            if let Some(err_json) = st.validation_error_response.clone() {
                                write_http_response(&mut stream, 400, "Bad Request", &err_json);
                                continue;
                            }
                            let payload: Value = serde_json::from_slice(&body).unwrap();
                            st.import_requests.push(payload.clone());

                            let mut created_folder_ids = Vec::new();
                            if let Some(folders) = payload.get("folders").and_then(Value::as_array)
                            {
                                for f in folders {
                                    let fid = format!(
                                        "imported-folder-{}",
                                        next_id.fetch_add(1, Ordering::SeqCst)
                                    );
                                    created_folder_ids.push(fid.clone());
                                    st.folders.push(json!({
                                        "id": fid,
                                        "name": f["name"],
                                    }));
                                }
                            }

                            let mut rel_map = std::collections::HashMap::new();
                            if let Some(rels) =
                                payload.get("folderRelationships").and_then(Value::as_array)
                            {
                                for r in rels {
                                    if let (Some(k), Some(v)) =
                                        (r["key"].as_u64(), r["value"].as_u64())
                                    {
                                        if let Some(fid) = created_folder_ids.get(v as usize) {
                                            rel_map.insert(k as usize, fid.clone());
                                        }
                                    }
                                }
                            }

                            if let Some(ciphers) = payload.get("ciphers").and_then(Value::as_array)
                            {
                                for (idx, c) in ciphers.iter().enumerate() {
                                    let mut stored = c.clone();
                                    let cid = format!(
                                        "imported-cipher-{}",
                                        next_id.fetch_add(1, Ordering::SeqCst)
                                    );
                                    stored["id"] = json!(cid);
                                    if let Some(fid) = rel_map.get(&idx) {
                                        stored["folderId"] = json!(fid);
                                    }
                                    st.ciphers.push(stored);
                                }
                            }

                            write_http_response(&mut stream, 200, "OK", "");
                        } else if method == "GET" && path.starts_with("/api/sync") {
                            st.sync_calls += 1;
                            let sync_body = json!({
                                "profile": {
                                    "id": "user-1",
                                    "email": "import@fixture.invalid",
                                    "organizations": []
                                },
                                "folders": st.folders,
                                "collections": [],
                                "ciphers": st.ciphers,
                            });
                            write_http_response(
                                &mut stream,
                                200,
                                "OK",
                                &serde_json::to_string(&sync_body).unwrap(),
                            );
                        } else if method == "POST" && path == "/identity/connect/token" {
                            st.token_refresh_calls += 1;
                            write_http_response(
                                &mut stream,
                                200,
                                "OK",
                                r#"{"access_token":"renewed-access-token","refresh_token":"fixture-refresh-token","expires_in":3600,"token_type":"Bearer"}"#,
                            );
                        } else {
                            write_http_response(
                                &mut stream,
                                404,
                                "Not Found",
                                r#"{"error":"not_found"}"#,
                            );
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            base_url: format!("http://{addr}"),
            state,
            stop,
            handle: Some(handle),
        }
    }
}

struct TestImportEnv {
    temp: tempfile::TempDir,
    user_key: SymmetricCryptoKey,
    server: MockBitwardenServer,
    _daemon: DaemonGuard,
}

impl TestImportEnv {
    fn new(unlock: bool) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path();

        let keyring = dir.join("secret-tool");
        fs::write(
            &keyring,
            "#!/bin/sh\ncase \"$*\" in\nlookup*'kind access_token'*) echo fixture-access-token;;\nlookup*'kind refresh_token'*) echo fixture-refresh-token;;\nstore*) cat >/dev/null; exit 0;;\nclear*) exit 0;;\n*) exit 1;;\nesac\n",
        )
        .unwrap();
        fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();

        let email = "import@fixture.invalid";
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

        let existing_folder_id = "existing-folder-work-0001";
        let initial_folders = vec![json!({
            "id": existing_folder_id,
            "name": user_key.encrypt_string("Work").unwrap()
        })];
        let initial_ciphers = vec![json!({
            "id": "existing-cipher-0001",
            "organizationId": null,
            "folderId": existing_folder_id,
            "type": 2,
            "name": user_key.encrypt_string("Existing Note").unwrap(),
            "notes": user_key.encrypt_string("Already in vault").unwrap(),
            "favorite": false,
            "reprompt": 0,
            "secureNote": { "type": 0 }
        })];

        let server = MockBitwardenServer::start(initial_folders.clone(), initial_ciphers.clone());

        let data = json!({
            "user_id": "user-id-123",
            "user_email": email,
            "server_url": server.base_url,
            "credential_id": "11111111111111111111111111111111",
            "enc_user_key": wrap,
            "kdf": 0,
            "kdf_iterations": 100_000,
            "folders": initial_folders,
            "ciphers": initial_ciphers,
            "organizations": [],
            "collections": []
        });
        fs::write(dir.join("data.json"), data.to_string()).unwrap();
        fs::write(
            dir.join("config.json"),
            serde_json::to_string(&json!({ "server_url": server.base_url })).unwrap(),
        )
        .unwrap();

        let socket = dir.join("omawarden.sock");
        let daemon = DaemonGuard(
            Command::new(env!("CARGO_BIN_EXE_omawarden"))
                .arg("daemon")
                .env_clear()
                .env("HOME", dir)
                .env("PATH", dir)
                .env("XDG_RUNTIME_DIR", dir)
                .env("OMAWARDEN_DATA_DIR", dir)
                .env("OMAWARDEN_CONFIG_DIR", dir)
                .env("OMA_KEYRING_PROVIDER", "secret-tool")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        assert_eq!(ipc(&socket, json!({"action": "ping"}))["ok"], true);
        if unlock {
            let res = ipc(
                &socket,
                json!({"action": "unlock", "password": master_password}),
            );
            assert_eq!(res["ok"], true, "unlock failed: {res}");
        }

        Self {
            temp,
            user_key,
            server,
            _daemon: daemon,
        }
    }

    fn run_cli(&self, args: &[&str]) -> Output {
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
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }
}

fn run_cli_in_controlling_pty(
    env: &TestImportEnv,
    args: &[&str],
    inputs: &[&str],
) -> (std::process::ExitStatus, String) {
    unsafe {
        let master_fd = libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY);
        assert!(master_fd >= 0, "posix_openpt failed");
        assert_eq!(libc::grantpt(master_fd), 0);
        assert_eq!(libc::unlockpt(master_fd), 0);
        let slave_name = std::ffi::CStr::from_ptr(libc::ptsname(master_fd))
            .to_str()
            .unwrap()
            .to_string();

        let slave_file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&slave_name)
            .unwrap();
        let slave_stdin = slave_file.try_clone().unwrap();
        let slave_stdout = slave_file.try_clone().unwrap();
        let slave_stderr = slave_file;

        let dir = env.temp.path();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_omawarden"));
        cmd.args(args)
            .env_clear()
            .env("HOME", dir)
            .env("PATH", dir)
            .env("XDG_RUNTIME_DIR", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMA_KEYRING_PROVIDER", "secret-tool")
            .stdin(Stdio::from(slave_stdin))
            .stdout(Stdio::from(slave_stdout))
            .stderr(Stdio::from(slave_stderr));

        cmd.pre_exec(|| {
            if libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });

        let mut child = cmd.spawn().unwrap();
        drop(cmd);

        let master_read_fd = libc::dup(master_fd);
        assert!(master_read_fd >= 0);
        let mut master_reader =
            <fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(master_read_fd);
        let mut master_writer = <fs::File as std::os::unix::io::FromRawFd>::from_raw_fd(master_fd);

        let reader_handle = thread::spawn(move || {
            let mut out = Vec::new();
            let mut buf = [0u8; 256];
            loop {
                match master_reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => out.extend_from_slice(&buf[..n]),
                }
            }
            String::from_utf8_lossy(&out).to_string()
        });

        for line in inputs {
            thread::sleep(Duration::from_millis(120));
            let _ = master_writer.write_all(line.as_bytes());
            let _ = master_writer.flush();
        }
        drop(master_writer);

        let status = child.wait().unwrap();
        let output = reader_handle.join().unwrap();
        (status, output)
    }
}

#[test]
fn cli_rejects_password_flag_format_mismatch_and_oversized_files() {
    let env = TestImportEnv::new(true);
    let json_path = env.temp.path().join("sample.json");
    fs::write(&json_path, r#"{"encrypted":false,"folders":[],"items":[]}"#).unwrap();

    // 1. Rule 11 Zero-Argv: --password must be rejected by CLI parser
    let pw_out = env.run_cli(&[
        "vault",
        "import",
        json_path.to_str().unwrap(),
        "--password",
        "secret",
    ]);
    assert!(!pw_out.status.success(), "--password must fail closed");

    // 2. Explicit --format mismatch fails closed with zero HTTP calls
    let mismatch = env.run_cli(&[
        "vault",
        "import",
        json_path.to_str().unwrap(),
        "--format",
        "csv",
        "--dry-run",
        "--json",
    ]);
    assert!(!mismatch.status.success());
    let mismatch_env: Value = serde_json::from_slice(&mismatch.stdout).unwrap();
    assert_eq!(mismatch_env["ok"], false);
    assert!(mismatch_env["error"]
        .as_str()
        .unwrap()
        .contains("Format mismatch"));

    // 3. 50 MiB size cap fails closed before parsing
    let big_path = env.temp.path().join("too-big.json");
    fs::File::create(&big_path)
        .unwrap()
        .set_len(MAX_IMPORT_FILE_BYTES + 1)
        .unwrap();
    let big_out = env.run_cli(&[
        "vault",
        "import",
        big_path.to_str().unwrap(),
        "--dry-run",
        "--json",
    ]);
    assert!(!big_out.status.success());
    let big_env: Value = serde_json::from_slice(&big_out.stdout).unwrap();
    assert_eq!(big_env["ok"], false);
    assert!(big_env["error"].as_str().unwrap().contains("50 MiB"));

    assert_eq!(env.server.state.lock().unwrap().import_calls, 0);
}

#[test]
fn dry_run_and_confirmation_gates_make_zero_http_requests() {
    let env = TestImportEnv::new(true);
    let import_file = env.temp.path().join("preview.json");
    fs::write(
        &import_file,
        serde_json::to_string_pretty(&json!({
            "encrypted": false,
            "folders": [
                { "id": "existing-folder-work-0001", "name": "Work" },
                { "id": "new-folder-id", "name": "Finance" }
            ],
            "items": [
                {
                    "type": 1,
                    "name": "Bank Login",
                    "folderId": "new-folder-id",
                    "login": { "username": "alice", "password": "pw", "uris": [] }
                },
                {
                    "type": 6,
                    "name": "Unsupported Checking"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    // 1. --dry-run --json succeeds with zero HTTP requests
    let dry = env.run_cli(&[
        "vault",
        "import",
        import_file.to_str().unwrap(),
        "--dry-run",
        "--json",
    ]);
    assert!(
        dry.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&dry.stderr)
    );
    let dry_json: Value = serde_json::from_slice(&dry.stdout).unwrap();
    assert_eq!(dry_json["ok"], true);
    assert_eq!(dry_json["dry_run"], true);
    assert_eq!(dry_json["detected_format"], "json");
    assert_eq!(dry_json["cipher_count"], 1);
    assert_eq!(dry_json["folders_reused"], 1);
    assert_eq!(dry_json["folders_created"], 1);
    assert_eq!(dry_json["skipped_unsupported"].as_array().unwrap().len(), 1);
    assert_eq!(env.server.state.lock().unwrap().import_calls, 0);
    assert_eq!(env.server.state.lock().unwrap().sync_calls, 0);

    // 2. Non-interactive without --yes fails closed
    let no_yes = env.run_cli(&["vault", "import", import_file.to_str().unwrap()]);
    assert!(!no_yes.status.success());
    assert!(String::from_utf8_lossy(&no_yes.stderr).contains("--yes"));

    // 3. --json without --yes fails closed
    let json_no_yes = env.run_cli(&["vault", "import", import_file.to_str().unwrap(), "--json"]);
    assert!(!json_no_yes.status.success());
    let json_err: Value = serde_json::from_slice(&json_no_yes.stdout).unwrap();
    assert_eq!(json_err["ok"], false);
    assert!(json_err["error"].as_str().unwrap().contains("--yes"));
    assert_eq!(env.server.state.lock().unwrap().import_calls, 0);

    // 4. Interactive PTY prompt: declining 'n' aborts with zero HTTP requests
    let (status_no, out_no) = run_cli_in_controlling_pty(
        &env,
        &["vault", "import", import_file.to_str().unwrap()],
        &["n\n"],
    );
    assert!(!status_no.success());
    assert!(out_no.contains("Import 1 item(s)"), "got: {out_no}");
    assert!(
        out_no.contains("1 folder(s) reused, 1 new folder(s)"),
        "got: {out_no}"
    );
    assert_eq!(env.server.state.lock().unwrap().import_calls, 0);

    // 5. Interactive PTY prompt: accepting 'y' imports and syncs
    let (status_yes, out_yes) = run_cli_in_controlling_pty(
        &env,
        &["vault", "import", import_file.to_str().unwrap()],
        &["y\n"],
    );
    assert!(status_yes.success(), "pty output: {out_yes}");
    assert_eq!(env.server.state.lock().unwrap().import_calls, 1);
    assert_eq!(env.server.state.lock().unwrap().sync_calls, 1);
}

#[test]
fn plaintext_json_import_reconciles_folders_normalizes_and_syncs_vault() {
    let env = TestImportEnv::new(true);
    let import_file = env.temp.path().join("full-import.json");
    fs::write(
        &import_file,
        serde_json::to_string_pretty(&json!({
            "encrypted": false,
            "folders": [
                { "id": "different-id-same-name", "name": "Work" },
                { "id": "new-infra-id", "name": "Infra" }
            ],
            "items": [
                {
                    "type": 1,
                    "name": "Imported GitHub",
                    "organizationId": "org-should-be-nulled",
                    "folderId": "different-id-same-name",
                    "favorite": true,
                    "reprompt": 1,
                    "notes": "Prod creds",
                    "login": {
                        "username": "octocat",
                        "password": "imported-password-123",
                        "totp": "JBSWY3DPEHPK3PXP",
                        "uris": [{ "uri": "https://github.com", "match": 0 }]
                    },
                    "passwordHistory": [
                        null,
                        { "password": "" },
                        { "password": "old1" },
                        { "password": "old2" },
                        { "password": "old3" },
                        { "password": "old4" },
                        { "password": "old5" },
                        { "password": "old6" }
                    ]
                },
                {
                    "type": 5,
                    "name": "Prod SSH Key",
                    "folderId": "new-infra-id",
                    "sshKey": {
                        "privateKey": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----",
                        "publicKey": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA test@prod",
                        "fingerprint": "SHA256:fallbackfp999"
                    }
                },
                {
                    "type": 8,
                    "name": "Future Passport"
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = env.run_cli(&[
        "vault",
        "import",
        import_file.to_str().unwrap(),
        "--yes",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let res: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(res["ok"], true);
    assert_eq!(res["dry_run"], false);
    assert_eq!(res["detected_format"], "json");
    assert_eq!(res["cipher_count"], 2);
    assert_eq!(res["folders_reused"], 1);
    assert_eq!(res["folders_created"], 1);
    assert_eq!(res["skipped_unsupported"].as_array().unwrap().len(), 1);

    // Inspect the encrypted POST /api/ciphers/import payload
    {
        let st = env.server.state.lock().unwrap();
        assert_eq!(st.import_calls, 1);
        assert_eq!(st.sync_calls, 1);
        let req = &st.import_requests[0];
        assert_eq!(req["folders"].as_array().unwrap().len(), 1);
        assert_eq!(
            decrypt_cipher_string(req["folders"][0]["name"].as_str(), &env.user_key).as_deref(),
            Some("Infra")
        );
        assert_eq!(req["ciphers"][0]["organizationId"], Value::Null);
        assert_eq!(req["ciphers"][0]["folderId"], "existing-folder-work-0001");
        assert_eq!(
            req["ciphers"][0]["passwordHistory"]
                .as_array()
                .unwrap()
                .len(),
            5
        );
        assert_eq!(req["ciphers"][1]["folderId"], Value::Null);
        assert_eq!(
            req["folderRelationships"],
            json!([{ "key": 1, "value": 0 }])
        );
    }

    // Post-import sync made newly imported items immediately visible in vault list/search/get!
    let list_out = env.run_cli(&["vault", "list"]);
    assert!(list_out.status.success());
    let list_text = String::from_utf8_lossy(&list_out.stdout);
    assert!(list_text.contains("Imported GitHub"), "list: {list_text}");
    assert!(list_text.contains("Prod SSH Key"), "list: {list_text}");

    let search_out = env.run_cli(&["vault", "search", "Imported GitHub"]);
    assert!(search_out.status.success());
    assert!(String::from_utf8_lossy(&search_out.stdout).contains("Imported GitHub"));

    let get_out = env.run_cli(&["vault", "get", "Imported GitHub", "--password"]);
    assert!(
        get_out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&get_out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&get_out.stdout).trim(),
        "imported-password-123"
    );
}

#[test]
fn csv_import_with_folder_override_and_token_renewal() {
    let env = TestImportEnv::new(true);
    env.server.state.lock().unwrap().fail_first_import_with_401 = true;

    // CSV without archivedDate column
    let csv_file = env.temp.path().join("legacy.csv");
    fs::write(
        &csv_file,
        concat!(
            "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n",
            "IgnoredFolder,1,login,CSV Login,\"Line1\nLine2\",\"Env: prod\",0,\"https://a.test,https://b.test\",csvuser,csvpass,\n",
            ",0,note,CSV Note,Just a note,,0,,,,\n"
        ),
    )
    .unwrap();

    let out = env.run_cli(&[
        "vault",
        "import",
        csv_file.to_str().unwrap(),
        "--folder",
        "ImportedBatch",
        "--yes",
        "--json",
    ]);
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let res: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(res["ok"], true);
    assert_eq!(res["detected_format"], "csv");
    assert_eq!(res["cipher_count"], 2);
    assert_eq!(res["folders_reused"], 0);
    assert_eq!(res["folders_created"], 1);

    {
        let st = env.server.state.lock().unwrap();
        assert_eq!(
            st.import_calls, 2,
            "should retry once after 401 token renewal"
        );
        assert_eq!(st.token_refresh_calls, 1);
        assert_eq!(st.sync_calls, 1);
        let req = &st.import_requests[0];
        assert_eq!(
            decrypt_cipher_string(req["folders"][0]["name"].as_str(), &env.user_key).as_deref(),
            Some("ImportedBatch")
        );
        assert_eq!(
            req["folderRelationships"],
            json!([{ "key": 0, "value": 0 }, { "key": 1, "value": 0 }])
        );
    }

    let get_out = env.run_cli(&["vault", "get", "CSV Login", "--password"]);
    assert!(get_out.status.success());
    assert_eq!(String::from_utf8_lossy(&get_out.stdout).trim(), "csvpass");
}

#[test]
fn surfaces_server_validation_errors_with_item_index_and_name() {
    let env = TestImportEnv::new(true);
    env.server.state.lock().unwrap().validation_error_response = Some(
        json!({
            "message": "The model state is invalid.",
            "validationErrors": {
                "Ciphers[1].Notes": ["The field Notes must be a string with a maximum length of 10000."]
            }
        })
        .to_string(),
    );

    let import_file = env.temp.path().join("val-err.json");
    fs::write(
        &import_file,
        serde_json::to_string(&json!({
            "encrypted": false,
            "folders": [],
            "items": [
                { "type": 2, "name": "Small Note", "secureNote": { "type": 0 } },
                { "type": 2, "name": "Huge Note", "notes": "too long", "secureNote": { "type": 0 } }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    let out = env.run_cli(&[
        "vault",
        "import",
        import_file.to_str().unwrap(),
        "--yes",
        "--json",
    ]);
    assert!(!out.status.success());
    let res: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(res["ok"], false);
    let err = res["error"].as_str().unwrap();
    assert!(err.contains("item #1 ('Huge Note')"), "got: {err}");
    assert!(err.contains("maximum length of 10000"), "got: {err}");
    assert_eq!(env.server.state.lock().unwrap().sync_calls, 0);
}

#[test]
fn locked_vault_and_stale_inprocess_daemon_fail_closed() {
    let locked_env = TestImportEnv::new(false);
    let import_file = locked_env.temp.path().join("locked.json");
    fs::write(
        &import_file,
        r#"{"encrypted":false,"folders":[],"items":[]}"#,
    )
    .unwrap();

    let locked_out = locked_env.run_cli(&[
        "vault",
        "import",
        import_file.to_str().unwrap(),
        "--dry-run",
        "--json",
    ]);
    assert!(!locked_out.status.success());
    let locked_res: Value = serde_json::from_slice(&locked_out.stdout).unwrap();
    assert_eq!(locked_res["ok"], false);
    assert!(locked_res["error"].as_str().unwrap().contains("locked"));

    // Stale in-process daemon missing "vault_export_import" capability fails closed
    let temp = tempfile::tempdir().unwrap();
    let runtime = temp.path().join("runtime");
    fs::create_dir_all(&runtime).unwrap();
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = runtime.join("omawarden.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_c = Arc::clone(&stop);
    let server_thread = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        while !stop_c.load(Ordering::SeqCst) {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut line = String::new();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let _ = reader.read_line(&mut line);
                let _ = writeln!(
                    stream,
                    "{}",
                    json!({
                        "ok": true,
                        "pong": true,
                        "unlocked": true,
                        "protocol_version": 1,
                        "schema_version": 3,
                        "daemon_mode": "in_process",
                        "capabilities": ["vault_get"]
                    })
                );
            } else {
                thread::sleep(Duration::from_millis(5));
            }
        }
    });

    let file = temp.path().join("stale.json");
    fs::write(&file, r#"{"encrypted":false,"folders":[],"items":[]}"#).unwrap();
    let stale_out = Command::new(env!("CARGO_BIN_EXE_omawarden"))
        .args([
            "vault",
            "import",
            file.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("XDG_DATA_HOME", temp.path().join("data"))
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .output()
        .unwrap();
    stop.store(true, Ordering::SeqCst);
    let _ = server_thread.join();

    assert!(!stale_out.status.success());
    let stale_res: Value = serde_json::from_slice(&stale_out.stdout).unwrap();
    assert_eq!(stale_res["ok"], false);
    assert!(
        stale_res["error"]
            .as_str()
            .unwrap()
            .contains("vault_export_import"),
        "got: {stale_res}"
    );
}

use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;

// Model wl-copy's fork *after* setting the selection. Each source holds a
// distinct file lock for as long as it can serve paste requests.
const WL_COPY: &str = r#"#!/bin/sh
set -eu
cd "$XDG_RUNTIME_DIR"
if [ "${1:-}" = --clear ]; then rm -f selection; exit; fi
echo "$*" >> "$XDG_RUNTIME_DIR/args.log"
value=$(mktemp "$PWD/source.XXXXXX")
cat > "$value"
exec 9<"$value"
flock -x 9
ln -sfn "$value" selection
(while [ "$(readlink selection)" = "$value" ]; do sleep .05; done) </dev/null >/dev/null 2>&1 &
"#;

struct Clipboard(TempDir);

struct DaemonProcess(std::process::Child);

impl Drop for DaemonProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn deny_regular_file_writes(command: &mut Command) {
    // SAFETY: this child-only hook changes a signal disposition and resource
    // limit using libc calls before exec, without touching shared Rust state.
    unsafe {
        command.pre_exec(|| {
            if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR {
                return Err(std::io::Error::last_os_error());
            }
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

struct EpochDaemon {
    stopped: Arc<AtomicBool>,
    shared_epoch: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl EpochDaemon {
    fn new(runtime: &Path, shared_epoch: bool) -> Self {
        let socket = runtime.join("omawarden.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let shared_epoch = Arc::new(AtomicBool::new(shared_epoch));
        let capability = Arc::clone(&shared_epoch);
        let thread = thread::spawn(move || {
            while !stop.load(Ordering::SeqCst) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => panic!("{error}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut line = String::new();
                BufReader::new(&stream).read_line(&mut line).unwrap();
                if line.is_empty() {
                    continue;
                }
                let request: Value = serde_json::from_str(&line).unwrap();
                let mut reply = match request["action"].as_str() {
                    Some("ping") => json!({"ok":true,"pong":true,"protocol_version":1}),
                    Some("status") => json!({"ok":true,"is_unlocked":false,"protocol_version":1}),
                    _ => json!({"ok":false,"error":"Unsupported fixture action"}),
                };
                if capability.load(Ordering::SeqCst) {
                    reply["shared_lock_epoch"] = json!(true);
                }
                writeln!(stream, "{reply}").unwrap();
            }
        });
        Self {
            stopped,
            shared_epoch,
            thread: Some(thread),
        }
    }
}

impl Drop for EpochDaemon {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

impl Clipboard {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mock = dir.path().join("wl-copy");
        fs::write(&mock, WL_COPY).unwrap();
        fs::set_permissions(&mock, fs::Permissions::from_mode(0o755)).unwrap();
        Self(dir)
    }

    fn command(&self, program: &Path) -> Command {
        let dir = self.0.path();
        let mut command = Command::new(program);
        command
            .env_clear()
            .env("XDG_RUNTIME_DIR", dir)
            .env("XDG_CONFIG_HOME", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("HOME", dir)
            .env("WAYLAND_DISPLAY", "fixture-wayland")
            .env("OMA_DAEMON_LAUNCH_STRATEGY", "disabled")
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        command
    }

    fn run(&self, program: &Path, args: &[&str], text: &str) -> Output {
        let mut child = self.command(program).args(args).spawn().unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    }

    fn copy(&self, text: &str, ttl: &str) -> Output {
        self.run(
            Path::new(env!("CARGO_BIN_EXE_omawarden")),
            &["copy", "--stdin", "--sensitive", "--timeout", ttl],
            text,
        )
    }

    fn paste(&self) -> Option<String> {
        let selection = self.0.path().join("selection");
        let file = File::open(&selection).ok()?;
        match file.try_lock() {
            Err(std::fs::TryLockError::WouldBlock) => Some(fs::read_to_string(selection).unwrap()),
            Ok(()) => None,
            Err(err) => panic!("could not check clipboard owner: {err}"),
        }
    }

    fn write_epoch(&self, epoch: u64) {
        fs::write(
            self.0.path().join("omawarden.lock-epoch"),
            epoch.to_string(),
        )
        .unwrap();
        fs::write(self.0.path().join("omawarden.lock-epoch.lock"), [0]).unwrap();
    }

    fn epoch(&self) -> u64 {
        fs::read_to_string(self.0.path().join("omawarden.lock-epoch"))
            .unwrap()
            .parse()
            .unwrap()
    }

    fn recorded_args(&self) -> Vec<String> {
        let args_file = self.0.path().join("args.log");
        if let Ok(content) = fs::read_to_string(&args_file) {
            content.lines().map(|s| s.to_string()).collect()
        } else {
            Vec::new()
        }
    }
}

#[test]
fn external_copy_survives_sensitive_expiry_even_with_identical_text() {
    let clips: Vec<_> = [("different", false), ("same", false), ("after-clear", true)]
        .into_iter()
        .map(|(replacement, clear_first)| {
            let clip = Clipboard::new();
            assert!(clip.copy("same", "1").status.success());
            assert_eq!(clip.paste().as_deref(), Some("same"));
            if clear_first {
                let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
                assert!(clip.run(cli, &["copy", "--clear"], "").status.success());
                assert!(clip.paste().is_none());
            }
            assert!(clip
                .run(&clip.0.path().join("wl-copy"), &[], replacement)
                .status
                .success());
            (clip, replacement)
        })
        .collect();
    thread::sleep(Duration::from_millis(1300));
    for (clip, replacement) in clips {
        assert_eq!(
            clip.paste().as_deref(),
            Some(replacement),
            "the expired owner cleared an external copy"
        );
    }
}

#[test]
fn expiry_preserves_replacement_when_old_wayland_owner_is_slow_to_exit() {
    let clip = Clipboard::new();
    let wl_copy = clip.0.path().join("wl-copy");
    // The compositor has transferred selection before the old source exits.
    fs::write(&wl_copy, WL_COPY.replace("done)", "done; sleep 5)")).unwrap();
    assert!(clip.copy("old secret", "1").status.success());
    let old_source = File::open(clip.0.path().join("selection")).unwrap();
    assert!(clip
        .run(&wl_copy, &[], "external selection")
        .status
        .success());
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match old_source.try_lock() {
            Ok(()) => break,
            Err(std::fs::TryLockError::WouldBlock) => {
                assert!(Instant::now() < deadline, "expired owner was not revoked");
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) => panic!("could not check expired owner: {error}"),
        }
    }
    assert_eq!(clip.paste().as_deref(), Some("external selection"));
}

#[test]
fn explicit_providers_enforce_cache_epoch_and_credential_scope() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    for provider in ["wayland", "mock"] {
        let clip = Clipboard::new();
        let cache = clip.0.path().join("data.json");
        let wl_copy = clip.0.path().join("wl-copy");
        let active = "11111111111111111111111111111111";
        fs::write(&cache, json!({"credential_id": active}).to_string()).unwrap();
        clip.write_epoch(41);
        let args = [
            "clipboard-holder",
            "0",
            "--provider",
            provider,
            "--binary-path",
            wl_copy.to_str().unwrap(),
            "--cache-path",
            cache.to_str().unwrap(),
            "--expected-credential-id",
            active,
            "--expected-lock-epoch",
            "41",
        ];
        assert!(
            clip.run(cli, &args, "authorized value").status.success(),
            "{provider}"
        );
        assert!(
            !clip.run(cli, &args[..10], "missing epoch").status.success(),
            "{provider}"
        );
        clip.write_epoch(42);
        assert!(
            !clip.run(cli, &args, "expired value").status.success(),
            "{provider}"
        );
        clip.write_epoch(41);
        fs::write(
            &cache,
            json!({"credential_id": "22222222222222222222222222222222"}).to_string(),
        )
        .unwrap();
        assert!(
            !clip.run(cli, &args, "wrong account").status.success(),
            "{provider}"
        );
        if provider == "wayland" {
            assert_eq!(clip.paste().as_deref(), Some("authorized value"));
        }
    }
}

#[test]
fn second_cli_copy_expires_on_its_own_deadline() {
    let clip = Clipboard::new();
    assert!(clip.copy("first", "1").status.success());
    assert!(clip.copy("second", "3").status.success());
    thread::sleep(Duration::from_millis(1300));
    assert_eq!(clip.paste().as_deref(), Some("second"));
    let deadline = Instant::now() + Duration::from_secs(5);
    while clip.paste().is_some() {
        assert!(
            Instant::now() < deadline,
            "owner outlived its TTL after the CLI exited"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn disabled_expiry_survives_previous_owner() {
    let clip = Clipboard::new();
    assert!(clip.copy("first", "1").status.success());
    assert!(clip.copy("keep", "0").status.success());
    thread::sleep(Duration::from_millis(1300));
    assert_eq!(clip.paste().as_deref(), Some("keep"));
}

#[test]
fn failed_owner_is_reported_to_caller() {
    let clip = Clipboard::new();
    fs::write(
        clip.0.path().join("wl-copy"),
        "#!/bin/sh\ncat >/dev/null\nexit 1\n",
    )
    .unwrap();
    let output = clip.copy("never served", "1");
    assert!(!output.status.success());
    let reply: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reply["ok"], false);
}

#[test]
fn stalled_selection_setup_fails_before_expiry_starts() {
    let clip = Clipboard::new();
    fs::write(
        clip.0.path().join("wl-copy"),
        "#!/bin/sh\nexec /usr/bin/sleep 10\n",
    )
    .unwrap();
    let output = clip.copy("never served", "30");
    assert!(!output.status.success());
    assert!(clip.paste().is_none());
}

#[test]
fn vault_item_and_totp_copies_validate_the_generation_that_supplied_the_value() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let cases: [(&[&str], &str); 3] = [
        (&["copy", "fixture", "--password", "--timeout", "0"], ""),
        (&["totp", "fixture", "--copy"], ""),
        (&["totp", "--stdin", "--copy"], "{\"query\":\"fixture\"}\n"),
    ];
    for (args, input) in cases {
        for current in [41, 42] {
            let clip = Clipboard::new();
            let socket = clip.0.path().join("omawarden.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let server = thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(10);
                loop {
                    let (mut stream, _) = match listener.accept() {
                        Ok(connection) => connection,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "copy never checked its session");
                            thread::sleep(Duration::from_millis(5));
                            continue;
                        }
                        Err(error) => panic!("{error}"),
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    let mut line = String::new();
                    BufReader::new(&stream).read_line(&mut line).unwrap();
                    let request: Value = serde_json::from_str(&line).unwrap();
                    let action = request["action"].as_str().unwrap();
                    let response = match action {
                        "ping" => json!({"commit":env!("GIT_HASH"), "unlocked":true}),
                        "status" => json!({"is_unlocked":true}),
                        "get_item" => json!({"ok":true,"lock_generation":41,"item":{
                            "id":"fixture","name":"Fixture","type":1,"type_name":"login",
                            "sub_title":"","search_text":"","favorite":false,
                            "login":{"password":"fixture-password","totp":"JBSWY3DPEHPK3PXP"}
                        }}),
                        "totp" => {
                            json!({"ok":true,"lock_generation":41,"code":"123456","id":"fixture","name":"Fixture"})
                        }
                        "output_generation" => json!({
                            "lock_generation":current,"credential_id":"11111111111111111111111111111111"
                        }),
                        other => panic!("unexpected request {other}"),
                    };
                    writeln!(stream, "{response}").unwrap();
                    if action == "output_generation" {
                        break;
                    }
                }
            });
            let output = clip.run(cli, args, input);
            let reply: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(output.status.success(), current == 41, "{reply}");
            if current == 41 {
                let expected = if args[0] == "copy" {
                    "fixture-password"
                } else {
                    reply["code"].as_str().unwrap()
                };
                assert_eq!(clip.paste().as_deref(), Some(expected));
            } else {
                assert!(clip.paste().is_none());
                assert!(
                    reply.get("code").is_none(),
                    "stale TOTP escaped in the error response"
                );
            }
            server.join().unwrap();
        }
    }
}

#[test]
fn offline_clipboard_holder_rejects_a_replaced_slot_and_logout_clears_without_daemon() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let clip = Clipboard::new();
    let runtime = clip.0.path();
    let cache = runtime.join("data.json");
    let active = "11111111111111111111111111111111";
    let write_cache =
        |slot: &str| fs::write(&cache, json!({"credential_id":slot}).to_string()).unwrap();
    write_cache(active);
    let keyring = runtime.join("secret-tool");
    fs::write(
        &keyring,
        "#!/bin/sh\ncase \"$1\" in clear|search) exit 0;; *) exit 1;; esac\n",
    )
    .unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();
    let wl_copy = runtime.join("wl-copy");
    clip.write_epoch(41);
    let holder = [
        "clipboard-holder",
        "0",
        wl_copy.to_str().unwrap(),
        "--cache-path",
        cache.to_str().unwrap(),
        "--expected-credential-id",
        active,
        "--expected-lock-epoch",
        "41",
    ];
    assert!(clip.run(cli, &holder, "old selection").status.success());
    assert_eq!(clip.paste().as_deref(), Some("old selection"));
    write_cache("22222222222222222222222222222222");
    assert!(!clip.run(cli, &holder, "late selection").status.success());
    assert_eq!(clip.paste().as_deref(), Some("old selection"));
    let logout = clip.run(cli, &["auth", "logout"], "");
    assert!(
        logout.status.success(),
        "{}",
        String::from_utf8_lossy(&logout.stdout)
    );
    assert!(clip.paste().is_none());
    assert!(!runtime.join("omawarden.clipboard.pending").exists());
}

fn holder_args<'a>(
    wl_copy: &'a Path,
    cache: &'a Path,
    credential_id: &'a str,
    lock_epoch: &'a str,
) -> [&'a str; 9] {
    [
        "clipboard-holder",
        "0",
        wl_copy.to_str().unwrap(),
        "--cache-path",
        cache.to_str().unwrap(),
        "--expected-credential-id",
        credential_id,
        "--expected-lock-epoch",
        lock_epoch,
    ]
}

#[test]
fn cli_lock_without_daemon_advances_epoch_and_rejects_stale_holder() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let clip = Clipboard::new();
    let runtime = clip.0.path();
    let cache = runtime.join("data.json");
    let active = "11111111111111111111111111111111";
    fs::write(&cache, json!({"credential_id":active}).to_string()).unwrap();
    let keyring = runtime.join("secret-tool");
    fs::write(
        &keyring,
        "#!/bin/sh\ncase \"$1\" in clear|search) exit 0;; *) exit 1;; esac\n",
    )
    .unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();
    let wl_copy = runtime.join("wl-copy");
    clip.write_epoch(100);
    let stale = holder_args(&wl_copy, &cache, active, "100");

    assert!(clip
        .run(cli, &stale, "authorized selection")
        .status
        .success());
    assert_eq!(clip.paste().as_deref(), Some("authorized selection"));

    let lock = clip.run(cli, &["auth", "lock"], "");
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stdout)
    );
    assert_eq!(clip.epoch(), 101, "local lock advanced the shared epoch");
    assert!(clip.paste().is_none(), "lock cleared the old selection");

    assert!(
        !clip.run(cli, &stale, "stale selection").status.success(),
        "a holder authorized before the lock must not publish"
    );
    assert!(clip.paste().is_none());

    let fresh = holder_args(&wl_copy, &cache, active, "101");
    assert!(clip.run(cli, &fresh, "fresh selection").status.success());
    assert_eq!(clip.paste().as_deref(), Some("fresh selection"));
}

#[test]
fn epoch_write_failure_cannot_leave_a_stale_holder_authorized() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let clip = Clipboard::new();
    let root = clip.0.path();
    let cache = root.join("data.json");
    let active = "11111111111111111111111111111111";
    fs::write(&cache, json!({"credential_id":active}).to_string()).unwrap();
    let keyring = root.join("secret-tool");
    fs::write(&keyring, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(keyring, fs::Permissions::from_mode(0o700)).unwrap();
    clip.write_epoch(100);

    let mut lock = Command::new(cli);
    lock.args(["auth", "lock"])
        .env_clear()
        .env("PATH", format!("{}:/usr/bin:/bin", root.display()))
        .env("XDG_RUNTIME_DIR", root)
        .env("OMAWARDEN_DATA_DIR", root)
        .env("OMAWARDEN_CONFIG_DIR", root)
        .env("WAYLAND_DISPLAY", "fixture-wayland");
    deny_regular_file_writes(&mut lock);
    let locked = lock.output().unwrap();
    assert!(
        locked.status.success(),
        "{}",
        String::from_utf8_lossy(&locked.stdout)
    );
    let stale = holder_args(&root.join("wl-copy"), &cache, active, "100").map(str::to_owned);
    let stale: Vec<_> = stale.iter().map(String::as_str).collect();
    assert!(
        !clip
            .run(cli, &stale, "late fixture selection")
            .status
            .success(),
        "a failed epoch write left the old authorization usable"
    );
    assert!(clip.paste().is_none());
    let reply: Value = serde_json::from_slice(&locked.stdout).unwrap();
    assert_eq!(reply["epoch_advanced"], false);
    assert!(
        reply["error"].is_null(),
        "a confirmed lock must reserve error for failure"
    );
    assert!(reply["warning"]
        .as_str()
        .unwrap()
        .contains("revocation is unconfirmed"));
}

#[test]
fn daemon_epoch_write_failure_cannot_authorize_an_offline_holder() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let clip = Clipboard::new();
    let root = clip.0.path();
    let cache = root.join("data.json");
    let active = "11111111111111111111111111111111";
    fs::write(&cache, json!({"credential_id":active}).to_string()).unwrap();
    clip.write_epoch(100);
    let mut command = clip.command(cli);
    command.arg("daemon");
    deny_regular_file_writes(&mut command);
    let _daemon = DaemonProcess(command.spawn().unwrap());
    let socket = root.join("omawarden.sock");
    let deadline = Instant::now() + Duration::from_secs(5);
    while !socket.exists() {
        assert!(
            Instant::now() < deadline,
            "fault-injected daemon did not start"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    writeln!(stream, "{}", json!({"action":"lock"})).unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    let reply: Value = serde_json::from_str(&line).unwrap();
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["outputs_cleared"], true);
    assert_eq!(reply["epoch_advanced"], false);
    assert_eq!(reply["lock_epoch"], Value::Null);
    let wl_copy = root.join("wl-copy");
    let stale = holder_args(&wl_copy, &cache, active, "100");
    assert!(!clip
        .run(cli, &stale, "late fixture selection")
        .status
        .success());
    assert!(clip.paste().is_none());
}

#[test]
fn daemon_lock_revokes_old_epoch_when_output_gate_is_unavailable() {
    assert_lock_revokes_old_epoch_with_unavailable_output_gate(true);
}

#[test]
fn cli_lock_without_daemon_revokes_old_epoch_when_output_gate_is_unavailable() {
    assert_lock_revokes_old_epoch_with_unavailable_output_gate(false);
}

fn assert_lock_revokes_old_epoch_with_unavailable_output_gate(with_daemon: bool) {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let clip = Clipboard::new();
    let root = clip.0.path();
    let cache = root.join("data.json");
    let active = "11111111111111111111111111111111";
    fs::write(&cache, json!({"credential_id":active}).to_string()).unwrap();
    let keyring = root.join("secret-tool");
    fs::write(&keyring, "#!/bin/sh\nexit 0\n").unwrap();
    fs::set_permissions(keyring, fs::Permissions::from_mode(0o700)).unwrap();
    clip.write_epoch(100);
    let wl_copy = root.join("wl-copy");
    let stale = holder_args(&wl_copy, &cache, active, "100");

    // Make only the output gate unavailable. The epoch files remain writable.
    let gate = root.join("omawarden.outputs.lock");
    fs::create_dir(&gate).unwrap();
    let _daemon =
        with_daemon.then(|| DaemonProcess(clip.command(cli).arg("daemon").spawn().unwrap()));
    let reply: Value = if with_daemon {
        let socket = root.join("omawarden.sock");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "daemon did not start");
            thread::sleep(Duration::from_millis(5));
        }
        let mut stream = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        writeln!(stream, "{}", json!({"action":"lock"})).unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        serde_json::from_str(&line).unwrap()
    } else {
        let lock = clip.run(cli, &["auth", "lock"], "");
        assert!(lock.status.success());
        serde_json::from_slice(&lock.stdout).unwrap()
    };

    fs::remove_dir(&gate).unwrap();
    assert!(
        !clip
            .run(cli, &stale, "stale fixture selection")
            .status
            .success(),
        "the old holder could publish after the output gate recovered"
    );
    assert!(clip.paste().is_none());
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["epoch_advanced"], true);
    assert_eq!(reply["lock_epoch"], 101);
    if with_daemon {
        assert_eq!(reply["outputs_cleared"], false);
    }

    let fresh = holder_args(&wl_copy, &cache, active, "101");
    assert!(clip
        .run(cli, &fresh, "fresh fixture selection")
        .status
        .success());
    assert_eq!(clip.paste().as_deref(), Some("fresh fixture selection"));
}

#[test]
fn offline_holder_requires_shared_epoch_support_from_a_live_daemon() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    for shared_epoch in [false, true] {
        let clip = Clipboard::new();
        let root = clip.0.path();
        let active = "11111111111111111111111111111111";
        let cache = root.join("data.json");
        fs::write(&cache, json!({"credential_id":active}).to_string()).unwrap();
        clip.write_epoch(100);
        let _daemon = EpochDaemon::new(root, shared_epoch);
        let wl_copy = root.join("wl-copy");
        let holder = holder_args(&wl_copy, &cache, active, "100");
        let copied = clip.run(cli, &holder, "fixture selection");
        assert_eq!(
            copied.status.success(),
            shared_epoch,
            "offline publication with shared-epoch capability {shared_epoch}"
        );
    }
}

fn write_offline_cache(root: &Path) {
    use omawarden::crypto::{derive_master_key, KdfType, SymmetricCryptoKey};

    let email = "offline-copy@example.invalid";
    let master =
        derive_master_key(email, "fixture", KdfType::Pbkdf2Sha256, 100_000, None, None).unwrap();
    let wrap = SymmetricCryptoKey::from_master_key(master.as_slice())
        .encrypt(&[42; 64])
        .unwrap();
    let user_key = SymmetricCryptoKey::from_raw_bytes(&[42; 64]).unwrap();
    fs::write(
        root.join("data.json"),
        json!({
            "server_url": "https://fixture.invalid",
            "user_email": email,
            "credential_id": "11111111111111111111111111111111",
            "enc_user_key": wrap,
            "kdf": 0,
            "kdf_iterations": 100_000,
            "ciphers": [{
                "id": "offline-item", "type": 1,
                "name": user_key.encrypt_string("Offline item").unwrap(),
                "login": {
                    "password": user_key.encrypt_string("offline secret").unwrap(),
                    "totp": user_key.encrypt_string("JBSWY3DPEHPK3PXP").unwrap()
                }
            }]
        })
        .to_string(),
    )
    .unwrap();
}

#[test]
fn offline_copy_captures_the_epoch_before_prompting_for_the_master_password() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let clip = Clipboard::new();
    let root = clip.0.path();
    write_offline_cache(root);

    let command = || clip.command(cli);
    let copy_args = ["copy", "offline-item", "--password", "--timeout", "0"];
    let mut pending = command()
        .args(copy_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut pending_stdin = pending.stdin.take().unwrap();

    let epoch_path = root.join("omawarden.lock-epoch");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !epoch_path.exists() {
        assert!(
            Instant::now() < deadline,
            "copy did not capture the epoch before prompting"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let captured: u64 = fs::read_to_string(&epoch_path).unwrap().parse().unwrap();

    let lock = command().args(["auth", "lock"]).output().unwrap();
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stdout)
    );
    let advanced: u64 = fs::read_to_string(&epoch_path).unwrap().parse().unwrap();
    assert_ne!(advanced, captured, "lock must advance the captured epoch");

    writeln!(pending_stdin, "fixture").unwrap();
    drop(pending_stdin);
    let pending_output = pending.wait_with_output().unwrap();
    assert!(
        !pending_output.status.success(),
        "the copy must fail after the lock: {}",
        String::from_utf8_lossy(&pending_output.stdout)
    );
    assert!(clip.paste().is_none());

    let mut fresh = command()
        .args(copy_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    writeln!(fresh.stdin.take().unwrap(), "fixture").unwrap();
    let fresh_output = fresh.wait_with_output().unwrap();
    assert!(
        fresh_output.status.success(),
        "{}",
        String::from_utf8_lossy(&fresh_output.stdout)
    );
    assert_eq!(clip.paste().as_deref(), Some("offline secret"));
}

#[test]
fn offline_copy_rejects_a_legacy_daemon_before_reading_the_password() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let cases: [&[&str]; 2] = [
        &["copy", "offline-item", "--password", "--timeout", "0"],
        &["totp", "offline-item", "--copy"],
    ];
    for args in cases {
        let clip = Clipboard::new();
        let root = clip.0.path();
        write_offline_cache(root);
        let _daemon = EpochDaemon::new(root, false);
        let mut copy = clip.command(cli).args(args).spawn().unwrap();
        // Keep stdin open: rejecting an unsupported owner must precede the
        // password read and encrypted-cache authorization.
        let input = copy.stdin.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = copy.try_wait().unwrap() {
                break status;
            }
            if Instant::now() >= deadline {
                copy.kill().unwrap();
                copy.wait().unwrap();
                panic!("{args:?} read the password before rejecting the legacy daemon");
            }
            thread::sleep(Duration::from_millis(5));
        };
        drop(input);
        assert!(!status.success());
        let result = copy.wait_with_output().unwrap();
        let reply: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(reply["error"]
            .as_str()
            .unwrap()
            .contains("shared lock epoch support"));
        assert!(!root.join("omawarden.lock-epoch").exists());
        assert!(clip.paste().is_none());
    }
}

#[test]
fn offline_copy_rechecks_daemon_capability_after_authorization() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    for initially_running in [false, true] {
        let clip = Clipboard::new();
        let root = clip.0.path();
        write_offline_cache(root);
        let mut daemon = initially_running.then(|| EpochDaemon::new(root, true));
        let mut copy = clip
            .command(cli)
            .args(["copy", "offline-item", "--password", "--timeout", "0"])
            .spawn()
            .unwrap();
        let input = copy.stdin.take().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while !root.join("omawarden.lock-epoch").exists() {
            assert!(Instant::now() < deadline, "copy did not capture its epoch");
            thread::sleep(Duration::from_millis(5));
        }
        if let Some(daemon) = &daemon {
            daemon.shared_epoch.store(false, Ordering::SeqCst);
        } else {
            daemon = Some(EpochDaemon::new(root, false));
        }
        let mut input = input;
        writeln!(input, "fixture").unwrap();
        drop(input);
        let result = copy.wait_with_output().unwrap();
        assert!(
            !result.status.success(),
            "an epoch-unaware owner accepted a queued copy"
        );
        assert!(clip.paste().is_none());
        drop(daemon);
    }
}

#[test]
fn unreachable_daemon_owner_blocks_offline_copy_and_local_lock_fallback() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let clip = Clipboard::new();
    let root = clip.0.path();
    let cache = root.join("data.json");
    let active = "11111111111111111111111111111111";
    fs::write(&cache, json!({"credential_id":active}).to_string()).unwrap();
    clip.write_epoch(100);
    let owner = File::create(root.join("omawarden.instance.lock")).unwrap();
    owner.lock().unwrap();
    let wl_copy = root.join("wl-copy");
    let holder = holder_args(&wl_copy, &cache, active, "100");
    assert!(!clip.run(cli, &holder, "fixture selection").status.success());
    for action in ["lock", "logout"] {
        let result = clip.run(cli, &["auth", action], "");
        assert!(
            !result.status.success(),
            "{action} treated a busy owner as absent"
        );
        let reply: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(reply["ok"], false);
        assert!(reply["warning"].is_null());
        assert!(reply["error"]
            .as_str()
            .is_some_and(|message| !message.is_empty()));
        assert_eq!(clip.epoch(), 100);
        assert_eq!(
            serde_json::from_slice::<Value>(&fs::read(&cache).unwrap()).unwrap()["credential_id"],
            active
        );
    }
    assert!(clip.paste().is_none());
}

#[test]
fn cli_lock_falls_back_when_an_old_daemon_omits_the_epoch() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let clip = Clipboard::new();
    let runtime = clip.0.path();
    let cache = runtime.join("data.json");
    let active = "11111111111111111111111111111111";
    fs::write(&cache, json!({"credential_id":active}).to_string()).unwrap();
    let keyring = runtime.join("secret-tool");
    fs::write(
        &keyring,
        "#!/bin/sh\ncase \"$1\" in clear|search) exit 0;; *) exit 1;; esac\n",
    )
    .unwrap();
    fs::set_permissions(&keyring, fs::Permissions::from_mode(0o700)).unwrap();
    let wl_copy = runtime.join("wl-copy");
    clip.write_epoch(30);

    let socket = runtime.join("omawarden.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut line = String::new();
        BufReader::new(&stream).read_line(&mut line).unwrap();
        let request: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["action"], "lock");
        // A legacy daemon has no shared epoch field.
        writeln!(stream, "{}", json!({"ok":true,"outputs_cleared":true})).unwrap();
    });

    let lock = clip.run(cli, &["auth", "lock"], "");
    assert!(
        lock.status.success(),
        "{}",
        String::from_utf8_lossy(&lock.stdout)
    );
    server.join().unwrap();
    assert_eq!(
        clip.epoch(),
        31,
        "an old daemon reply must not suppress the local fallback"
    );

    let stale = holder_args(&wl_copy, &cache, active, "30");
    assert!(!clip.run(cli, &stale, "stale selection").status.success());
    assert!(clip.paste().is_none());
    let fresh = holder_args(&wl_copy, &cache, active, "31");
    assert!(clip.run(cli, &fresh, "fresh selection").status.success());
    assert_eq!(clip.paste().as_deref(), Some("fresh selection"));
}

#[test]
fn logout_invalidates_pending_offline_copies_when_cache_removal_fails() {
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let clip = Clipboard::new();
    let runtime = clip.0.path();
    let active = "11111111111111111111111111111111";
    let data_dir = runtime.join("cache");
    fs::create_dir(&data_dir).unwrap();
    let cache = data_dir.join("data.json");
    fs::write(&cache, json!({"credential_id":active}).to_string()).unwrap();
    let credentials = cache.with_extension("credentials");
    fs::create_dir(&credentials).unwrap();
    for marker in [active, "legacy"] {
        fs::write(credentials.join(marker), []).unwrap();
    }
    fs::write(data_dir.join("data.account.lock"), []).unwrap();
    fs::write(data_dir.join("data.daemon.lock"), []).unwrap();
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o500)).unwrap();

    let wl_copy = runtime.join("wl-copy");
    clip.write_epoch(50);
    let stale = holder_args(&wl_copy, &cache, active, "50");
    assert!(clip
        .run(cli, &stale, "authorized selection")
        .status
        .success());

    // The cache is readable, but the read-only data directory rejects the
    // temporary file used to replace data.json. Logout therefore fails after
    // the hard-lock epoch transition, not before it.
    let logout = Command::new(cli)
        .args(["auth", "logout"])
        .env_clear()
        .env("HOME", runtime)
        .env("PATH", format!("{}:/usr/bin:/bin", runtime.display()))
        .env("XDG_RUNTIME_DIR", runtime)
        .env("OMAWARDEN_DATA_DIR", &data_dir)
        .env("OMAWARDEN_CONFIG_DIR", runtime)
        .env("WAYLAND_DISPLAY", "fixture-wayland")
        .output()
        .unwrap();
    assert!(
        !logout.status.success(),
        "cache replacement was expected to fail: {}",
        String::from_utf8_lossy(&logout.stdout)
    );
    assert_eq!(
        clip.epoch(),
        51,
        "logout advanced the epoch before the cache failure"
    );
    assert_eq!(
        clip.paste().as_deref(),
        Some("authorized selection"),
        "failed cache replacement must not clear the published selection"
    );

    assert!(
        !clip.run(cli, &stale, "stale selection").status.success(),
        "a logout that failed cache replacement still invalidates queued copies"
    );
    let fresh = holder_args(&wl_copy, &cache, active, "51");
    assert!(clip.run(cli, &fresh, "fresh selection").status.success());
    assert_eq!(clip.paste().as_deref(), Some("fresh selection"));
    fs::set_permissions(&data_dir, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn clipboard_forces_text_plain_mime_type_for_pem_and_all_content() {
    let clip = Clipboard::new();
    let pem_content =
        "-----BEGIN OPENSSH PRIVATE KEY-----\ntest\n-----END OPENSSH PRIVATE KEY-----\n";
    assert!(clip.copy(pem_content, "5").status.success());
    assert_eq!(clip.paste().as_deref(), Some(pem_content));
    let args = clip.recorded_args();
    assert!(
        args.iter().any(|line| line.contains("--type text/plain")),
        "wl-copy must be invoked with --type text/plain, got: {:?}",
        args
    );
}

#[test]
fn clipboard_without_expiry_forces_text_plain_mime_type() {
    let clip = Clipboard::new();
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    assert!(clip
        .run(
            cli,
            &["copy", "--stdin", "--timeout", "0"],
            "unexpired text"
        )
        .status
        .success());
    assert_eq!(clip.paste().as_deref(), Some("unexpired text"));
    let args = clip.recorded_args();
    assert!(
        args.iter().any(|line| line.contains("--type text/plain")),
        "wl-copy must be invoked with --type text/plain for unexpired copies, got: {:?}",
        args
    );
}

#[test]
fn clipboard_holder_supports_explicit_provider_and_binary_path() {
    let clip = Clipboard::new();
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let wl_copy = clip.0.path().join("wl-copy");

    assert!(clip
        .run(
            cli,
            &[
                "clipboard-holder",
                "0",
                "--provider",
                "wayland",
                "--binary-path",
                wl_copy.to_str().unwrap(),
                "--public",
            ],
            "provider explicit text"
        )
        .status
        .success());
    assert_eq!(clip.paste().as_deref(), Some("provider explicit text"));
}

#[test]
fn clipboard_provider_env_override() {
    let clip = Clipboard::new();
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let wl_copy = clip.0.path().join("wl-copy");

    let dir = clip.0.path();
    let mut child = Command::new(cli)
        .args(["copy", "--stdin", "--timeout", "0"])
        .env("XDG_RUNTIME_DIR", dir)
        .env("XDG_CONFIG_HOME", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("HOME", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "wayland")
        .env("OMA_WL_COPY_PATH", &wl_copy)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"env-routed text").unwrap();
    drop(stdin);
    assert!(child.wait().unwrap().success());
    assert_eq!(clip.paste().as_deref(), Some("env-routed text"));
}

#[test]
fn clipboard_provider_env_override_mock() {
    let clip = Clipboard::new();
    let cli = Path::new(env!("CARGO_BIN_EXE_omawarden"));
    let dir = clip.0.path();

    let mut child = Command::new(cli)
        .args(["copy", "--stdin", "--timeout", "0"])
        .env("XDG_RUNTIME_DIR", dir)
        .env("XDG_CONFIG_HOME", dir)
        .env("OMAWARDEN_CONFIG_DIR", dir)
        .env("OMAWARDEN_DATA_DIR", dir)
        .env("HOME", dir)
        .env("OMA_CLIPBOARD_PROVIDER", "mock")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"mock text").unwrap();
    drop(stdin);
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
}

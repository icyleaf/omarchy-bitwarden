use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
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

impl Clipboard {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let mock = dir.path().join("wl-copy");
        fs::write(&mock, WL_COPY).unwrap();
        fs::set_permissions(&mock, fs::Permissions::from_mode(0o755)).unwrap();
        Self(dir)
    }

    fn run(&self, program: &Path, args: &[&str], text: &str) -> Output {
        let dir = self.0.path();
        let mut child = Command::new(program)
            .args(args)
            .env("XDG_RUNTIME_DIR", dir)
            .env("XDG_CONFIG_HOME", dir)
            .env("OMAWARDEN_CONFIG_DIR", dir)
            .env("OMAWARDEN_DATA_DIR", dir)
            .env("HOME", dir)
            .env("WAYLAND_DISPLAY", "fixture-wayland")
            .env_remove("WAYLAND_SOCKET")
            .env_remove("DBUS_SESSION_BUS_ADDRESS")
            .env("PATH", format!("{}:/usr/bin:/bin", dir.display()))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
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
    let holder = [
        "clipboard-holder",
        "0",
        wl_copy.to_str().unwrap(),
        "--cache-path",
        cache.to_str().unwrap(),
        "--expected-credential-id",
        active,
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

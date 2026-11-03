use std::fs::{self, File};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
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
            .env("HOME", dir)
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

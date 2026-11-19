use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

struct MacOsFixture {
    dir: TempDir,
    pbcopy_log: PathBuf,
    mock_pbcopy: PathBuf,
}

impl MacOsFixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let pbcopy_log = dir.path().join("pbcopy.log");
        let mock_pbcopy = dir.path().join("pbcopy");

        let script = format!(
            r#"#!/bin/sh
cat > "{}"
exit 0
"#,
            pbcopy_log.display()
        );

        fs::write(&mock_pbcopy, script).unwrap();
        fs::set_permissions(&mock_pbcopy, fs::Permissions::from_mode(0o755)).unwrap();

        Self {
            dir,
            pbcopy_log,
            mock_pbcopy,
        }
    }

    fn read_clipboard(&self) -> String {
        fs::read_to_string(&self.pbcopy_log).unwrap_or_default()
    }
}

fn omawarden_bin() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test exe name
    if path.ends_with("deps") {
        path.pop();
    }
    path.push("omawarden");
    path
}

#[test]
fn test_macos_clipboard_holder_with_explicit_provider() {
    let fixture = MacOsFixture::new();
    let bin = omawarden_bin();
    if !bin.exists() {
        return;
    }

    // Run clipboard-holder with 1s timeout and our mock pbcopy binary
    let mut child = Command::new(&bin)
        .args([
            "clipboard-holder",
            "1",
            "--provider",
            "macos",
            "--binary-path",
            fixture.mock_pbcopy.to_str().unwrap(),
        ])
        .env("XDG_RUNTIME_DIR", fixture.dir.path())
        .env("XDG_CONFIG_HOME", fixture.dir.path())
        .env("OMAWARDEN_CONFIG_DIR", fixture.dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(b"macos_fixture_token").unwrap();
    drop(stdin);

    // Read the 1-byte handshake sent by clipboard-holder
    let mut stdout = child.stdout.take().unwrap();
    let mut handshake = [0u8; 1];
    use std::io::Read;
    let _ = stdout.read_exact(&mut handshake);

    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(fixture.read_clipboard(), "macos_fixture_token");

    // After 1.5s, the holder TTL timer triggers clear
    std::thread::sleep(Duration::from_millis(1500));
    assert!(fixture.read_clipboard().is_empty());
    let _ = child.wait();
}

#[test]
#[cfg(target_os = "macos")]
fn test_macos_real_cli_copy_and_pasteboard() {
    let bin = omawarden_bin();
    if !bin.exists() {
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    let token = format!(
        "real_mac_token_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );

    let mut child = Command::new(&bin)
        .args(["copy", "--stdin", "--sensitive", "--timeout", "1"])
        .env("XDG_RUNTIME_DIR", dir.path())
        .env("XDG_CONFIG_HOME", dir.path())
        .env("OMAWARDEN_CONFIG_DIR", dir.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    child
        .stdin
        .take()
        .unwrap()
        .write_all(token.as_bytes())
        .unwrap();
    let status = child.wait().unwrap();
    assert!(status.success());

    // Verify using pbpaste that clipboard contains our token
    let pbpaste_output = Command::new("pbpaste").output().unwrap();
    assert_eq!(String::from_utf8_lossy(&pbpaste_output.stdout), token);

    // After 1.5s (timeout 1s expired), verify it has been cleared
    std::thread::sleep(Duration::from_millis(1500));
    let after_output = Command::new("pbpaste").output().unwrap();
    assert_ne!(String::from_utf8_lossy(&after_output.stdout), token);
}

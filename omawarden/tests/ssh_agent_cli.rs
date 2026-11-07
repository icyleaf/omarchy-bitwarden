//! The `ssh-agent` and `config` commands, run against the real binary with its
//! own config, data and runtime directories.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Output};

struct Sandbox {
    dir: tempfile::TempDir,
}

impl Sandbox {
    fn new() -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        for sub in ["config", "data", "runtime", "home"] {
            std::fs::create_dir(dir.path().join(sub)).unwrap();
        }
        Sandbox { dir }
    }

    fn path(&self, sub: &str) -> std::path::PathBuf {
        self.dir.path().join(sub)
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_omawarden"))
            .args(args)
            .env("OMAWARDEN_CONFIG_DIR", self.path("config"))
            .env("OMAWARDEN_DATA_DIR", self.path("data"))
            .env("XDG_RUNTIME_DIR", self.path("runtime"))
            .env("HOME", self.path("home"))
            .env_remove("SSH_AUTH_SOCK")
            .output()
            .unwrap()
    }

    fn stdout(&self, args: &[&str]) -> String {
        let out = self.run(args);
        assert!(out.status.success(), "{args:?}: {out:?}");
        String::from_utf8(out.stdout).unwrap()
    }

    /// Ask a running daemon to exit.
    fn stop_daemon(&self) {
        let socket = self.path("runtime").join("omawarden.sock");
        if let Ok(mut stream) = UnixStream::connect(socket) {
            let _ = stream.write_all(b"{\"action\":\"stop\",\"admin\":true}\n");
            let mut reply = String::new();
            let _ = stream.read_to_string(&mut reply);
        }
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        self.stop_daemon();
    }
}

fn json(text: &str) -> serde_json::Value {
    serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

#[test]
fn ssh_agent_settings_round_trip_through_the_cli() {
    let sb = Sandbox::new();
    assert_eq!(sb.stdout(&["config", "get", "ssh_agent"]).trim(), "false");
    assert_eq!(
        sb.stdout(&["config", "get", "ssh_agent_confirm"]).trim(),
        "first-use"
    );

    let out = sb.stdout(&[
        "config",
        "set",
        "--ssh-agent",
        "true",
        "--ssh-agent-confirm",
        "always",
    ]);
    let shown = json(&out[out.find('{').unwrap()..]);
    assert_eq!(shown["ssh_agent_enabled"], true);
    assert_eq!(shown["ssh_agent_confirm"], "always");

    assert_eq!(
        sb.stdout(&["config", "get", "ssh_agent_enabled"]).trim(),
        "true"
    );
    assert_eq!(sb.stdout(&["config", "get", "ssh_agent"]).trim(), "true");
    assert_eq!(
        sb.stdout(&["config", "get", "ssh_agent_confirm"]).trim(),
        "always"
    );

    // Accepted spellings of "off".
    sb.stdout(&["config", "set", "--ssh-agent", "false"]);
    assert_eq!(sb.stdout(&["config", "get", "ssh_agent"]).trim(), "false");
    sb.stdout(&["config", "set", "--ssh-agent", "yes"]);
    assert_eq!(sb.stdout(&["config", "get", "ssh_agent"]).trim(), "true");
}

#[test]
fn an_unknown_confirm_policy_is_rejected_and_nothing_is_saved() {
    let sb = Sandbox::new();
    let out = sb.run(&["config", "set", "--ssh-agent-confirm", "sometimes"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("ssh_agent_confirm"));
    assert_eq!(
        sb.stdout(&["config", "get", "ssh_agent_confirm"]).trim(),
        "first-use"
    );
}

#[test]
fn the_ssh_agent_commands_talk_to_the_daemon() {
    let sb = Sandbox::new();
    sb.stdout(&["config", "set", "--ssh-agent", "true"]);

    // `ssh-agent status` starts the daemon, which starts the agent.
    let status = json(&sb.stdout(&["ssh-agent", "status"]));
    assert_eq!(status["ok"], true);
    assert_eq!(status["running"], true);
    assert_eq!(status["enabled"], true);
    assert_eq!(status["confirm"], "first-use");
    let socket = status["socket"].as_str().unwrap();
    assert!(Path::new(socket).ends_with("omawarden-ssh-agent.sock"));
    assert!(Path::new(socket).exists());

    let pending = json(&sb.stdout(&["ssh-agent", "pending"]));
    assert_eq!(pending["prompts"], serde_json::json!([]));

    // Nothing is waiting, so the answer isn't delivered and the command fails.
    let out = sb.run(&["ssh-agent", "reply", "7", "--allow"]);
    assert!(!out.status.success());
    let reply = json(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(reply["delivered"], false);
    assert!(!sb
        .run(&["ssh-agent", "reply", "7", "--deny"])
        .status
        .success());

    // Turning it off in settings stops the agent without a restart.
    sb.stdout(&["config", "set", "--ssh-agent", "false"]);
    let status = json(&sb.stdout(&["ssh-agent", "status"]));
    assert_eq!(status["running"], false);
    assert!(!Path::new(socket).exists());

    // Stopping the daemon takes the agent socket with it.
    sb.stdout(&["config", "set", "--ssh-agent", "true"]);
    assert_eq!(json(&sb.stdout(&["ssh-agent", "status"]))["running"], true);
    assert!(Path::new(socket).exists());
    sb.stop_daemon();
    assert!(!Path::new(socket).exists());
}

#[test]
fn a_blocked_agent_socket_does_not_stop_the_daemon() {
    let sb = Sandbox::new();
    sb.stdout(&["config", "set", "--ssh-agent", "true"]);
    // Something that isn't ours sits where the socket goes.
    std::os::unix::fs::symlink(
        "/tmp/elsewhere",
        sb.path("runtime").join("omawarden-ssh-agent.sock"),
    )
    .unwrap();
    let status = json(&sb.stdout(&["ssh-agent", "status"]));
    assert_eq!(status["enabled"], true);
    assert_eq!(status["running"], false);
}

#[test]
fn the_command_fails_when_the_daemon_cannot_start() {
    let sb = Sandbox::new();
    // A directory sits where the daemon's socket goes, so it can't bind.
    std::fs::create_dir(sb.path("runtime").join("omawarden.sock")).unwrap();
    let out = sb.run(&["ssh-agent", "status"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not responding"));
}

#[test]
fn a_daemon_from_another_build_with_compatible_protocol_is_kept() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    let sb = Sandbox::new();
    sb.stdout(&["config", "set", "--ssh-agent", "true"]);
    let socket = sb.path("runtime").join("omawarden.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    // ADR-0028: A daemon from another commit with compatible protocol_version: 1
    // is kept and NOT replaced or stopped, even when locked.
    let old_daemon = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for stream in listener.incoming() {
            let mut stream = stream.unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            let action = json(&line)["action"].as_str().unwrap().to_string();
            let reply = match action.as_str() {
                "ping" => serde_json::json!({
                    "ok": true,
                    "protocol_version": 1,
                    "commit": "other-commit",
                    "unlocked": false
                }),
                "ssh_agent_status" => serde_json::json!({
                    "ok": true,
                    "running": true,
                    "socket": "/tmp/test.sock"
                }),
                _ => serde_json::json!({ "ok": true }),
            };
            writeln!(stream, "{reply}").unwrap();
            seen.push(action.clone());
            if action == "ssh_agent_status" {
                return seen;
            }
        }
        seen
    });

    let status = json(&sb.stdout(&["ssh-agent", "status"]));
    assert_eq!(
        status["running"], true,
        "the compatible daemon answers status"
    );
    assert_eq!(old_daemon.join().unwrap(), ["ping", "ssh_agent_status"]);
}

#[test]
fn reply_needs_allow_or_deny() {
    let sb = Sandbox::new();
    assert!(!sb.run(&["ssh-agent", "reply", "1"]).status.success());
    assert!(!sb
        .run(&["ssh-agent", "reply", "1", "--allow", "--deny"])
        .status
        .success());
}

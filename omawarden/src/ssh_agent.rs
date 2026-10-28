//! OpenSSH agent backed by the vault's SSH key items.
//!
//! The daemon listens on `$XDG_RUNTIME_DIR/omawarden-ssh-agent.sock` when
//! `ssh_agent_enabled` is set. Private keys are parsed only for the duration
//! of a single signature. Signing asks for confirmation in the Omarchy overlay
//! according to `ssh_agent_confirm`:
//!
//! - `always`: every signature
//! - `first-use` (default): once per key, client program and the app it runs
//!   in (terminal, editor…), until the daemon exits (normally at logout);
//!   re-locking the vault does not reset it
//! - `never`: no prompt (the vault still has to be unlocked)
//!
//! Requests that arrive through agent forwarding (OpenSSH's
//! `session-bind@openssh.com` with `is_forwarding`) are always confirmed,
//! whatever the policy, so a remote host can't use your keys silently.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use serde::Serialize;
use sha2::Digest;
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use zeroize::Zeroizing;

use crate::daemon::DaemonState;

const FAILURE: u8 = 5;
const SUCCESS: u8 = 6;
const REQUEST_IDENTITIES: u8 = 11;
const IDENTITIES_ANSWER: u8 = 12;
const SIGN_REQUEST: u8 = 13;
const SIGN_RESPONSE: u8 = 14;
const EXTENSION: u8 = 27;

const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

/// Largest agent message accepted (OpenSSH uses 256 KiB as well).
const MAX_MESSAGE: usize = 256 * 1024;
const PROMPT_TIMEOUT: Duration = Duration::from_secs(60);
const UNLOCK_TIMEOUT: Duration = Duration::from_secs(60);

pub fn socket_path() -> PathBuf {
    crate::daemon::get_runtime_dir().join("omawarden-ssh-agent.sock")
}

// ---------------------------------------------------------------------------
// Confirmation prompts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirm {
    Always,
    FirstUse,
    Never,
}

impl Confirm {
    pub fn parse(s: &str) -> Confirm {
        match s {
            "always" => Confirm::Always,
            "never" => Confirm::Never,
            "first-use" => Confirm::FirstUse,
            // A misspelt policy must not quietly ask less often.
            _ => Confirm::Always,
        }
    }
}

/// What the overlay shows for a pending signature.
#[derive(Debug, Clone, Serialize)]
pub struct Prompt {
    pub id: u64,
    /// Short question, e.g. "Sign a Git commit?".
    pub title: String,
    /// What is being signed, e.g. "SSH login as git@github.com".
    pub action: String,
    pub key_name: String,
    pub fingerprint: String,
    /// Requesting program, e.g. "git (ssh)".
    pub client: String,
    pub command: String,
    pub forwarded: bool,
    /// Whether approving is remembered for this key, program and app until
    /// logout (first-use policy and not forwarded), so the UI can say so.
    pub remembered: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct Decision {
    pub approve: bool,
}

struct Pending {
    prompt: Prompt,
    decision: Option<Decision>,
}

pub struct SshAgent {
    pending: Mutex<HashMap<u64, Pending>>,
    answered: Condvar,
    next_id: AtomicU64,
    /// Approved "fingerprint|client exe|app exe" triples. They outlive vault locks:
    /// the vault re-locks on every screen lock, and unlocking already proves
    /// presence, so asking again each time adds nothing.
    approvals: Mutex<HashSet<String>>,
    /// Whether the socket is currently bound.
    running: std::sync::atomic::AtomicBool,
    /// An unlock prompt is already on screen.
    unlock_prompted: std::sync::atomic::AtomicBool,
    prompt_timeout: Duration,
    unlock_timeout: Duration,
}

impl Default for SshAgent {
    fn default() -> Self {
        SshAgent {
            pending: Mutex::new(HashMap::new()),
            answered: Condvar::new(),
            next_id: AtomicU64::new(1),
            approvals: Mutex::new(HashSet::new()),
            running: std::sync::atomic::AtomicBool::new(false),
            unlock_prompted: std::sync::atomic::AtomicBool::new(false),
            prompt_timeout: PROMPT_TIMEOUT,
            unlock_timeout: UNLOCK_TIMEOUT,
        }
    }
}

impl SshAgent {
    /// Pending prompts, oldest first (for the overlay).
    pub fn pending(&self) -> Vec<Prompt> {
        let mut list: Vec<Prompt> = self
            .pending
            .lock()
            .map(|p| {
                p.values()
                    .filter(|p| p.decision.is_none())
                    .map(|p| p.prompt.clone())
                    .collect()
            })
            .unwrap_or_default();
        list.sort_by_key(|p| p.id);
        list
    }

    /// Answer a prompt. Returns false if it no longer exists.
    pub fn reply(&self, id: u64, decision: Decision) -> bool {
        let Ok(mut pending) = self.pending.lock() else {
            return false;
        };
        match pending.get_mut(&id) {
            Some(p) if p.decision.is_none() => {
                p.decision = Some(decision);
                self.answered.notify_all();
                true
            }
            _ => false,
        }
    }

    fn is_approved(&self, key: &str) -> bool {
        self.approvals.lock().is_ok_and(|a| a.contains(key))
    }

    fn approve(&self, key: String) {
        if let Ok(mut a) = self.approvals.lock() {
            a.insert(key);
        }
    }
}

/// Post a prompt and wait for its answer; no answer within the timeout denies.
fn ask(host: &Arc<dyn Host>, mut prompt: Prompt) -> Decision {
    let agent = host.agent();
    let id = agent.next_id.fetch_add(1, Ordering::Relaxed);
    prompt.id = id;
    let (title, body) = notification_text(&prompt);
    if let Ok(mut pending) = agent.pending.lock() {
        pending.insert(
            id,
            Pending {
                prompt,
                decision: None,
            },
        );
    }
    // Open the approval card straight away, like a polkit prompt: a
    // notification is too easy to miss. Without the shell, fall back to a
    // notification for servers that render Approve and Deny buttons.
    if !host.summon_overlay(&serde_json::json!({ "view": "ssh-approval", "id": id })) {
        let h = host.clone();
        host.notify(
            &title,
            &body,
            &[("approve", "Approve"), ("deny", "Deny")],
            agent.prompt_timeout,
            Box::new(move |action| {
                if let "approve" | "deny" = action {
                    h.agent().reply(
                        id,
                        Decision {
                            approve: action == "approve",
                        },
                    );
                }
            }),
        );
    }

    let deadline = Instant::now() + agent.prompt_timeout;
    let Ok(mut pending) = agent.pending.lock() else {
        return Decision::default();
    };
    let decision = loop {
        if let Some(d) = pending.get(&id).and_then(|p| p.decision) {
            break d;
        }
        let now = Instant::now();
        if now >= deadline {
            break Decision::default();
        }
        match agent.answered.wait_timeout(pending, deadline - now) {
            Ok((guard, _)) => pending = guard,
            Err(_) => return Decision::default(),
        }
    };
    pending.remove(&id);
    decision
}

/// Notification text for a pending signature, used when the approval card
/// can't be shown. At most three short lines, since Omarchy's card shows no
/// more, escaped because servers treat the body as markup.
fn notification_text(p: &Prompt) -> (String, String) {
    let mut body = format!("{}\n{} \u{b7} {}", p.action, p.key_name, p.client);
    if p.forwarded {
        body.push_str("\nForwarded from a remote host");
    } else if p.remembered {
        body.push_str("\nRemembered until logout");
    }
    (p.title.clone(), escape_markup(&body))
}

fn escape_markup(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Show a system notification with action buttons and hand the chosen action
/// (empty when dismissed or expired) to `on_action` from a worker thread.
/// Returns false if `notify-send` couldn't be started.
fn notify(
    title: &str,
    body: &str,
    actions: &[(&str, &str)],
    timeout: Duration,
    on_action: impl FnOnce(&str) + Send + 'static,
) -> bool {
    let mut cmd = std::process::Command::new("notify-send");
    cmd.args([
        "--app-name=Bitwarden",
        // A Nerd Font key, drawn by Omarchy in the icon slot. Its card shows a
        // broken-image placeholder for theme icons it can't find, such as
        // `dialog-password` under Yaru, and a found icon would hide the glyph.
        "--hint=string:omarchy-glyph:\u{f0306}",
        "--urgency=critical",
    ])
    .arg(format!("--expire-time={}", timeout.as_millis()));
    for (name, label) in actions {
        cmd.arg("-A").arg(format!("{name}={label}"));
    }
    cmd.arg(title)
        .arg(body)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let Ok(child) = cmd.spawn() else {
        return false;
    };
    std::thread::spawn(move || {
        let action = child
            .wait_with_output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default();
        on_action(&action);
    });
    true
}

/// Open the Omarchy Bitwarden overlay (for a prompt, or to unlock). Returns
/// whether the shell opened it; it answers "ok" when it did.
fn summon_overlay(payload: &serde_json::Value) -> bool {
    let Some(shell) = crate::daemon::get_omarchy_shell_cmd() else {
        crate::log_warn!(
            "omawarden:ssh-agent",
            "omarchy-shell not found; cannot show the confirmation prompt"
        );
        return false;
    };
    let mut cmd = std::process::Command::new(shell);
    cmd.args(["shell", "summon", "icyleaf.bitwarden", &payload.to_string()])
        .stdin(std::process::Stdio::null());
    match cmd.output() {
        Ok(out) => {
            let reply = String::from_utf8_lossy(&out.stdout).trim().to_string();
            let opened = out.status.success() && reply == "ok";
            if !opened {
                crate::log_warn!(
                    "omawarden:ssh-agent",
                    "omarchy-shell did not open the overlay ({}); replied {:?}, stderr {:?}",
                    out.status,
                    reply,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            opened
        }
        Err(e) => {
            crate::log_warn!("omawarden:ssh-agent", "could not summon the overlay: {}", e);
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/// What the agent needs from the daemon and the desktop. The daemon is the
/// real host; tests drive the protocol against a fake one.
trait Host: Send + Sync + 'static {
    fn agent(&self) -> &Arc<SshAgent>;
    fn is_unlocked(&self) -> bool;
    fn keys(&self) -> Vec<AgentKey>;
    fn policy(&self) -> Confirm;
    /// A signature was made (keeps the vault from idle-locking).
    fn record_activity(&self);
    fn known_host(&self, hostkey: &[u8]) -> Option<String>;
    /// See [`notify`].
    fn notify(
        &self,
        title: &str,
        body: &str,
        actions: &[(&str, &str)],
        timeout: Duration,
        on_action: Box<dyn FnOnce(&str) + Send>,
    ) -> bool;
    /// See [`summon_overlay`].
    fn summon_overlay(&self, payload: &serde_json::Value) -> bool;
    /// ADR-0025: attempt the polkit-backed quick unlock. False means the
    /// caller should fall back to the overlay summon.
    fn try_quick_unlock(&self) -> bool {
        false
    }
}

impl Host for DaemonState {
    fn agent(&self) -> &Arc<SshAgent> {
        &self.ssh_agent
    }
    fn is_unlocked(&self) -> bool {
        self.vault_mgr.is_unlocked()
    }
    fn keys(&self) -> Vec<AgentKey> {
        vault_keys(self)
    }
    fn policy(&self) -> Confirm {
        Confirm::parse(
            &crate::config::ConfigManager::default()
                .load()
                .ssh_agent_confirm,
        )
    }
    fn record_activity(&self) {
        self.touch_activity();
    }
    fn known_host(&self, hostkey: &[u8]) -> Option<String> {
        known_host_for(hostkey)
    }
    fn notify(
        &self,
        title: &str,
        body: &str,
        actions: &[(&str, &str)],
        timeout: Duration,
        on_action: Box<dyn FnOnce(&str) + Send>,
    ) -> bool {
        notify(title, body, actions, timeout, on_action)
    }
    fn summon_overlay(&self, payload: &serde_json::Value) -> bool {
        summon_overlay(payload)
    }
    fn try_quick_unlock(&self) -> bool {
        self.perform_quick_unlock().is_ok()
    }
}

/// Start or stop the agent to match the `ssh_agent_enabled` setting, without
/// restarting the daemon (which would lock the vault).
pub fn apply(state: &Arc<DaemonState>) -> std::io::Result<bool> {
    let enabled = crate::config::ConfigManager::default()
        .load()
        .ssh_agent_enabled;
    let running = state.ssh_agent.running.load(Ordering::SeqCst);
    if enabled && !running {
        spawn(state.clone())?;
    } else if !enabled && running {
        // An unlinked socket can't be connected to; the idle accept thread
        // ends with the daemon.
        state.ssh_agent.running.store(false, Ordering::SeqCst);
        remove_socket();
        crate::log_info!("omawarden:ssh-agent", "stopped");
    }
    Ok(enabled)
}

pub fn is_running(state: &DaemonState) -> bool {
    state.ssh_agent.running.load(Ordering::SeqCst)
}

/// Bind the agent socket and serve it on background threads.
pub fn spawn(state: Arc<DaemonState>) -> std::io::Result<()> {
    let path = socket_path();
    if path.exists() {
        crate::daemon::validate_socket_path(&path)?;
        let _ = fs::remove_file(&path);
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
    crate::log_info!("omawarden:ssh-agent", "listening on {}", path.display());
    state.ssh_agent.running.store(true, Ordering::SeqCst);
    let host: Arc<dyn Host> = state;
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if !host.agent().running.load(Ordering::SeqCst) {
                break;
            }
            accepted(&host, stream);
        }
    });
    Ok(())
}

/// Serve one accepted connection on its own thread.
fn accepted(host: &Arc<dyn Host>, stream: std::io::Result<UnixStream>) {
    match stream {
        Ok(stream) => {
            let host = host.clone();
            std::thread::spawn(move || {
                let served = crate::daemon::verify_peer_credentials(&stream).and_then(|_| {
                    let peer = Peer::of(&stream);
                    serve(&host, stream, peer)
                });
                if let Err(e) = served {
                    crate::log_debug!("omawarden:ssh-agent", "client ended: {}", e);
                }
            });
        }
        Err(e) => crate::log_warn!("omawarden:ssh-agent", "accept failed: {}", e),
    }
}

pub fn remove_socket() {
    let _ = fs::remove_file(socket_path());
}

/// Per-connection context.
struct Conn {
    peer: Peer,
    /// Destination host learned from a verified session-bind, if known.
    host: Option<String>,
    /// Session id of the verified session-bind: a login request names the
    /// host only when it signs this session.
    session_id: Option<Vec<u8>>,
    forwarded: bool,
}

fn serve(host: &Arc<dyn Host>, mut stream: impl Read + Write, peer: Peer) -> std::io::Result<()> {
    let mut conn = Conn {
        peer,
        host: None,
        session_id: None,
        forwarded: false,
    };
    loop {
        let mut len = [0u8; 4];
        if stream.read_exact(&mut len).is_err() {
            return Ok(());
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 || len > MAX_MESSAGE {
            return Err(std::io::Error::other("bad message length"));
        }
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg)?;
        // Turning the agent off also ends connections that are already open,
        // at their next request.
        if !host.agent().running.load(Ordering::SeqCst) {
            return Ok(());
        }
        let (kind, body) = (msg[0], &msg[1..]);
        match kind {
            REQUEST_IDENTITIES => send(&mut stream, IDENTITIES_ANSWER, &identities(host))?,
            SIGN_REQUEST => match sign(host, &conn, body) {
                Ok(sig) => {
                    let mut out = Vec::new();
                    put_string(&mut out, &sig);
                    send(&mut stream, SIGN_RESPONSE, &out)?;
                }
                Err(e) => {
                    crate::log_info!("omawarden:ssh-agent", "signature refused: {}", e);
                    send(&mut stream, FAILURE, &[])?;
                }
            },
            EXTENSION => {
                let mut r = Reader(body);
                let reply = match (r.string().ok(), r.0) {
                    (Some(b"session-bind@openssh.com"), rest) => match parse_session_bind(rest) {
                        Some(bind) if bind.verifies() => {
                            conn.host = host.known_host(&bind.hostkey);
                            conn.session_id = Some(bind.session_id);
                            // Sticky: a forwarded chain binds once per hop.
                            conn.forwarded |= bind.forwarded;
                            SUCCESS
                        }
                        // Malformed, or not signed by the host key it names.
                        _ => FAILURE,
                    },
                    // Unsupported extension, as OpenSSH's agent answers.
                    _ => FAILURE,
                };
                send(&mut stream, reply, &[])?;
            }
            // Adding/removing keys and locking the agent are managed by the vault.
            _ => send(&mut stream, FAILURE, &[])?,
        }
    }
}

fn send(stream: &mut impl Write, kind: u8, payload: &[u8]) -> std::io::Result<()> {
    let mut frame = Vec::with_capacity(payload.len() + 5);
    frame.extend_from_slice(&((payload.len() + 1) as u32).to_be_bytes());
    frame.push(kind);
    frame.extend_from_slice(payload);
    stream.write_all(&frame)
}

// ---------------------------------------------------------------------------
// Vault keys
// ---------------------------------------------------------------------------

struct AgentKey {
    name: String,
    blob: Vec<u8>,
    fingerprint: String,
    private_key: Zeroizing<String>,
    passphrase: Option<Zeroizing<String>>,
}

fn blob_of(public_key: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(public_key.split_whitespace().nth(1)?)
        .ok()
}

fn vault_keys(state: &DaemonState) -> Vec<AgentKey> {
    state
        .vault_mgr
        .ssh_key_items()
        .into_iter()
        .filter_map(|(name, ssh)| {
            let private_key = Zeroizing::new(ssh.private_key?);
            let passphrase = ssh.passphrase.map(Zeroizing::new);
            // Derive the public key when the item doesn't store one.
            let public = match ssh.public_key {
                Some(p) if !p.trim().is_empty() => p,
                _ => PrivateKey::from_openssh(private_key.as_bytes())
                    .ok()?
                    .public_key()
                    .to_openssh()
                    .ok()?,
            };
            let blob = blob_of(&public)?;
            let fingerprint = ssh
                .fingerprint
                .filter(|f| !f.is_empty())
                .unwrap_or_else(|| {
                    ssh_key::PublicKey::from_openssh(&public)
                        .map(|k| k.fingerprint(HashAlg::Sha256).to_string())
                        .unwrap_or_default()
                });
            Some(AgentKey {
                name,
                blob,
                fingerprint,
                private_key,
                passphrase,
            })
        })
        .collect()
}

/// Wait for the vault to be unlocked, opening the overlay so the person can.
/// With quick unlock enabled (ADR-0025) the first attempt goes through the
/// system authentication prompt instead.
fn wait_for_unlock(host: &Arc<dyn Host>) -> bool {
    if host.is_unlocked() {
        return true;
    }
    let agent = host.agent();
    // One unlock prompt at a time, however many ssh processes are waiting.
    if !agent.unlock_prompted.swap(true, Ordering::SeqCst) {
        if host.try_quick_unlock() {
            agent.unlock_prompted.store(false, Ordering::SeqCst);
            if host.is_unlocked() {
                return true;
            }
        } else {
            host.summon_overlay(&serde_json::json!({}));
            let h = host.clone();
            let spawned = host.notify(
                "Vault locked",
                "An SSH key was requested. Unlock your vault to continue.",
                &[("default", "Unlock")],
                agent.unlock_timeout,
                Box::new(move |action| {
                    if action == "default" {
                        h.summon_overlay(&serde_json::json!({}));
                    }
                    h.agent().unlock_prompted.store(false, Ordering::SeqCst);
                }),
            );
            if !spawned {
                agent.unlock_prompted.store(false, Ordering::SeqCst);
            }
        }
    }
    let deadline = Instant::now() + agent.unlock_timeout;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
        if host.is_unlocked() {
            agent.unlock_prompted.store(false, Ordering::SeqCst);
            return true;
        }
    }
    false
}

fn identities(host: &Arc<dyn Host>) -> Vec<u8> {
    let keys = if wait_for_unlock(host) {
        host.keys()
    } else {
        Vec::new()
    };
    let mut out = (keys.len() as u32).to_be_bytes().to_vec();
    for k in &keys {
        put_string(&mut out, &k.blob);
        put_string(&mut out, k.name.as_bytes());
    }
    out
}

fn sign(host: &Arc<dyn Host>, conn: &Conn, body: &[u8]) -> Result<Vec<u8>, String> {
    let mut r = Reader(body);
    let key_blob = r.string()?.to_vec();
    let data = r.string()?.to_vec();
    let flags = r.u32().unwrap_or(0);

    if !wait_for_unlock(host) {
        return Err("vault is locked".into());
    }
    let find_key = || host.keys().into_iter().find(|k| k.blob == key_blob);
    let mut key = find_key().ok_or("key not in vault")?;

    let agent = host.agent();
    let policy = host.policy();
    let remember_key = format!("{}|{}|{}", key.fingerprint, conn.peer.exe, conn.peer.app);
    // Without /proc/<pid>/exe the requester can't be told apart from any other
    // such request, so nothing is remembered for it.
    let remembers = policy == Confirm::FirstUse && !conn.forwarded && !conn.peer.exe.is_empty();
    let needs_prompt = conn.forwarded
        || match policy {
            Confirm::Never => false,
            Confirm::Always => true,
            Confirm::FirstUse => !(remembers && agent.is_approved(&remember_key)),
        };
    if needs_prompt {
        // Name the host only if the login being signed is for the session that
        // was bound, so a forwarding host can't borrow another host's name.
        let bound_host = conn.host.as_deref().filter(|_| {
            conn.session_id
                .as_deref()
                .is_some_and(|id| Reader(&data).string().ok() == Some(id))
        });
        let (title, action) = describe(&purpose(&data), bound_host);
        let decision = ask(
            host,
            Prompt {
                id: 0,
                title,
                action,
                key_name: key.name.clone(),
                fingerprint: key.fingerprint.clone(),
                client: conn.peer.describe(),
                command: conn.peer.cmdline.clone(),
                forwarded: conn.forwarded,
                remembered: remembers,
            },
        );
        if !decision.approve {
            return Err("denied".into());
        }
        // The prompt can wait a minute: don't sign with a key copied before
        // the vault locked, or one that has since changed.
        if !host.is_unlocked() {
            return Err("vault locked while waiting for approval".into());
        }
        key = find_key().ok_or("key no longer in vault")?;
        if remembers {
            agent.approve(remember_key);
        }
    }

    let mut private = PrivateKey::from_openssh(key.private_key.as_bytes())
        .map_err(|e| format!("parsing private key: {e}"))?;
    if private.is_encrypted() {
        let pass = key
            .passphrase
            .as_ref()
            .ok_or("key is encrypted and the item has no passphrase")?;
        private = private
            .decrypt(pass.as_bytes())
            .map_err(|e| format!("decrypting private key: {e}"))?;
    }
    // Only a completed signature counts as activity: listing keys is open to
    // any process of this user and must not keep the vault unlocked.
    let signature = sign_with(&private, &data, flags)?;
    host.record_activity();
    Ok(signature)
}

/// Produce an SSH signature blob (string algorithm, string signature).
pub fn sign_with(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Vec<u8>, String> {
    use ssh_encoding::Encode;
    use ssh_key::Signature;
    let signature = match key.key_data() {
        ssh_key::private::KeypairData::Rsa(kp) => {
            let rsa_key = rsa_private_key(kp)?;
            let (hash, sig) = if flags & RSA_SHA2_512 != 0 {
                (
                    Some(HashAlg::Sha512),
                    rsa_key.sign_with_rng(
                        &mut rand_core::OsRng,
                        rsa::Pkcs1v15Sign::new::<sha2::Sha512>(),
                        &sha2::Sha512::digest(data),
                    ),
                )
            } else if flags & RSA_SHA2_256 != 0 {
                (
                    Some(HashAlg::Sha256),
                    rsa_key.sign_with_rng(
                        &mut rand_core::OsRng,
                        rsa::Pkcs1v15Sign::new::<sha2::Sha256>(),
                        &sha2::Sha256::digest(data),
                    ),
                )
            } else {
                (
                    None,
                    rsa_key.sign_with_rng(
                        &mut rand_core::OsRng,
                        rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                        &sha1::Sha1::digest(data),
                    ),
                )
            };
            let sig = sig.map_err(|e| format!("rsa sign: {e}"))?;
            let Some(hash) = hash else {
                // ssh-key can't represent a legacy SHA-1 `ssh-rsa` signature
                // (it rejects a hashless RSA algorithm), so write the wire
                // form, string algorithm + string signature, directly.
                let mut out = Vec::new();
                put_string(&mut out, b"ssh-rsa");
                put_string(&mut out, &sig);
                return Ok(out);
            };
            Signature::new(Algorithm::Rsa { hash: Some(hash) }, sig).map_err(|e| e.to_string())?
        }
        _ => signature::Signer::try_sign(key, data).map_err(|e| format!("sign: {e}"))?,
    };
    let mut out = Vec::new();
    signature
        .encode(&mut out)
        .map_err(|e| format!("encode: {e}"))?;
    Ok(out)
}

/// ssh-key's own RsaKeypair → rsa conversion rejects valid keys; build it
/// from the raw components instead.
fn rsa_private_key(kp: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey, String> {
    use rsa::BigUint;
    let int = |m: &ssh_key::Mpint| -> Result<BigUint, String> {
        Ok(BigUint::from_bytes_be(
            m.as_positive_bytes().ok_or("negative RSA component")?,
        ))
    };
    rsa::RsaPrivateKey::from_components(
        int(&kp.public.n)?,
        int(&kp.public.e)?,
        int(&kp.private.d)?,
        vec![int(&kp.private.p)?, int(&kp.private.q)?],
    )
    .map_err(|e| format!("rsa key: {e}"))
}

// ---------------------------------------------------------------------------
// Describing a request
// ---------------------------------------------------------------------------

/// What a signature is for, decoded from the data being signed.
#[derive(Debug, PartialEq)]
pub enum Purpose {
    /// SSH user authentication (RFC 4252): logging in as `user`.
    Login {
        user: String,
    },
    /// `ssh-keygen -Y sign` (SSHSIG); namespace "git" is a commit/tag signature.
    Sig {
        namespace: String,
    },
    Unknown,
}

pub fn purpose(data: &[u8]) -> Purpose {
    if let Some(rest) = data.strip_prefix(b"SSHSIG") {
        return match Reader(rest).string() {
            Ok(ns) => Purpose::Sig {
                namespace: String::from_utf8_lossy(ns).into_owned(),
            },
            Err(_) => Purpose::Unknown,
        };
    }
    let mut r = Reader(data);
    let parsed = (|| -> Result<Purpose, String> {
        let _session_id = r.string()?;
        if r.byte()? != 50 {
            return Err("not a userauth request".into());
        }
        let user = String::from_utf8_lossy(r.string()?).into_owned();
        let service = r.string()?;
        let method = r.string()?;
        let publickey = method == b"publickey" || method == b"publickey-hostbound-v00@openssh.com";
        if service != b"ssh-connection" || !publickey {
            return Err("unexpected service".into());
        }
        Ok(Purpose::Login { user })
    })();
    parsed.unwrap_or(Purpose::Unknown)
}

fn describe(purpose: &Purpose, host: Option<&str>) -> (String, String) {
    match purpose {
        Purpose::Login { user } => match host {
            Some(h) => (
                format!("Log in to {h}?"),
                format!("SSH login as {user}@{h}"),
            ),
            None => ("Log in with SSH?".into(), format!("SSH login as {user}")),
        },
        Purpose::Sig { namespace } if namespace == "git" => (
            "Sign with Git?".into(),
            "Git commit or tag signature".into(),
        ),
        Purpose::Sig { namespace } if namespace == "file" => {
            ("Sign a file?".into(), "File signature".into())
        }
        Purpose::Sig { namespace } => ("Sign data?".into(), format!("Signature ({namespace})")),
        Purpose::Unknown => ("Use SSH key?".into(), "Unrecognized signing request".into()),
    }
}

/// `session-bind@openssh.com` body: string hostkey, string session id,
/// string signature, bool is_forwarding.
#[derive(Debug, PartialEq)]
struct SessionBind {
    hostkey: Vec<u8>,
    session_id: Vec<u8>,
    signature: Vec<u8>,
    forwarded: bool,
}

impl SessionBind {
    /// Whether the host key really signed the session id, as OpenSSH's agent
    /// checks before trusting a bind.
    fn verifies(&self) -> bool {
        use ssh_encoding::Decode;
        let (Ok(key), Ok(sig)) = (
            ssh_key::PublicKey::from_bytes(&self.hostkey),
            ssh_key::Signature::decode(&mut &self.signature[..]),
        ) else {
            return false;
        };
        signature::Verifier::verify(&key, &self.session_id, &sig).is_ok()
    }
}

fn parse_session_bind(body: &[u8]) -> Option<SessionBind> {
    let mut r = Reader(body);
    let hostkey = r.string().ok()?.to_vec();
    let session_id = r.string().ok()?.to_vec();
    let signature = r.string().ok()?.to_vec();
    let forwarded = r.byte().ok()? != 0;
    Some(SessionBind {
        hostkey,
        session_id,
        signature,
        forwarded,
    })
}

/// Map a server host key to a host name via ~/.ssh/known_hosts (plain
/// entries only; hashed entries can't be reversed).
fn known_host_for(hostkey: &[u8]) -> Option<String> {
    use base64::Engine;
    let path = Path::new(&std::env::var("HOME").ok()?).join(".ssh/known_hosts");
    let text = fs::read_to_string(path).ok()?;
    let wanted = base64::engine::general_purpose::STANDARD.encode(hostkey);
    text.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let mut hosts = fields.next()?;
        if hosts.starts_with('@') {
            hosts = fields.next()?;
        }
        let (_kind, key) = (fields.next()?, fields.next()?);
        if key != wanted || hosts.starts_with('|') {
            return None;
        }
        let first = hosts.split(',').next()?;
        Some(
            first
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or(first)
                .to_string(),
        )
    })
}

// ---------------------------------------------------------------------------
// Peer process
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct Peer {
    pid: i32,
    exe: String,
    comm: String,
    cmdline: String,
    /// Executable of the app the request comes from (see [`Peer::find_app`]).
    app: String,
}

impl Peer {
    fn of(stream: &UnixStream) -> Peer {
        let mut cred = libc::ucred {
            pid: 0,
            uid: 0,
            gid: 0,
        };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        let ok = unsafe {
            libc::getsockopt(
                std::os::fd::AsRawFd::as_raw_fd(stream),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut cred as *mut _ as *mut libc::c_void,
                &mut len,
            )
        } == 0;
        if ok {
            let mut peer = Peer::from_pid(cred.pid);
            peer.app = peer.find_app();
            peer
        } else {
            Peer::default()
        }
    }

    fn from_pid(pid: i32) -> Peer {
        let proc = PathBuf::from(format!("/proc/{pid}"));
        let exe = fs::read_link(proc.join("exe"))
            .map(|p| {
                p.to_string_lossy()
                    .trim_end_matches(" (deleted)")
                    .to_string()
            })
            .unwrap_or_default();
        let comm = fs::read_to_string(proc.join("comm"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let cmdline = fs::read(proc.join("cmdline"))
            .map(|b| {
                b.split(|c| *c == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
            .unwrap_or_default();
        Peer {
            pid,
            exe,
            comm,
            cmdline,
            app: String::new(),
        }
    }

    /// The first ancestor that isn't a shell or an ssh/git wrapper: the
    /// terminal, editor or tool the person is using. Remembered approvals are
    /// scoped to it, so approving `ssh` in a terminal doesn't approve every
    /// other program that runs `ssh`. Read from `exe` links, which a process
    /// can't rename.
    fn find_app(&self) -> String {
        let mut next = self.parent();
        for _ in 0..16 {
            let Some(p) = next else { break };
            if !is_wrapper(&p.exe) {
                return p.exe;
            }
            next = p.parent();
        }
        String::new()
    }

    fn parent(&self) -> Option<Peer> {
        let stat = fs::read_to_string(format!("/proc/{}/stat", self.pid)).ok()?;
        // Fields after the parenthesised comm (which may contain spaces).
        let ppid: i32 = stat
            .rsplit_once(')')?
            .1
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()?;
        (ppid > 1).then(|| Peer::from_pid(ppid))
    }

    /// "git (ssh)", "ssh", "ssh-keygen"…
    fn describe(&self) -> String {
        let mut who = if self.comm.is_empty() {
            "A program".to_string()
        } else {
            self.comm.clone()
        };
        if self.comm == "ssh" {
            if let Some(parent) = self.parent() {
                if !parent.comm.is_empty()
                    && !matches!(parent.comm.as_str(), "bash" | "zsh" | "fish" | "sh" | "nu")
                {
                    who = format!("{} (ssh)", parent.comm);
                }
            }
        }
        let app = Path::new(&self.app)
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !app.is_empty() && !who.starts_with(&app) {
            who = format!("{who} in {app}");
        }
        who
    }
}

fn is_wrapper(exe: &str) -> bool {
    let name = Path::new(exe)
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    matches!(
        name.as_ref(),
        "sh" | "bash" | "dash" | "zsh" | "fish" | "nu" | "ssh" | "git" | "ssh-keygen"
    )
}

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8, String> {
        let (b, rest) = self.0.split_first().ok_or("short read")?;
        self.0 = rest;
        Ok(*b)
    }
    fn u32(&mut self) -> Result<u32, String> {
        if self.0.len() < 4 {
            return Err("short read".into());
        }
        let (n, rest) = self.0.split_at(4);
        self.0 = rest;
        Ok(u32::from_be_bytes([n[0], n[1], n[2], n[3]]))
    }
    fn string(&mut self) -> Result<&'a [u8], String> {
        let len = self.u32()? as usize;
        if self.0.len() < len {
            return Err("short string".into());
        }
        let (s, rest) = self.0.split_at(len);
        self.0 = rest;
        Ok(s)
    }
}

fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    out.extend_from_slice(&(s.len() as u32).to_be_bytes());
    out.extend_from_slice(s);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::OsRng;
    use ssh_key::LineEnding;

    fn verify(key: &PrivateKey, data: &[u8], blob: &[u8]) -> ssh_key::Signature {
        let sig = <ssh_key::Signature as ssh_encoding::Decode>::decode(&mut &blob[..]).unwrap();
        signature::Verifier::verify(key.public_key(), data, &sig).unwrap();
        sig
    }

    #[test]
    fn notification_text_reflects_policy() {
        let mut p = Prompt {
            id: 1,
            title: "Log in to github.com?".into(),
            action: "SSH login as git@github.com".into(),
            key_name: "Work".into(),
            fingerprint: String::new(),
            client: "git (ssh)".into(),
            command: String::new(),
            forwarded: false,
            remembered: true,
        };
        let (title, body) = notification_text(&p);
        assert_eq!(title, "Log in to github.com?");
        assert_eq!(
            body,
            "SSH login as git@github.com\nWork \u{b7} git (ssh)\nRemembered until logout"
        );
        p.remembered = false;
        assert!(notification_text(&p).1.ends_with("\nWork \u{b7} git (ssh)"));
        p.forwarded = true;
        assert!(notification_text(&p).1.contains("Forwarded"));
        p.key_name = "<b>&".into();
        assert!(notification_text(&p).1.contains("&lt;b&gt;&amp;"));
    }

    #[test]
    fn ed25519_signature_verifies() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let pem = key.to_openssh(LineEnding::LF).unwrap();
        let parsed = PrivateKey::from_openssh(pem.as_bytes()).unwrap();
        verify(
            &key,
            b"challenge",
            &sign_with(&parsed, b"challenge", 0).unwrap(),
        );
    }

    #[test]
    fn ecdsa_p256_signature_verifies() {
        let key = PrivateKey::random(
            &mut OsRng,
            Algorithm::Ecdsa {
                curve: ssh_key::EcdsaCurve::NistP256,
            },
        )
        .unwrap();
        verify(
            &key,
            b"challenge",
            &sign_with(&key, b"challenge", 0).unwrap(),
        );
    }

    #[test]
    fn rsa_honours_sha2_flags() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None }).unwrap();
        let sig = verify(
            &key,
            b"challenge",
            &sign_with(&key, b"challenge", RSA_SHA2_512).unwrap(),
        );
        assert_eq!(
            sig.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha512)
            }
        );
        let sig = verify(
            &key,
            b"challenge",
            &sign_with(&key, b"challenge", RSA_SHA2_256).unwrap(),
        );
        assert_eq!(
            sig.algorithm(),
            Algorithm::Rsa {
                hash: Some(HashAlg::Sha256)
            }
        );
    }

    #[test]
    fn decodes_purpose() {
        let mut login = Vec::new();
        put_string(&mut login, b"session-id");
        login.push(50);
        put_string(&mut login, b"git");
        put_string(&mut login, b"ssh-connection");
        put_string(&mut login, b"publickey");
        login.push(1);
        assert_eq!(purpose(&login), Purpose::Login { user: "git".into() });

        let mut hostbound = Vec::new();
        put_string(&mut hostbound, b"session-id");
        hostbound.push(50);
        put_string(&mut hostbound, b"git");
        put_string(&mut hostbound, b"ssh-connection");
        put_string(&mut hostbound, b"publickey-hostbound-v00@openssh.com");
        hostbound.push(1);
        assert_eq!(purpose(&hostbound), Purpose::Login { user: "git".into() });

        let mut sig = b"SSHSIG".to_vec();
        put_string(&mut sig, b"git");
        assert_eq!(
            purpose(&sig),
            Purpose::Sig {
                namespace: "git".into()
            }
        );
        assert_eq!(purpose(b"random"), Purpose::Unknown);
        assert_eq!(purpose(b""), Purpose::Unknown);
        assert_eq!(
            describe(
                &Purpose::Login {
                    user: "root".into()
                },
                Some("vps")
            )
            .0,
            "Log in to vps?"
        );
    }

    #[test]
    fn session_bind_detects_forwarding() {
        let bind = |forwarding: u8| {
            let mut b = Vec::new();
            put_string(&mut b, b"hostkey-blob");
            put_string(&mut b, b"session-id");
            put_string(&mut b, b"signature");
            b.push(forwarding);
            b
        };
        let expected = |forwarded| SessionBind {
            hostkey: b"hostkey-blob".to_vec(),
            session_id: b"session-id".to_vec(),
            signature: b"signature".to_vec(),
            forwarded,
        };
        assert_eq!(parse_session_bind(&bind(0)), Some(expected(false)));
        assert_eq!(parse_session_bind(&bind(1)), Some(expected(true)));
        // Truncated before the flag: rejected, not treated as "not forwarded".
        let mut truncated = bind(1);
        truncated.pop();
        assert_eq!(parse_session_bind(&truncated), None);
        assert_eq!(parse_session_bind(b""), None);
    }

    #[test]
    fn session_binds_must_be_signed_by_the_host_key() {
        let host_key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let other = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let bind = |hostkey: &PrivateKey, signer: &PrivateKey, session: &[u8], signed: &[u8]| {
            let _ = session;
            SessionBind {
                hostkey: hostkey.public_key().to_bytes().unwrap(),
                session_id: session.to_vec(),
                signature: sign_with(signer, signed, 0).unwrap(),
                forwarded: false,
            }
        };
        assert!(bind(&host_key, &host_key, b"sid", b"sid").verifies());
        assert!(
            !bind(&host_key, &other, b"sid", b"sid").verifies(),
            "wrong signer"
        );
        assert!(
            !bind(&host_key, &host_key, b"sid", b"other").verifies(),
            "wrong session"
        );
        let garbage = |hostkey: &[u8], signature: &[u8]| SessionBind {
            hostkey: hostkey.to_vec(),
            session_id: b"sid".to_vec(),
            signature: signature.to_vec(),
            forwarded: false,
        };
        let good = bind(&host_key, &host_key, b"sid", b"sid");
        assert!(!garbage(b"not a key", &good.signature).verifies());
        assert!(!garbage(&good.hostkey, b"not a signature").verifies());
    }

    #[test]
    fn malformed_input_is_rejected_not_panicking() {
        let mut r = Reader(&[0, 0, 0, 9, 1, 2]);
        assert!(r.string().is_err());
        assert!(Reader(&[]).u32().is_err());
        assert!(Reader(&[]).byte().is_err());
    }

    #[test]
    fn prompts_and_replies() {
        let agent = SshAgent::default();
        agent.pending.lock().unwrap().insert(
            7,
            Pending {
                prompt: Prompt {
                    id: 7,
                    title: "t".into(),
                    action: "a".into(),
                    key_name: "k".into(),
                    fingerprint: "f".into(),
                    client: "c".into(),
                    command: "cmd".into(),
                    forwarded: false,
                    remembered: true,
                },
                decision: None,
            },
        );
        assert_eq!(agent.pending().len(), 1);
        assert!(agent.reply(7, Decision { approve: true }));
        assert!(
            !agent.reply(7, Decision::default()),
            "a prompt can only be answered once"
        );
        assert!(agent.pending().is_empty());
        assert!(!agent.reply(99, Decision::default()));
    }

    #[test]
    fn wrappers_are_skipped_when_finding_the_app() {
        assert!(is_wrapper("/usr/bin/zsh"));
        assert!(is_wrapper("/usr/bin/ssh"));
        assert!(is_wrapper("/usr/bin/git"));
        assert!(!is_wrapper("/usr/bin/ghostty"));
        assert!(!is_wrapper("/usr/bin/lazygit"));
        assert!(!is_wrapper(""));
        let peer = |comm: &str, app: &str| Peer {
            comm: comm.into(),
            app: app.into(),
            ..Peer::default()
        };
        assert_eq!(peer("ssh", "/usr/bin/ghostty").describe(), "ssh in ghostty");
        assert_eq!(peer("lazygit", "/usr/bin/lazygit").describe(), "lazygit");
        assert_eq!(peer("ssh", "").describe(), "ssh");
    }

    #[test]
    fn find_app_walks_past_shells_to_the_launching_program() {
        // Spawns `sh`, which tests that change $PATH would hide.
        let _lock = crate::env_lock();
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 5; true"])
            .spawn()
            .unwrap();
        let sh = child.id() as i32;
        let sleep = (0..100)
            .find_map(|_| {
                std::thread::sleep(Duration::from_millis(10));
                fs::read_to_string(format!("/proc/{sh}/task/{sh}/children"))
                    .ok()?
                    .split_whitespace()
                    .next()?
                    .parse::<i32>()
                    .ok()
            })
            .unwrap();
        let app = Peer::from_pid(sleep).find_app();
        let _ = child.kill();
        let _ = child.wait();
        let ours = fs::read_link("/proc/self/exe").unwrap();
        assert_eq!(app, ours.to_string_lossy());
    }

    // -- Protocol tests against a fake vault and desktop ---------------------

    /// What the person at the fake desktop does with an approval card.
    #[derive(Clone, Copy)]
    enum Card {
        Approve,
        Deny,
        /// Leaves it on screen until it times out.
        Ignore,
        /// The shell isn't running, so the card can't open.
        Unavailable,
    }

    /// The handler of a notification's buttons.
    type Callback = Box<dyn FnOnce(&str) + Send>;

    struct FakeHost {
        agent: Arc<SshAgent>,
        unlocked: std::sync::atomic::AtomicBool,
        keys: Vec<(String, PrivateKey)>,
        policy: Mutex<Confirm>,
        card: Mutex<Card>,
        activity: AtomicU64,
        notifications: Mutex<Vec<String>>,
        overlays: Mutex<Vec<serde_json::Value>>,
        /// Notifications can't be shown (no notify-send).
        notify_fails: std::sync::atomic::AtomicBool,
        /// The approval cards opened, as the overlay would show them.
        prompts: Mutex<Vec<Prompt>>,
        /// Button handlers of the notifications shown, to press from a test.
        callbacks: Mutex<Vec<Callback>>,
        /// The vault no longer has the key (it is removed while a prompt waits).
        keys_gone: std::sync::atomic::AtomicBool,
        /// Replaces the first key's private key and passphrase.
        stored_key: Mutex<Option<(String, Option<String>)>>,
    }

    impl FakeHost {
        fn new(policy: Confirm, card: Card) -> Arc<FakeHost> {
            Arc::new(FakeHost {
                agent: Arc::new(SshAgent {
                    running: true.into(),
                    prompt_timeout: Duration::from_millis(400),
                    unlock_timeout: Duration::from_millis(400),
                    ..SshAgent::default()
                }),
                unlocked: true.into(),
                keys: vec![(
                    "Work".into(),
                    PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap(),
                )],
                policy: Mutex::new(policy),
                card: Mutex::new(card),
                activity: AtomicU64::new(0),
                notifications: Mutex::new(Vec::new()),
                overlays: Mutex::new(Vec::new()),
                notify_fails: false.into(),
                prompts: Mutex::new(Vec::new()),
                callbacks: Mutex::new(Vec::new()),
                keys_gone: false.into(),
                stored_key: Mutex::new(None),
            })
        }
        fn notifications(&self) -> Vec<String> {
            self.notifications.lock().unwrap().clone()
        }
        fn overlays(&self) -> Vec<serde_json::Value> {
            self.overlays.lock().unwrap().clone()
        }
        /// Approval cards opened so far.
        fn cards(&self) -> usize {
            self.overlays()
                .iter()
                .filter(|o| o["view"] == "ssh-approval")
                .count()
        }
        fn activity(&self) -> u64 {
            self.activity.load(Ordering::SeqCst)
        }
    }

    impl Host for FakeHost {
        fn agent(&self) -> &Arc<SshAgent> {
            &self.agent
        }
        fn is_unlocked(&self) -> bool {
            self.unlocked.load(Ordering::SeqCst)
        }
        fn keys(&self) -> Vec<AgentKey> {
            let stored = self.stored_key.lock().unwrap().clone();
            if self.keys_gone.load(Ordering::SeqCst) {
                return Vec::new();
            }
            self.keys
                .iter()
                .map(|(name, key)| {
                    let (private_key, passphrase) = stored
                        .clone()
                        .map(|(pem, pass)| (Zeroizing::new(pem), pass.map(Zeroizing::new)))
                        .unwrap_or_else(|| (key.to_openssh(LineEnding::LF).unwrap(), None));
                    AgentKey {
                        name: name.clone(),
                        blob: blob_of(&key.public_key().to_openssh().unwrap()).unwrap(),
                        fingerprint: key.fingerprint(HashAlg::Sha256).to_string(),
                        private_key,
                        passphrase,
                    }
                })
                .collect()
        }
        fn policy(&self) -> Confirm {
            *self.policy.lock().unwrap()
        }
        fn record_activity(&self) {
            self.activity.fetch_add(1, Ordering::SeqCst);
        }
        fn known_host(&self, _hostkey: &[u8]) -> Option<String> {
            Some("vps".into())
        }
        fn notify(
            &self,
            title: &str,
            _body: &str,
            _actions: &[(&str, &str)],
            _timeout: Duration,
            on_action: Box<dyn FnOnce(&str) + Send>,
        ) -> bool {
            if self.notify_fails.load(Ordering::SeqCst) {
                return false;
            }
            self.notifications.lock().unwrap().push(title.into());
            self.callbacks.lock().unwrap().push(on_action);
            true
        }
        fn summon_overlay(&self, payload: &serde_json::Value) -> bool {
            let card = *self.card.lock().unwrap();
            if matches!(card, Card::Unavailable) {
                return false;
            }
            self.overlays.lock().unwrap().push(payload.clone());
            if let Some(id) = payload["id"].as_u64() {
                let shown = self.agent.pending().into_iter().find(|p| p.id == id);
                self.prompts.lock().unwrap().extend(shown);
            }
            if let (Some(id), Card::Approve | Card::Deny) = (payload["id"].as_u64(), card) {
                let agent = self.agent.clone();
                std::thread::spawn(move || {
                    std::thread::sleep(Duration::from_millis(20));
                    agent.reply(
                        id,
                        Decision {
                            approve: matches!(card, Card::Approve),
                        },
                    );
                });
            }
            true
        }
    }

    /// An ssh-like client connected to a fresh agent connection.
    struct Client(UnixStream);

    impl Client {
        fn connect(host: &Arc<FakeHost>, exe: &str, app: &str) -> Client {
            let (ours, theirs) = UnixStream::pair().unwrap();
            let host: Arc<dyn Host> = host.clone();
            let peer = Peer {
                exe: exe.into(),
                comm: "ssh".into(),
                app: app.into(),
                ..Peer::default()
            };
            std::thread::spawn(move || serve(&host, theirs, peer));
            Client(ours)
        }
        fn request(&mut self, kind: u8, body: &[u8]) -> (u8, Vec<u8>) {
            send(&mut self.0, kind, body).unwrap();
            let mut len = [0u8; 4];
            self.0.read_exact(&mut len).unwrap();
            let mut msg = vec![0u8; u32::from_be_bytes(len) as usize];
            self.0.read_exact(&mut msg).unwrap();
            (msg[0], msg[1..].to_vec())
        }
        fn identities(&mut self) -> Vec<(Vec<u8>, String)> {
            let (kind, body) = self.request(REQUEST_IDENTITIES, &[]);
            assert_eq!(kind, IDENTITIES_ANSWER);
            let mut r = Reader(&body);
            (0..r.u32().unwrap())
                .map(|_| {
                    let blob = r.string().unwrap().to_vec();
                    let name = String::from_utf8_lossy(r.string().unwrap()).into_owned();
                    (blob, name)
                })
                .collect()
        }
        /// Sign a login challenge with the first key; the signature on success.
        fn sign(&mut self, host: &FakeHost) -> Option<Vec<u8>> {
            let blob = host.keys()[0].blob.clone();
            let mut body = Vec::new();
            put_string(&mut body, &blob);
            put_string(&mut body, LOGIN);
            body.extend_from_slice(&0u32.to_be_bytes());
            match self.request(SIGN_REQUEST, &body) {
                (SIGN_RESPONSE, sig) => Some(Reader(&sig).string().unwrap().to_vec()),
                (kind, _) => {
                    assert_eq!(kind, FAILURE, "unexpected reply");
                    None
                }
            }
        }
        fn session_bind(&mut self, forwarding: bool) -> u8 {
            self.session_bind_to(&SESSION_ID, &HOST_KEY, forwarding)
        }
        /// A bind for `session_id`, signed by `host_key`.
        fn session_bind_to(
            &mut self,
            session_id: &[u8],
            host_key: &PrivateKey,
            forwarding: bool,
        ) -> u8 {
            let mut body = Vec::new();
            put_string(&mut body, b"session-bind@openssh.com");
            put_string(&mut body, &host_key.public_key().to_bytes().unwrap());
            put_string(&mut body, session_id);
            put_string(&mut body, &sign_with(host_key, session_id, 0).unwrap());
            body.push(forwarding as u8);
            self.request(EXTENSION, &body).0
        }
    }

    static HOST_KEY: std::sync::LazyLock<PrivateKey> =
        std::sync::LazyLock::new(|| PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap());
    static SESSION_ID: [u8; 2] = *b"id";

    const LOGIN: &[u8] =
        b"\0\0\0\x02id\x32\0\0\0\x04root\0\0\0\x0essh-connection\0\0\0\x09publickey";

    const SSH: &str = "/usr/bin/ssh";
    const TERMINAL: &str = "/usr/bin/ghostty";

    #[test]
    fn signatures_verify_and_count_as_activity_but_listing_does_not() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        let ids = c.identities();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0].1, "Work");
        assert_eq!(
            host.activity(),
            0,
            "listing keys must not keep the vault awake"
        );

        let sig = c.sign(&host).expect("never policy signs without asking");
        verify(&host.keys[0].1, LOGIN, &sig);
        assert_eq!(host.activity(), 1);
        assert_eq!(host.cards(), 0);
    }

    #[test]
    fn first_use_asks_once_per_key_program_and_app() {
        let host = FakeHost::new(Confirm::FirstUse, Card::Approve);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert!(c.sign(&host).is_some());
        assert!(c.sign(&host).is_some());
        assert_eq!(host.cards(), 1, "second use is remembered");

        // Same terminal, new connection: still remembered.
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_some());
        assert_eq!(host.cards(), 1);

        // The same ssh binary run by another app asks again.
        assert!(Client::connect(&host, SSH, "/usr/bin/python3")
            .sign(&host)
            .is_some());
        assert_eq!(host.cards(), 2);
        assert!(
            host.notifications().is_empty(),
            "the card replaces the notification"
        );
    }

    #[test]
    fn locking_the_vault_keeps_first_use_approvals() {
        let host = FakeHost::new(Confirm::FirstUse, Card::Approve);
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_some());
        host.unlocked.store(false, Ordering::SeqCst);
        let h = host.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            h.unlocked.store(true, Ordering::SeqCst);
        });
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_some());
        assert_eq!(host.cards(), 1, "no re-approval");
        assert_eq!(host.notifications(), vec!["Vault locked".to_string()]);
    }

    #[test]
    fn always_asks_every_time_and_deny_refuses() {
        let host = FakeHost::new(Confirm::Always, Card::Approve);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert!(c.sign(&host).is_some());
        assert!(c.sign(&host).is_some());
        assert_eq!(host.cards(), 2);

        *host.card.lock().unwrap() = Card::Deny;
        assert!(c.sign(&host).is_none());
        assert_eq!(host.activity(), 2, "a refused signature is not activity");
    }

    #[test]
    fn forwarded_requests_always_ask_and_are_never_remembered() {
        let host = FakeHost::new(Confirm::Never, Card::Approve);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert_eq!(c.session_bind(true), SUCCESS);
        assert!(c.sign(&host).is_some());
        assert_eq!(host.cards(), 1);

        *host.policy.lock().unwrap() = Confirm::FirstUse;
        assert!(c.sign(&host).is_some());
        assert!(c.sign(&host).is_some());
        assert_eq!(host.cards(), 3);
        assert!(!host.agent.approvals.lock().unwrap().iter().any(|_| true));

        // A later non-forwarding bind on the same connection doesn't clear it.
        assert_eq!(c.session_bind(false), SUCCESS);
        assert!(c.sign(&host).is_some());
        assert_eq!(host.cards(), 4);
    }

    #[test]
    fn the_approval_card_opens_without_a_notification() {
        let host = FakeHost::new(Confirm::Always, Card::Ignore);
        // Nobody answers the card: the prompt times out and is refused.
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
        let overlays = host.overlays();
        assert_eq!(overlays.len(), 1);
        assert_eq!(overlays[0]["view"], "ssh-approval");
        assert!(host.notifications().is_empty());
        assert!(
            host.agent.pending().is_empty(),
            "timed-out prompts are removed"
        );
    }

    #[test]
    fn without_the_shell_a_notification_asks_instead() {
        let host = FakeHost::new(Confirm::Always, Card::Unavailable);
        let h = host.clone();
        let approver = std::thread::spawn(move || loop {
            if let Some(p) = h.agent.pending().first() {
                // Answered from the notification's Approve button.
                return h.agent.reply(p.id, Decision { approve: true });
            }
            std::thread::sleep(Duration::from_millis(10));
        });
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_some());
        assert!(approver.join().unwrap());
        assert_eq!(host.notifications().len(), 1);
    }

    #[test]
    fn locked_vault_prompts_once_and_gives_up_after_the_timeout() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        host.unlocked.store(false, Ordering::SeqCst);
        let clients: Vec<_> = (0..3)
            .map(|_| {
                let h = host.clone();
                std::thread::spawn(move || Client::connect(&h, SSH, TERMINAL).identities())
            })
            .collect();
        for c in clients {
            assert!(c.join().unwrap().is_empty(), "no keys while locked");
        }
        assert_eq!(host.notifications(), vec!["Vault locked".to_string()]);
        assert_eq!(host.overlays().len(), 1);
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
    }

    #[test]
    fn key_management_and_unknown_requests_are_refused() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        for kind in [17u8, 18, 19, 22, 23] {
            // add, remove, remove-all, lock, unlock
            assert_eq!(c.request(kind, &[]).0, FAILURE);
        }
        let mut ext = Vec::new();
        put_string(&mut ext, b"unknown@example.com");
        assert_eq!(c.request(EXTENSION, &ext).0, FAILURE);

        let mut bogus = Vec::new();
        put_string(&mut bogus, b"not-a-key");
        put_string(&mut bogus, b"data");
        assert_eq!(c.request(SIGN_REQUEST, &bogus).0, FAILURE);
        // Still usable afterwards.
        assert_eq!(c.identities().len(), 1);
    }

    #[test]
    fn oversized_messages_close_the_connection() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        c.0.write_all(&((MAX_MESSAGE as u32) + 1).to_be_bytes())
            .unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(c.0.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn a_forged_session_bind_is_refused() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        // Claims to be github.com's key but can't sign with it.
        let github = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let mut body = Vec::new();
        put_string(&mut body, b"session-bind@openssh.com");
        put_string(&mut body, &github.public_key().to_bytes().unwrap());
        put_string(&mut body, &SESSION_ID);
        put_string(&mut body, &sign_with(&HOST_KEY, &SESSION_ID, 0).unwrap());
        body.push(1);
        assert_eq!(c.request(EXTENSION, &body).0, FAILURE);
        // Nothing was learned from it: not forwarded, no host.
        assert!(c.sign(&host).is_some());
        assert_eq!(
            host.cards(),
            0,
            "a refused bind doesn't make requests forwarded"
        );

        // Truncated binds are refused too.
        let mut short = Vec::new();
        put_string(&mut short, b"session-bind@openssh.com");
        put_string(&mut short, b"hostkey");
        assert_eq!(c.request(EXTENSION, &short).0, FAILURE);
        assert_eq!(c.request(EXTENSION, &[]).0, FAILURE);
    }

    #[test]
    fn the_card_names_the_host_only_for_the_bound_session() {
        let host = FakeHost::new(Confirm::Always, Card::Approve);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert_eq!(c.session_bind(true), SUCCESS);
        // LOGIN signs session "id", which is the one that was bound.
        assert!(c.sign(&host).is_some());

        // A host that bound its own session can't pass off a login for another
        // one under the name of the host it bound.
        let other_session = |session: &[u8]| {
            let mut data = Vec::new();
            put_string(&mut data, session);
            data.extend_from_slice(&LOGIN[6..]);
            data
        };
        let key_blob = host.keys()[0].blob.clone();
        let mut body = Vec::new();
        put_string(&mut body, &key_blob);
        put_string(&mut body, &other_session(b"another"));
        body.extend_from_slice(&0u32.to_be_bytes());
        assert_eq!(c.request(SIGN_REQUEST, &body).0, SIGN_RESPONSE);

        let prompts = host.prompts.lock().unwrap();
        assert_eq!(prompts[0].title, "Log in to vps?");
        assert_eq!(prompts[1].title, "Log in with SSH?");
        assert_eq!(prompts[1].action, "SSH login as root");
    }

    #[test]
    fn unidentifiable_requesters_are_asked_every_time() {
        let host = FakeHost::new(Confirm::FirstUse, Card::Approve);
        // No /proc/<pid>/exe (the process is gone): nothing to scope a
        // remembered approval to.
        let mut c = Client::connect(&host, "", "");
        assert!(c.sign(&host).is_some());
        assert!(c.sign(&host).is_some());
        assert_eq!(host.cards(), 2);
        assert!(!host.prompts.lock().unwrap()[0].remembered);
        assert!(host.agent.approvals.lock().unwrap().is_empty());
    }

    #[test]
    fn a_vault_that_locks_during_the_prompt_signs_nothing() {
        let host = FakeHost::new(Confirm::Always, Card::Ignore);
        let h = host.clone();
        let locker = std::thread::spawn(move || {
            assert!(eventually(|| !h.agent.pending().is_empty()));
            let id = h.agent.pending()[0].id;
            h.unlocked.store(false, Ordering::SeqCst);
            h.agent.reply(id, Decision { approve: true });
        });
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
        locker.join().unwrap();
        assert_eq!(host.activity(), 0);
    }

    #[test]
    fn a_key_removed_during_the_prompt_signs_nothing() {
        let host = FakeHost::new(Confirm::Always, Card::Ignore);
        let h = host.clone();
        let remover = std::thread::spawn(move || {
            assert!(eventually(|| !h.agent.pending().is_empty()));
            let id = h.agent.pending()[0].id;
            h.keys_gone.store(true, Ordering::SeqCst);
            h.agent.reply(id, Decision { approve: true });
        });
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
        remover.join().unwrap();
        assert_eq!(host.activity(), 0);
    }

    #[test]
    fn turning_the_agent_off_ends_open_connections() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert_eq!(c.identities().len(), 1);
        host.agent.running.store(false, Ordering::SeqCst);
        send(&mut c.0, REQUEST_IDENTITIES, &[]).unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(
            c.0.read(&mut buf).unwrap(),
            0,
            "connection closed, no answer"
        );
    }

    #[test]
    fn malformed_requests_get_a_failure_and_the_connection_survives() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert_eq!(
            c.request(SIGN_REQUEST, &[]).0,
            FAILURE,
            "empty sign request"
        );
        assert_eq!(
            c.request(SIGN_REQUEST, &[0, 0, 0, 9, 1]).0,
            FAILURE,
            "short key blob"
        );
        assert_eq!(
            c.request(EXTENSION, &[0, 0]).0,
            FAILURE,
            "short extension name"
        );
        assert_eq!(c.request(99, &[1, 2, 3]).0, FAILURE, "unknown request");
        assert_eq!(c.identities().len(), 1, "still serving");
    }

    #[test]
    fn a_failed_unlock_notification_lets_the_next_request_prompt_again() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        host.unlocked.store(false, Ordering::SeqCst);
        host.notify_fails.store(true, Ordering::SeqCst);
        assert!(Client::connect(&host, SSH, TERMINAL)
            .identities()
            .is_empty());
        assert!(!host.agent.unlock_prompted.load(Ordering::SeqCst));
        assert!(host.notifications().is_empty());
    }

    #[test]
    fn a_poisoned_prompt_list_denies_instead_of_panicking() {
        let host = FakeHost::new(Confirm::Always, Card::Approve);
        let agent = host.agent.clone();
        let _ = std::thread::spawn(move || {
            let _held = agent.pending.lock().unwrap();
            panic!("poison the prompt list");
        })
        .join();
        assert!(!host.agent.reply(1, Decision { approve: true }));
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
        assert!(host.agent.pending().is_empty());
    }

    #[test]
    fn a_prompt_list_poisoned_while_waiting_denies() {
        let host = FakeHost::new(Confirm::Always, Card::Ignore);
        let h = host.clone();
        let poisoner = std::thread::spawn(move || {
            assert!(eventually(|| !h.agent.pending().is_empty()));
            let agent = h.agent.clone();
            let _ = std::thread::spawn(move || {
                let _held = agent.pending.lock().unwrap();
                panic!("poison the prompt list");
            })
            .join();
            // Wake the waiter so it notices.
            h.agent.answered.notify_all();
        });
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
        poisoner.join().unwrap();
    }

    #[test]
    fn other_purposes_and_malformed_ones_are_unknown() {
        // SSHSIG with a truncated namespace.
        assert_eq!(purpose(b"SSHSIG\0\0"), Purpose::Unknown);
        // A userauth message with a different message type.
        let mut other_type = Vec::new();
        put_string(&mut other_type, b"id");
        other_type.push(51);
        assert_eq!(purpose(&other_type), Purpose::Unknown);
        // A login for a service other than ssh-connection.
        let mut other_service = Vec::new();
        put_string(&mut other_service, b"id");
        other_service.push(50);
        put_string(&mut other_service, b"root");
        put_string(&mut other_service, b"ssh-userauth");
        put_string(&mut other_service, b"publickey");
        assert_eq!(purpose(&other_service), Purpose::Unknown);
        // Other authentication methods.
        let mut password = Vec::new();
        put_string(&mut password, b"id");
        password.push(50);
        put_string(&mut password, b"root");
        put_string(&mut password, b"ssh-connection");
        put_string(&mut password, b"password");
        assert_eq!(purpose(&password), Purpose::Unknown);
    }

    #[test]
    fn peers_without_a_socket_or_a_process_have_no_identity() {
        // Not a socket: SO_PEERCRED fails.
        let file = fs::File::open("/dev/null").unwrap();
        let stream = UnixStream::from(std::os::fd::OwnedFd::from(file));
        let peer = Peer::of(&stream);
        assert_eq!(
            (peer.pid, peer.exe.as_str(), peer.app.as_str()),
            (0, "", "")
        );
        // A process that has exited has no ancestors to name.
        assert_eq!(Peer::from_pid(i32::MAX).find_app(), "");
    }

    #[test]
    fn accept_errors_and_bad_clients_do_not_stop_the_agent() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        let dyn_host: Arc<dyn Host> = host.clone();
        accepted(&dyn_host, Err(std::io::Error::other("too many open files")));

        // A client announcing an oversized message is dropped; the next works.
        let (mut bad, theirs) = UnixStream::pair().unwrap();
        accepted(&dyn_host, Ok(theirs));
        bad.write_all(&((MAX_MESSAGE as u32) + 1).to_be_bytes())
            .unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(bad.read(&mut buf).unwrap(), 0);

        let (mut good, theirs) = UnixStream::pair().unwrap();
        accepted(&dyn_host, Ok(theirs));
        send(&mut good, REQUEST_IDENTITIES, &[]).unwrap();
        let mut len = [0u8; 4];
        good.read_exact(&mut len).unwrap();
        assert_eq!(good.read(&mut buf).unwrap(), 1, "answers with the key list");
    }

    #[test]
    fn the_accept_loop_ends_once_the_agent_is_off() {
        let _lock = crate::env_lock();
        let runtime = tempfile::tempdir().unwrap();
        let _env = EnvVars::set(&[("XDG_RUNTIME_DIR", runtime.path().as_os_str())]);
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path());
        spawn(state.clone()).unwrap();
        assert!(is_running(&state));
        // Off, but the thread is still waiting in accept: the next connection
        // wakes it, and it hangs up instead of serving.
        state.ssh_agent.running.store(false, Ordering::SeqCst);
        let mut late = UnixStream::connect(socket_path()).unwrap();
        let mut buf = [0u8; 1];
        assert_eq!(late.read(&mut buf).unwrap(), 0);
        remove_socket();
    }

    // -- Desktop, vault and environment ---------------------------------------

    /// Sets environment variables for one test and restores them on drop. Hold
    /// [`crate::env_lock`] for as long as it lives.
    struct EnvVars(Vec<(&'static str, Option<std::ffi::OsString>)>);

    impl EnvVars {
        fn set(vars: &[(&'static str, &std::ffi::OsStr)]) -> EnvVars {
            let old = vars
                .iter()
                .map(|(k, v)| {
                    let old = std::env::var_os(k);
                    std::env::set_var(k, v);
                    (*k, old)
                })
                .collect();
            EnvVars(old)
        }
    }

    impl Drop for EnvVars {
        fn drop(&mut self) {
            for (k, old) in self.0.drain(..) {
                match old {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    /// `$PATH` with `dir` in front, so stub commands win over real ones.
    fn path_with(dir: &Path) -> std::ffi::OsString {
        let mut paths = vec![dir.to_path_buf()];
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        std::env::join_paths(paths).unwrap()
    }

    /// Poll until `cond` holds (up to two seconds).
    fn eventually(cond: impl Fn() -> bool) -> bool {
        (0..200).any(|_| {
            let done = cond();
            if !done {
                std::thread::sleep(Duration::from_millis(10));
            }
            done
        })
    }

    #[test]
    fn confirm_policy_names_parse_and_unknown_ones_always_ask() {
        assert_eq!(Confirm::parse("always"), Confirm::Always);
        assert_eq!(Confirm::parse("never"), Confirm::Never);
        assert_eq!(Confirm::parse("first-use"), Confirm::FirstUse);
        assert_eq!(
            Confirm::parse("Always "),
            Confirm::Always,
            "a misspelt policy asks more, never less"
        );
        assert_eq!(Confirm::parse(""), Confirm::Always);
    }

    #[test]
    fn socket_lives_in_the_runtime_dir() {
        let _lock = crate::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let _env = EnvVars::set(&[("XDG_RUNTIME_DIR", dir.path().as_os_str())]);
        assert_eq!(socket_path(), dir.path().join("omawarden-ssh-agent.sock"));
    }

    #[test]
    fn notification_buttons_answer_the_prompt() {
        for (button, signed) in [("approve", true), ("deny", false)] {
            let host = FakeHost::new(Confirm::Always, Card::Unavailable);
            let h = host.clone();
            let presser = std::thread::spawn(move || {
                assert!(eventually(|| !h.callbacks.lock().unwrap().is_empty()));
                let press = h.callbacks.lock().unwrap().pop().unwrap();
                press(button);
            });
            let sig = Client::connect(&host, SSH, TERMINAL).sign(&host);
            presser.join().unwrap();
            assert_eq!(sig.is_some(), signed, "{button}");
        }
    }

    #[test]
    fn dismissing_the_notification_leaves_the_prompt_to_time_out() {
        let host = FakeHost::new(Confirm::Always, Card::Unavailable);
        let h = host.clone();
        let presser = std::thread::spawn(move || {
            assert!(eventually(|| !h.callbacks.lock().unwrap().is_empty()));
            let press = h.callbacks.lock().unwrap().pop().unwrap();
            // Dismissed, expired or an action we didn't offer.
            press("");
            assert_eq!(h.agent.pending().len(), 1, "still waiting for an answer");
        });
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_none());
        presser.join().unwrap();
        assert!(host.agent.pending().is_empty());
    }

    #[test]
    fn replies_to_unknown_or_answered_prompts_are_not_delivered() {
        let agent = SshAgent::default();
        assert!(!agent.reply(99, Decision { approve: true }));
        agent.pending.lock().unwrap().insert(
            1,
            Pending {
                prompt: Prompt {
                    id: 1,
                    title: String::new(),
                    action: String::new(),
                    key_name: String::new(),
                    fingerprint: String::new(),
                    client: String::new(),
                    command: String::new(),
                    forwarded: false,
                    remembered: false,
                },
                decision: None,
            },
        );
        assert!(agent.reply(1, Decision { approve: false }));
        assert!(
            !agent.reply(1, Decision { approve: true }),
            "first answer wins"
        );
        assert!(
            agent.pending().is_empty(),
            "answered prompts are not listed"
        );
    }

    #[test]
    fn unlocking_the_vault_releases_waiting_clients() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        host.unlocked.store(false, Ordering::SeqCst);
        let h = host.clone();
        let unlocker = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            h.unlocked.store(true, Ordering::SeqCst);
        });
        assert_eq!(
            Client::connect(&host, SSH, TERMINAL).identities().len(),
            1,
            "keys are listed once the vault unlocks"
        );
        unlocker.join().unwrap();
        assert!(
            !host.agent.unlock_prompted.load(Ordering::SeqCst),
            "the next lock prompts again"
        );
    }

    #[test]
    fn unlock_notification_reopens_the_overlay_only_when_pressed() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        host.unlocked.store(false, Ordering::SeqCst);
        assert!(Client::connect(&host, SSH, TERMINAL)
            .identities()
            .is_empty());
        assert_eq!(host.overlays().len(), 1);

        // Dismissing it only re-arms the prompt.
        host.agent.unlock_prompted.store(true, Ordering::SeqCst);
        host.callbacks.lock().unwrap().pop().unwrap()("");
        assert_eq!(host.overlays().len(), 1);
        assert!(!host.agent.unlock_prompted.load(Ordering::SeqCst));

        // Pressing Unlock opens the overlay again.
        assert!(Client::connect(&host, SSH, TERMINAL)
            .identities()
            .is_empty());
        host.callbacks.lock().unwrap().pop().unwrap()("default");
        assert_eq!(host.overlays().len(), 3);
    }

    #[test]
    fn encrypted_keys_sign_with_the_stored_passphrase() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        let encrypted = host.keys[0]
            .1
            .encrypt(&mut OsRng, "hunter2")
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap();

        *host.stored_key.lock().unwrap() = Some((encrypted.to_string(), Some("hunter2".into())));
        assert!(Client::connect(&host, SSH, TERMINAL).sign(&host).is_some());

        *host.stored_key.lock().unwrap() = Some((encrypted.to_string(), None));
        assert!(
            Client::connect(&host, SSH, TERMINAL).sign(&host).is_none(),
            "no passphrase stored"
        );

        *host.stored_key.lock().unwrap() = Some((encrypted.to_string(), Some("wrong".into())));
        assert!(
            Client::connect(&host, SSH, TERMINAL).sign(&host).is_none(),
            "wrong passphrase"
        );
    }

    #[test]
    fn unparseable_private_keys_are_refused() {
        let host = FakeHost::new(Confirm::Never, Card::Ignore);
        *host.stored_key.lock().unwrap() = Some(("not a key".into(), None));
        let mut c = Client::connect(&host, SSH, TERMINAL);
        assert!(c.sign(&host).is_none());
        assert_eq!(host.activity(), 0);
    }

    #[test]
    fn rsa_without_flags_signs_with_sha1() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Rsa { hash: None }).unwrap();
        let blob = sign_with(&key, b"challenge", 0).unwrap();
        // ssh-key can't decode a hashless RSA signature; read the wire form.
        let mut r = Reader(&blob);
        assert_eq!(r.string().unwrap(), b"ssh-rsa");
        let sig = r.string().unwrap();
        // Legacy SHA-1 signatures verify against the RSA public key directly.
        let public = key.public_key().key_data().rsa().expect("an RSA key");
        let public = rsa::RsaPublicKey::try_from(public).unwrap();
        public
            .verify(
                rsa::Pkcs1v15Sign::new::<sha1::Sha1>(),
                &sha1::Sha1::digest(b"challenge"),
                sig,
            )
            .unwrap();
    }

    #[test]
    fn ecdsa_p384_and_p521_signatures_verify() {
        for curve in [ssh_key::EcdsaCurve::NistP384, ssh_key::EcdsaCurve::NistP521] {
            let key = PrivateKey::random(&mut OsRng, Algorithm::Ecdsa { curve }).unwrap();
            verify(
                &key,
                b"challenge",
                &sign_with(&key, b"challenge", 0).unwrap(),
            );
        }
    }

    #[test]
    fn describes_every_kind_of_request() {
        let login = |user: &str| Purpose::Login { user: user.into() };
        let sig = |ns: &str| Purpose::Sig {
            namespace: ns.into(),
        };
        assert_eq!(
            describe(&login("root"), Some("vps")),
            ("Log in to vps?".into(), "SSH login as root@vps".into())
        );
        assert_eq!(
            describe(&login("root"), None),
            ("Log in with SSH?".into(), "SSH login as root".into())
        );
        assert_eq!(describe(&sig("git"), None).0, "Sign with Git?");
        assert_eq!(describe(&sig("file"), None).0, "Sign a file?");
        assert_eq!(
            describe(&sig("mail"), None),
            ("Sign data?".into(), "Signature (mail)".into())
        );
        assert_eq!(describe(&Purpose::Unknown, None).0, "Use SSH key?");
    }

    #[test]
    fn wire_reader_reports_short_input() {
        assert!(Reader(&[]).byte().is_err());
        assert!(Reader(&[0, 0, 1]).u32().is_err());
        assert!(Reader(&[0, 0, 0, 5, b'a']).string().is_err());
        assert_eq!(Reader(&[0, 0, 0, 1, b'a']).string().unwrap(), b"a");
    }

    #[test]
    fn known_hosts_map_a_host_key_to_its_name() {
        use base64::Engine;
        let _lock = crate::env_lock();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvVars::set(&[("HOME", home.path().as_os_str())]);
        assert_eq!(known_host_for(b"key"), None, "no known_hosts file");

        let b64 = |k: &[u8]| base64::engine::general_purpose::STANDARD.encode(k);
        fs::create_dir_all(home.path().join(".ssh")).unwrap();
        fs::write(
            home.path().join(".ssh/known_hosts"),
            format!(
                "|1|salt|hash ssh-ed25519 {hashed}\n\
                 @cert-authority *.corp ssh-ed25519 {ca}\n\
                 [vps.example.com]:2222,10.0.0.5 ssh-ed25519 {vps}\n\
                 github.com,140.82.0.1 ssh-ed25519 {github}\n\
                 short\n",
                hashed = b64(b"hashed"),
                ca = b64(b"ca"),
                vps = b64(b"vps"),
                github = b64(b"github"),
            ),
        )
        .unwrap();

        assert_eq!(known_host_for(b"github").as_deref(), Some("github.com"));
        assert_eq!(known_host_for(b"vps").as_deref(), Some("vps.example.com"));
        assert_eq!(known_host_for(b"ca").as_deref(), Some("*.corp"));
        assert_eq!(
            known_host_for(b"hashed"),
            None,
            "hashed names can't be reversed"
        );
        assert_eq!(known_host_for(b"unknown"), None);
    }

    #[test]
    fn blob_of_decodes_the_public_key_field() {
        let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let line = key.public_key().to_openssh().unwrap();
        assert_eq!(
            blob_of(&line).unwrap(),
            key.public_key().to_bytes().unwrap()
        );
        assert!(blob_of("ssh-ed25519").is_none());
        assert!(blob_of("ssh-ed25519 !!!notbase64").is_none());
    }

    #[test]
    fn peers_are_identified_from_proc() {
        let (ours, _theirs) = UnixStream::pair().unwrap();
        let me = Peer::of(&ours);
        assert_eq!(me.pid, std::process::id() as i32);
        assert_eq!(
            me.exe,
            fs::read_link("/proc/self/exe").unwrap().to_string_lossy()
        );
        assert!(!me.comm.is_empty());
        assert!(!me.cmdline.is_empty());

        let gone = Peer::from_pid(i32::MAX);
        assert!(gone.exe.is_empty() && gone.comm.is_empty() && gone.cmdline.is_empty());
        assert!(gone.parent().is_none());
    }

    #[test]
    fn peers_are_described_for_the_prompt() {
        // Spawns `sh`, which tests that change $PATH would hide.
        let _lock = crate::env_lock();
        let peer = |comm: &str, app: &str| Peer {
            comm: comm.into(),
            app: app.into(),
            ..Peer::default()
        };
        assert_eq!(peer("", "").describe(), "A program");
        assert_eq!(peer("ssh-keygen", "").describe(), "ssh-keygen");
        assert_eq!(
            peer("ssh-keygen", "/usr/bin/ghostty").describe(),
            "ssh-keygen in ghostty"
        );
        assert_eq!(
            peer("helper", "/usr/bin/ghostty").describe(),
            "helper in ghostty"
        );
        assert_eq!(
            peer("ghostty", "/usr/bin/ghostty").describe(),
            "ghostty",
            "no repeat when the program is the app"
        );

        // An ssh run by a program that isn't a shell names that program.
        let mut child = std::process::Command::new("sh")
            .args(["-c", "sleep 5; true"])
            .spawn()
            .unwrap();
        let sh = child.id() as i32;
        let sleep = eventually_child(sh);
        let mut ssh = Peer::from_pid(sleep);
        ssh.comm = "ssh".into();
        let shell = ssh.describe();
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(shell, "ssh", "run from a shell: just ssh");

        let me = Peer::from_pid(std::process::id() as i32);
        let mut under_runner = Peer {
            comm: "ssh".into(),
            ..me
        };
        // Our parent is the test runner (cargo or a shell); either way the
        // result is "ssh" or "<parent> (ssh)" and never panics.
        assert!(under_runner.describe().contains("ssh"));
        under_runner.pid = i32::MAX;
        assert_eq!(under_runner.describe(), "ssh");
    }

    /// The first child of `parent`, once it has started.
    fn eventually_child(parent: i32) -> i32 {
        (0..100)
            .find_map(|_| {
                std::thread::sleep(Duration::from_millis(10));
                fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))
                    .ok()?
                    .split_whitespace()
                    .next()?
                    .parse::<i32>()
                    .ok()
            })
            .unwrap()
    }

    #[test]
    fn notify_runs_notify_send_and_reports_the_pressed_button() {
        let _lock = crate::env_lock();
        let bin = tempfile::tempdir().unwrap();
        let log = bin.path().join("args");
        crate::write_test_executable(
            &bin.path().join("notify-send"),
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho approve\n",
                log.display()
            ),
        );
        let _env = EnvVars::set(&[("PATH", path_with(bin.path()).as_os_str())]);

        let (tx, rx) = std::sync::mpsc::channel();
        assert!(notify(
            "Title",
            "Body",
            &[("approve", "Approve"), ("deny", "Deny")],
            Duration::from_millis(1234),
            move |action| tx.send(action.to_string()).unwrap(),
        ));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), "approve");
        let args = fs::read_to_string(log).unwrap();
        for expected in [
            "--app-name=Bitwarden",
            "--urgency=critical",
            "--expire-time=1234",
            "approve=Approve",
            "deny=Deny",
            "Title",
            "Body",
        ] {
            assert!(args.lines().any(|l| l == expected), "{expected} in {args}");
        }
    }

    #[test]
    fn notify_reports_when_notify_send_cannot_start() {
        let _lock = crate::env_lock();
        let empty = tempfile::tempdir().unwrap();
        let _env = EnvVars::set(&[("PATH", empty.path().as_os_str())]);
        assert!(!notify("t", "b", &[], Duration::from_secs(1), |_| {}));
    }

    #[test]
    fn the_overlay_is_summoned_through_omarchy_shell() {
        let _lock = crate::env_lock();
        let bin = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let log = bin.path().join("args");
        let stub = |reply: &str, code: i32| {
            crate::write_test_executable(
                &bin.path().join("omarchy-shell"),
                format!(
                    "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\necho {reply}\nexit {code}\n",
                    log.display()
                ),
            )
        };
        let _env = EnvVars::set(&[
            ("PATH", path_with(bin.path()).as_os_str()),
            ("HOME", home.path().as_os_str()),
        ]);

        stub("ok", 0);
        assert!(summon_overlay(
            &serde_json::json!({ "view": "ssh-approval", "id": 7 })
        ));
        let args = fs::read_to_string(&log).unwrap();
        assert_eq!(
            args.lines().collect::<Vec<_>>(),
            [
                "shell",
                "summon",
                "icyleaf.bitwarden",
                r#"{"id":7,"view":"ssh-approval"}"#
            ]
        );

        stub("busy", 0);
        assert!(
            !summon_overlay(&serde_json::json!({})),
            "shell didn't open it"
        );
        stub("ok", 1);
        assert!(!summon_overlay(&serde_json::json!({})), "shell failed");
    }

    #[test]
    fn summoning_without_the_shell_or_with_a_broken_one_fails() {
        let _lock = crate::env_lock();
        let empty = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let _env = EnvVars::set(&[
            ("PATH", empty.path().as_os_str()),
            ("HOME", home.path().as_os_str()),
        ]);
        assert!(!summon_overlay(&serde_json::json!({})), "no omarchy-shell");

        // Found under ~/.local/share/omarchy/bin but not runnable.
        let broken = home.path().join(".local/share/omarchy/bin");
        fs::create_dir_all(&broken).unwrap();
        fs::write(broken.join("omarchy-shell"), "").unwrap();
        assert!(!summon_overlay(&serde_json::json!({})), "not executable");
    }

    fn state_in(dir: &Path) -> Arc<DaemonState> {
        Arc::new(DaemonState::new(
            crate::storage::StorageManager::new(dir.join("daemon_data.json")),
            15,
        ))
    }

    fn ssh_item(name: &str, ssh: Option<crate::vault::SshMetadata>) -> crate::vault::VaultItem {
        crate::vault::VaultItem {
            id: name.into(),
            name: name.into(),
            item_type: 5,
            type_name: "SSH Key".into(),
            sub_title: String::new(),
            notes: None,
            favorite: false,
            created_at: None,
            updated_at: None,
            folder_id: None,
            folder_name: None,
            organization_id: None,
            organization_name: None,
            collection_ids: None,
            login: None,
            card: None,
            identity: None,
            ssh_key: ssh,
            fields: Vec::new(),
            attachments: Vec::new(),
            search_text: String::new(),
        }
    }

    fn ssh_meta(
        private_key: Option<String>,
        public_key: Option<String>,
        fingerprint: Option<String>,
        passphrase: Option<String>,
    ) -> Option<crate::vault::SshMetadata> {
        Some(crate::vault::SshMetadata {
            is_ssh_key: true,
            key_type: "ssh-ed25519".into(),
            private_key,
            public_key,
            fingerprint,
            passphrase,
        })
    }

    #[test]
    fn vault_keys_come_from_ssh_key_items() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_in(dir.path());
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        let key = |_: u8| PrivateKey::random(&mut OsRng, Algorithm::Ed25519).unwrap();
        let (a, b, c) = (key(0), key(1), key(2));
        let pem = |k: &PrivateKey| Some(k.to_openssh(LineEnding::LF).unwrap().to_string());
        let public = |k: &PrivateKey| Some(k.public_key().to_openssh().unwrap());

        *state.vault_mgr.decrypted_items.write().unwrap() = vec![
            // Everything stored: used as is.
            ssh_item(
                "stored",
                ssh_meta(
                    pem(&a),
                    public(&a),
                    Some("SHA256:stored".into()),
                    Some("pw".into()),
                ),
            ),
            // Public key and fingerprint derived from the private key.
            ssh_item(
                "derived",
                ssh_meta(pem(&b), Some("  ".into()), Some(String::new()), None),
            ),
            ssh_item("derived-none", ssh_meta(pem(&c), None, None, None)),
            // Skipped: no SSH data, no private key, unparseable key, bad public key.
            ssh_item("login", None),
            ssh_item("public-only", ssh_meta(None, public(&a), None, None)),
            ssh_item(
                "garbage",
                ssh_meta(Some("garbage".into()), None, None, None),
            ),
            ssh_item(
                "bad-public",
                ssh_meta(pem(&a), Some("ssh-ed25519".into()), None, None),
            ),
        ];

        let keys = vault_keys(&state);
        // Locked: nothing is offered, even though the items are still in memory.
        *state.vault_mgr.is_unlocked.write().unwrap() = false;
        assert!(vault_keys(&state).is_empty());
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        let names: Vec<_> = keys.iter().map(|k| k.name.as_str()).collect();
        assert_eq!(names, ["stored", "derived", "derived-none"]);
        assert_eq!(keys[0].fingerprint, "SHA256:stored");
        assert_eq!(
            keys[0].passphrase.as_deref().map(String::as_str),
            Some("pw")
        );
        assert_eq!(
            keys[1].fingerprint,
            b.fingerprint(HashAlg::Sha256).to_string()
        );
        assert_eq!(
            keys[2].fingerprint,
            c.fingerprint(HashAlg::Sha256).to_string()
        );
        assert_eq!(keys[1].blob, blob_of(&public(&b).unwrap()).unwrap());
        assert!(keys[1].passphrase.is_none());
    }

    #[test]
    fn the_daemon_hosts_the_agent() {
        let _lock = crate::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        crate::write_test_executable(&bin.path().join("omarchy-shell"), "#!/bin/sh\necho ok\n");
        let _env = EnvVars::set(&[
            ("OMAWARDEN_CONFIG_DIR", dir.path().as_os_str()),
            ("HOME", home.path().as_os_str()),
            ("PATH", path_with(bin.path()).as_os_str()),
        ]);
        let state = state_in(dir.path());
        let host: &dyn Host = &*state;

        assert!(!host.is_unlocked());
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        assert!(host.is_unlocked());
        assert_eq!(host.policy(), Confirm::FirstUse, "default policy");
        let mut config = crate::config::ConfigManager::default().load();
        config.ssh_agent_confirm = "always".into();
        fs::write(
            dir.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
            serde_json::to_string(&config).unwrap(),
        )
        .unwrap();
        assert_eq!(host.policy(), Confirm::Always);

        assert!(host.keys().is_empty());
        assert_eq!(host.known_host(b"nothing"), None);
        *state.last_activity.lock().unwrap() = Instant::now() - Duration::from_secs(60);
        host.record_activity();
        assert!(state.last_activity.lock().unwrap().elapsed() < Duration::from_secs(30));
        assert!(host.summon_overlay(&serde_json::json!({})));
        assert!(Arc::ptr_eq(host.agent(), &state.ssh_agent));
    }

    #[test]
    fn the_daemon_hosts_notifications() {
        let _lock = crate::env_lock();
        let dir = tempfile::tempdir().unwrap();
        let bin = tempfile::tempdir().unwrap();
        crate::write_test_executable(&bin.path().join("notify-send"), "#!/bin/sh\necho default\n");
        let _env = EnvVars::set(&[("PATH", path_with(bin.path()).as_os_str())]);
        let state = state_in(dir.path());
        let (tx, rx) = std::sync::mpsc::channel();
        assert!(Host::notify(
            &*state,
            "t",
            "b",
            &[("default", "Open")],
            Duration::from_secs(1),
            Box::new(move |a| tx.send(a.to_string()).unwrap()),
        ));
        assert_eq!(rx.recv_timeout(Duration::from_secs(5)).unwrap(), "default");
    }

    #[test]
    fn the_agent_follows_the_setting_over_a_real_socket() {
        let _lock = crate::env_lock();
        let runtime = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let _env = EnvVars::set(&[
            ("XDG_RUNTIME_DIR", runtime.path().as_os_str()),
            ("OMAWARDEN_CONFIG_DIR", config.path().as_os_str()),
        ]);
        let state = state_in(config.path());
        let enable = |on: bool| {
            let mut cfg = crate::config::ConfigManager::default().load();
            cfg.ssh_agent_enabled = on;
            fs::write(
                config.path().join(crate::config::DEFAULT_CONFIG_FILENAME),
                serde_json::to_string(&cfg).unwrap(),
            )
            .unwrap();
        };

        // Off by default: nothing is bound.
        assert!(!apply(&state).unwrap());
        assert!(!is_running(&state));
        assert!(!socket_path().exists());

        // A stale socket from a previous daemon is replaced.
        fs::write(socket_path(), "").unwrap();
        enable(true);
        assert!(apply(&state).unwrap());
        assert!(is_running(&state));
        assert_eq!(
            fs::metadata(socket_path()).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(apply(&state).unwrap(), "already running: left alone");

        // The vault is unlocked and empty: a real client sees an empty list.
        *state.vault_mgr.is_unlocked.write().unwrap() = true;
        let mut stream = UnixStream::connect(socket_path()).unwrap();
        send(&mut stream, REQUEST_IDENTITIES, &[]).unwrap();
        let mut len = [0u8; 4];
        stream.read_exact(&mut len).unwrap();
        let mut reply = vec![0u8; u32::from_be_bytes(len) as usize];
        stream.read_exact(&mut reply).unwrap();
        assert_eq!(reply, [&[IDENTITIES_ANSWER][..], &[0, 0, 0, 0]].concat());
        drop(stream);

        // Turning it off removes the socket without a restart.
        enable(false);
        assert!(!apply(&state).unwrap());
        assert!(!is_running(&state));
        assert!(!socket_path().exists());
        remove_socket();
    }

    #[test]
    fn a_hijacked_socket_path_is_not_followed() {
        let _lock = crate::env_lock();
        let runtime = tempfile::tempdir().unwrap();
        let config = tempfile::tempdir().unwrap();
        let _env = EnvVars::set(&[
            ("XDG_RUNTIME_DIR", runtime.path().as_os_str()),
            ("OMAWARDEN_CONFIG_DIR", config.path().as_os_str()),
        ]);
        let state = state_in(config.path());
        std::os::unix::fs::symlink("/tmp/elsewhere", socket_path()).unwrap();
        assert!(spawn(state.clone()).is_err());
        assert!(!is_running(&state));
    }
}

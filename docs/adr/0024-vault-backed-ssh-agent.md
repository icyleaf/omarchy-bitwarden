# ADR 0024: Vault-Backed OpenSSH Agent with Notification Prompts

## Status
Proposed

## Context
`omawarden` could generate, import and export SSH keys (ADR 0005) but could not use them: keys had to be exported to disk or loaded into another agent. The README lists the missing OpenSSH agent as a gap compared with `rbw`.

The goal is for vault SSH keys to work like a native session agent: nothing to start after login, no keys on disk, and a prompt only when a key is actually used.

## Decision
1. **Agent inside the daemon**: when `ssh_agent_enabled` is set, the daemon serves the OpenSSH agent protocol on `$XDG_RUNTIME_DIR/omawarden-ssh-agent.sock` (`0600`, peer UID verified). Point `SSH_AUTH_SOCK` (or `IdentityAgent` in `~/.ssh/config`) at it; nothing sets that for you. Private keys are parsed only for the duration of one signature and are zeroized afterwards. Adding, removing and locking keys through the agent protocol is refused; the vault owns them.
2. **Unlock on demand**: a request while the vault is locked opens the overlay (a password cannot be entered in a notification) and posts a "Vault locked" notification; clicking it reopens the unlock screen. One prompt is shown however many clients are waiting; requests wait up to 60 seconds. The notification is posted once per lock cycle (from the vault locking until it locks again after an unlock), so a client that keeps retrying while you are away doesn't stack up a notification a minute (the overlay is still summoned).
3. **Approval card, like a polkit prompt**: signing opens the overlay approval card straight away, showing the host, key, requesting program and whether approval is remembered. A notification was tried first and was too easy to miss. Because the card can appear while the person is typing elsewhere, Enter and Allow are ignored for its first 600 ms; Esc and a click outside deny at once. Unanswered prompts are refused after 60 seconds. When the shell can't open the card (`omarchy-shell summon` doesn't answer `ok`), a notification with Approve and Deny actions is posted instead. `ssh_agent_confirm` is `always`, `first-use` or `never`. A first-use approval covers one key, client executable and *app*: the first ancestor process that isn't a shell, `ssh` or `git` (the terminal, editor or tool in use), read from `/proc/<pid>/exe`. Approving `ssh` in a terminal therefore doesn't approve a script or another program that runs the same `ssh` binary. Approvals last until the daemon exits at logout; vault re-locks don't reset them, since unlocking already proves presence. Requests forwarded through `session-bind@openssh.com` are always confirmed. A bind is accepted only if the host key it names signed the session id (as OpenSSH's agent checks), and the card shows the host name from `known_hosts` only when the login being signed is for that bound session, so a forwarding host can't borrow another host's name. An unrecognised `ssh_agent_confirm` value is treated as `always`.
4. **Activity**: a completed signature counts as vault activity, so active use does not idle-lock. Listing keys does not, because any process of the same user can do that and it must not keep the vault unlocked (Security Handbook Rule 9).
5. **Daemon lifecycle**: a daemon built from a different commit is replaced only while the vault is locked. Replacing an unlocked daemon would lock the vault and drop the agent socket mid-use.
6. **Lock model unchanged**: the vault still locks on idle timeout, screen lock, suspend and the maximum session lifetime, and is unlocked with the master password.

## Alternatives Considered
- **`ssh-add` keys into the stock `ssh-agent` on unlock**: far less code, but keys are loaded only after a manual unlock, so `ssh` cannot trigger one; keys leave the daemon's `mlock`/`zeroize` protection; per-host and per-program prompts are lost.
- **Separate agent process**: cleaner lifecycle, but it still needs the daemon for keys and signing, and does not change the user-visible behaviour.
- **Keyring or polkit-backed unlock** (as Bitwarden's desktop app does): would make unlocking silent or a system prompt, at the cost of the vault being only as strong as the login. Not adopted here; it changes the security model and should be decided separately.

- **Approvals keyed by key and executable only**: the executable is almost always `/usr/bin/ssh` or `git`, so one approval would let any process of the user sign silently.
- **Approvals scoped to a terminal session (session ID)**: tighter, but every new terminal window or tab asks again.

## Consequences
- **Positive**: `ssh`, `git` signing and `ssh-keygen -Y sign` use vault keys with no files on disk and no manual agent management.
- **Trade-off**: the master password is still required after each lock, so a session that screen-locks or suspends will ask again on the next use.
- **Trade-off**: after an upgrade the old daemon keeps running until the vault locks, so new daemon actions may be unavailable until then.
- **Trade-off**: anything started from an approved app (a script run in an approved terminal) shares its approval; `always` closes that gap at the cost of a prompt per signature.
- **Limit**: the prompt protects against forwarded agents, accidents and programs that happen to run `ssh`; it is not a boundary against a hostile process of the same user. Any such process can already read the vault through the daemon socket, and can answer a prompt with `omawarden ssh-agent reply`.
- **Requirement**: prompts need the Omarchy shell; without it, a notification server that renders action buttons.

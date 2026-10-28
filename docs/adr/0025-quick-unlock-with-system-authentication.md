# ADR 0025: Quick Unlock with System Authentication

## Status
Accepted (implemented by `feat(quick-unlock)`: polkit check via `pkcheck`, retained key in the daemon's locked memory, policy file shipped by the packages)

## Context
The vault locks on screen lock, suspend, idle timeout and the maximum session lifetime (Security Handbook Rule 3, Rule 9), and unlocking always takes the master password. On Omarchy the screen locks after a few minutes idle, so with the SSH agent (ADR 0024) a normal working day means typing the master password into the overlay many times, usually because `ssh` or `git` needed a key.

Desktop password managers solve this with "unlock with system authentication": after one master-password unlock per session, later unlocks use the OS prompt (login password or fingerprint). Bitwarden's Linux desktop app does this through polkit, keeping a key in the Secret Service keyring.

## Decision
1. **Opt-in setting** `quick_unlock` (off by default). With it on, the first unlock of a session still needs the master password.
2. **Key kept in the daemon, not the keyring**: when the vault locks for a screen lock or the idle timeout, decrypted items, attachments and previews are purged as today, but the user key is kept in its locked memory (`LockedMemory`, mlocked, with the process non-dumpable). It never goes to the Secret Service, disk, argv or environ (Rules 1, 7, 11).
3. **Re-unlock through polkit**: unlocking checks a polkit action (`org.omarchy.bitwarden.unlock`, `auth_self`, no caching) with `pkcheck --allow-user-interaction`, so the system's polkit agent shows its own dialog (Omarchy's shell has one built in), which can use fingerprint authentication where PAM is set up for it. On success the vault is decrypted from the retained key. The overlay offers the master password as a fallback.
4. **Hard locks wipe the retained key**: suspend, the maximum session lifetime, explicit `lock`/logout, daemon exit, three failed polkit checks, and a server or account change all zeroize it, so the next unlock needs the master password again.
5. **SSH agent**: a locked request triggers the polkit prompt directly instead of opening the overlay, so the first `ssh` after a screen lock shows a system dialog.

## Alternatives Considered
- **Keep the vault unlocked across screen locks**: simplest, but contradicts Rule 3 and the handbook's PR checklist.
- **Store the user key in the Secret Service** (Bitwarden desktop's approach): survives logout, but the login keyring is readable by any process of the user without a prompt, so the vault becomes only as strong as the login session. Keeping the key in a non-dumpable daemon is stronger against same-user processes.
- **PIN unlock**: needs its own key-wrapping scheme and brute-force limits, and doesn't feel native.

## Consequences
- **Positive**: after the first unlock, screen locks cost a system authentication (or a fingerprint) instead of the master password; `ssh` after a screen lock gets a native prompt.
- **Trade-off**: during a soft lock the user key stays in mlocked memory, so the vault is access-locked rather than crypto-locked. Someone with root or physical memory access while the screen is locked can recover it; that's why suspend wipes it.
- **Trade-off**: polkit proves someone who knows the login password (or has an enrolled finger) is present, not the master password. Opting in accepts the login password as the unlock secret for the rest of the session.
- **Requirement**: a polkit action file under `/usr/share/polkit-1/actions/` (shipped by the package) and a running polkit agent (Omarchy's shell provides one).

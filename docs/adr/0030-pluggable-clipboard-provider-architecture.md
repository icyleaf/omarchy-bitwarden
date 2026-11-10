# ADR 0030: Pluggable Clipboard Provider Architecture

## Status
Accepted

## Context
Previously, Omawarden's ephemeral clipboard management was tightly coupled to the Wayland-specific `wl-copy` utility (`wl-clipboard`), hardcoding binary paths and error messages throughout `clipboard.rs`, `clipboard_holder.rs`, and CLI handlers.

This tight coupling introduced several architectural limitations:
1. **Platform Lock-In**: Running Omawarden on non-Wayland desktop sessions (X11) or operating systems (macOS, Windows) was impossible without breaking clipboard operations.
2. **Brittle Integration Testing**: Verifying clipboard features required creating shell scripts simulating `wl-copy` on disk and spawning subprocesses rather than utilizing pure in-memory test doubles.
3. **MIME & Selection Ownership Semantics**: Wayland's `wl-copy` acts as an active selection owner that forks into the background and exits when another application overwrites the selection. Other operating systems and tools (e.g., macOS `pbcopy`, X11 `xclip`) operate synchronously and terminate immediately after setting the pasteboard.

## Decision

We decouple the clipboard subsystem into a two-tier architecture:

### 1. Separation of Concerns
- **Core Orchestration (`ClipboardGuard`)**:
  - Enforces zero-knowledge security invariants (Rule 11: no secrets in argv/environ, piping through STDIN).
  - Manages vault session authorization barriers (`ClipboardScope`), lock generation tokens, and cache credential verification.
  - Controls ephemeral TTL auto-clearing via a dedicated background holder process or timer thread.
  - Maintains the active provider via dynamic polymorphism (`Arc<dyn ClipboardProvider>`).
- **Low-Level Adapters (`ClipboardProvider`)**:
  - Defines low-level platform operations:
    - `name(&self) -> &'static str`
    - `is_available(&self) -> bool`
    - `unavailable_reason(&self) -> Option<String>`
    - `monitors_selection(&self) -> bool`
    - `copy(&self, text: &str, sensitive: bool) -> io::Result<()>`
    - `copy_from_stdin(&self, sensitive: bool) -> io::Result<()>`
    - `clear(&self) -> io::Result<()>`
    - `binary_path(&self) -> Option<PathBuf>`

### 2. Selection-Monitoring vs. Timer-Driven Lifecycles
- Providers report whether they monitor selection takeovers via `monitors_selection()`.
- **Wayland (`WlClipboardProvider`)**: Returns `monitors_selection() = true`. The holder adopts child processes (`PR_SET_CHILD_SUBREAPER`) and reaps `wl-copy` upon selection loss via `waitpid`, releasing holds and session locks early.
- **Timer-Driven Providers (`MacOsClipboardProvider`, `X11ClipboardProvider`, `MockClipboardProvider`)**: The holder parks and relies on the expiry timer thread to call `provider.clear()` followed by process group cleanup.
- **macOS Scheme A Selection Protection**: On macOS (`MacOsClipboardProvider`), `pbcopy` writes to the centralized pasteboard and exits immediately. To prevent clobbering replacement clipboard selections upon TTL expiry, `MacOsClipboardProvider` tracks `[NSPasteboard generalPasteboard].changeCount`. If `changeCount` increments after Omawarden's copy, the TTL expiry clearing step is safely skipped.

### 3. Resolution Chain & Overrides
- Resolves providers in the following precedence order:
  1. Explicit name / path passed programmatically or via CLI (`--provider`, `--binary-path`).
  2. Environment override (`OMA_CLIPBOARD_PROVIDER`, `OMA_WL_COPY_PATH`).
  3. Compile-time target OS dispatch (`#[cfg(target_os = "macos")]` -> `MacOsClipboardProvider`).
  4. Runtime display detection on Linux/Unix (Wayland display/socket check -> `WlClipboardProvider`; `$DISPLAY` check -> `X11ClipboardProvider`).
  5. Graceful fallback to `UnavailableClipboardProvider` reporting actionable diagnostic guidance.

### 4. Backward Compatibility
- Re-exported `pub type ClipboardManager = ClipboardGuard;` ensures full source compatibility with existing daemon handlers and CLI operations.
- The internal `clipboard-holder` command supports both `--provider <NAME> [--binary-path <PATH>]` and legacy positional path arguments.

### 5. Sensitive Semantics: Two-Tier Security Model
- `sensitive: bool` is a platform best-effort capability:
  - Providers with native OS/protocol support for clipboard history suppression (e.g., Wayland's `wl-copy --sensitive`) forward the privacy flag.
  - Basic CLI adapters (macOS `pbcopy`, X11 `xclip`) execute standard piped writes without shell/script wrappers (avoiding slow interpreters or accessibility permission prompts like `osascript`).
  - The universal security invariant is enforced by Omawarden's core `ClipboardGuard` and `clipboard-holder` via strict TTL auto-clearing and vault session revocation (clearing the selection on lock, suspend, or logout).
- Native Cocoa/FFI bindings (e.g., using `objc2-app-kit` to set `org.nspasteboard.TransientType` directly) are out of scope for this architecture iteration and tracked for future macOS native enhancements.

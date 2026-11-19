# ADR 0030: Pluggable Clipboard Provider Architecture

## Status
Accepted

## Context
Previously, Omawarden's ephemeral clipboard management was tightly coupled to the Wayland-specific `wl-copy` utility (`wl-clipboard`), hardcoding binary paths and error messages throughout `clipboard.rs`, `clipboard_holder.rs`, and CLI handlers.

This tight coupling introduced several architectural limitations:
1. **Platform Lock-In**: Running Omawarden on non-Wayland desktop sessions (X11) or operating systems (macOS, Windows) was impossible without breaking clipboard operations.
2. **Brittle Integration Testing**: Verifying clipboard features required creating shell scripts simulating `wl-copy` on disk and spawning subprocesses rather than utilizing pure in-memory test doubles.
3. **MIME & Selection Ownership Semantics**: Wayland's `wl-copy` and X11's `xclip` fork into the background to own the selection and exit after another application takes over. On macOS, `pbcopy` writes to the centralized pasteboard and exits.

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
- **Selection-Monitoring Providers (`WlClipboardProvider`, `X11ClipboardProvider`)**: Both Wayland (`wl-copy`) and X11 (`xclip`) act as persistent selection owners that fork into the background and terminate when another application acquires the selection (`SelectionClear`). The holder adopts child processes (`PR_SET_CHILD_SUBREAPER`) and reaps the forked provider upon selection loss via `waitpid`, releasing holds and session locks early. On TTL expiration, the holder terminates its own process group (`revoke()`) without acquiring a fresh empty selection, ensuring newer external selections are never overwritten.
- **Timer-Driven Providers (`MacOsClipboardProvider`, `MockClipboardProvider`)**: For platforms with centralized pasteboard architectures where writers terminate immediately (e.g. macOS `pbcopy`), the holder tracks pasteboard state changes (`changeCount`) or parks until the expiry timer triggers.
- **macOS Scheme A Selection Protection**: On macOS (`MacOsClipboardProvider`), `pbcopy` writes to the centralized pasteboard and exits immediately. To prevent clobbering replacement clipboard selections upon TTL expiry, `MacOsClipboardProvider` tracks `[NSPasteboard generalPasteboard].changeCount`. If `changeCount` increments after Omawarden's copy, the TTL expiry clearing step is safely skipped.
- **Explicit session revocation**: Lock and logout cleanup still call the provider's `clear()` when clipboard cleanup is needed and the output gate is held. This is separate from TTL expiry.

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

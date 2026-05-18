# AgentSec

AgentSec is a Rust CLI that helps harden AI coding agent usage in a repository.

It focuses on three workflows:
- `doctor`: assess current security posture
- `generate`: generate baseline policy + hook/config files
- `report`: generate a Markdown policy report

## What it does

AgentSec manages a repo-local policy file (`.agentsec/policy.yaml`) and evaluates risky actions through hooks.

Current policy concepts:
- `files.deny_read`
- `files.deny_write`
- `files.require_human_review`
- `shell.deny`
- `shell.require_human_review`
- `mcp.rules` (scan-only metadata for now)

## Quick Start

### 1. Build

```bash
cargo build
```

### 2. Generate baseline files

```bash
cargo run -- generate --profile team-backend
```

This generates (if missing):
- `.agentsec/policy.yaml`
- `.agentsec/hooks/agentsec-policy.sh` (or `.ps1` on Windows)
- `.claude/settings.json`
- `.codex/config.toml`
- `.github/hooks/agentsec-policy.json`
- `AI_AGENT_POLICY.md`

### 3. Run a posture check

```bash
cargo run -- doctor
```

Optional threshold gating:

```bash
cargo run -- doctor --fail-on high
```

### 4. Regenerate report

```bash
cargo run -- report
```

## CLI Reference

### `doctor`

```bash
agentsec doctor [--policy <path>] [--fail-on low|medium|high|critical]
```

- Loads policy
- Detects generated tool config presence
- Returns findings with severity/remediation
- Exits non-zero when `--fail-on` threshold is reached

### `generate`

```bash
agentsec generate [--policy <path>] [--profile <name>]
```

- Creates default policy if missing
- Creates hook scripts and tool-specific config files
- Does not overwrite existing hook/config files (idempotent baseline generation)

### `report`

```bash
agentsec report [--policy <path>] [--output <path>]
```

- Renders a Markdown report from policy + doctor analysis

### `hook-eval` (internal/runtime)

```bash
agentsec hook-eval [--policy <path>]
```

- Reads hook event JSON from `stdin`
- Evaluates policy
- Returns decision JSON (`allow` / `review` / blocked response for supported hook events)

## How hooks are wired

Generated hook wrappers call `agentsec hook-eval`.

Resolution order in the generated shell/PowerShell wrappers:
1. `agentsec` from `PATH`
2. repo-local `target/release/agentsec`
3. repo-local `target/debug/agentsec`

If no binary is found, wrappers return a safe review-style fallback response.

## Notes

- Policy enforcement depends on each tool's supported hook events.
- If you update hook config files, restart your agent session so hooks are reloaded.
- For architecture and event flow details, see [`docs/how-it-works.md`](docs/how-it-works.md).

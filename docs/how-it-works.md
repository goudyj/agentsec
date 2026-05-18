# How AgentSec Works

This document explains the runtime behavior of AgentSec in a repository.

## 1. Core Model

AgentSec is policy-as-code plus hook-based enforcement.

- Policy source: `.agentsec/policy.yaml`
- Decision engine: `agentsec hook-eval`
- Hook wrappers: `.agentsec/hooks/agentsec-policy.sh` / `.ps1`
- Tool adapters: generated config files for Claude, Codex, and Copilot CLI

The decision engine evaluates actions into:
- `allow`
- `review`
- blocked/denied response (tool-event specific)

## 2. Policy Loading

`agentsec` loads YAML policy into typed Rust structs.

Main rule groups:
- `rules.files.deny_read`
- `rules.files.deny_write`
- `rules.files.require_human_review`
- `rules.shell.deny`
- `rules.shell.require_human_review`
- `rules.mcp.rules`

Pattern matching:
- File/path patterns are matched using glob semantics.
- Shell patterns are matched as exact/substring, with glob fallback.

## 3. Command Responsibilities

### `agentsec generate`

- Creates default policy when missing
- Generates hook wrappers
- Generates tool configuration files:
  - `.claude/settings.json`
  - `.codex/config.toml`
  - `.github/hooks/agentsec-policy.json`
- Generates/refreshes `AI_AGENT_POLICY.md`

Behavior note:
- Existing hook/config files are not overwritten by default.

### `agentsec doctor`

- Detects expected tool config files
- Runs minimal policy sanity checks
- Emits findings with severity and remediation
- Optional fail gate with `--fail-on`

### `agentsec report`

- Renders Markdown posture report from policy + doctor findings

### `agentsec hook-eval`

- Reads a hook event payload from `stdin`
- Infers action type (`file read`, `file write`, `shell`)
- Applies policy rules
- Emits response JSON

## 4. Hook Runtime Flow

At runtime, generated tool hooks invoke the wrapper script.

Wrapper behavior:
1. Resolve repo root and policy path
2. Execute `agentsec hook-eval --policy <path>`
3. Forward stdin payload to `hook-eval`
4. Print JSON decision to stdout

Binary resolution order:
1. `agentsec` from `PATH`
2. `target/release/agentsec`
3. `target/debug/agentsec`

## 5. Event-Specific Output

Some tools require specific output schema for blocking decisions.

AgentSec currently handles dedicated responses for:
- `PreToolUse`
- `PermissionRequest`

For other/unknown events, it returns a generic decision payload.

## 6. Practical Enforcement Boundaries

AgentSec can only enforce what the host tool exposes via hooks.

Important implications:
- If an action is not emitted through a supported hook event, it cannot be blocked by AgentSec.
- Hook config changes usually require session restart/reload.
- Policy coverage should be validated with real tool events in your environment.

## 7. Testing and Verification

Recommended local verification loop:
1. `cargo run -- generate`
2. Restart Claude/Codex session
3. Trigger representative commands (`rm`, `terraform`, sensitive file read/write)
4. Confirm decisions in hook behavior and tool UI output
5. Run `cargo run -- doctor --fail-on high`

For low-level checks, simulate hook payloads:

```bash
printf '%s' '{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf tmp"}}' | cargo run -- hook-eval
```

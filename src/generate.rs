use std::fs;
use std::path::Path;

use serde_json::json;

use crate::doctor::analyze;
use crate::error::AppError;
use crate::policy::{load_policy, write_default_policy};
use crate::report::render_markdown_report;

pub fn run_generate(policy_path: &Path, profile: Option<&str>) -> Result<(), AppError> {
    write_default_policy(policy_path, profile)?;
    let policy = load_policy(policy_path)?;
    let hook_script_path = if cfg!(windows) {
        ".agentsec/hooks/agentsec-policy.ps1"
    } else {
        ".agentsec/hooks/agentsec-policy.sh"
    };
    let claude_hook_command = if cfg!(windows) {
        "powershell -NoProfile -ExecutionPolicy Bypass -File .agentsec/hooks/agentsec-policy.ps1"
    } else {
        "sh .agentsec/hooks/agentsec-policy.sh"
    };
    let codex_hook_command = if cfg!(windows) {
        "powershell -NoProfile -ExecutionPolicy Bypass -File .agentsec/hooks/agentsec-policy.ps1"
    } else {
        "sh .agentsec/hooks/agentsec-policy.sh"
    };

    create_parented_file(
        Path::new(".agentsec/hooks/README.md"),
        "# AgentSec hooks\n\nThis directory contains generated hook helpers.\n",
        false,
    )?;
    if cfg!(windows) {
        create_parented_file(
            Path::new(hook_script_path),
            "$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path\n$repoRoot = Resolve-Path (Join-Path $scriptDir \"..\\..\")\n$policyPath = Join-Path $repoRoot \".agentsec\\policy.yaml\"\n\n$agentsec = Get-Command agentsec -ErrorAction SilentlyContinue\nif ($agentsec) {\n  & $agentsec.Source hook-eval --policy $policyPath\n  exit $LASTEXITCODE\n}\n\n$releaseBin = Join-Path $repoRoot \"target\\release\\agentsec.exe\"\nif (Test-Path $releaseBin) {\n  & $releaseBin hook-eval --policy $policyPath\n  exit $LASTEXITCODE\n}\n\n$debugBin = Join-Path $repoRoot \"target\\debug\\agentsec.exe\"\nif (Test-Path $debugBin) {\n  & $debugBin hook-eval --policy $policyPath\n  exit $LASTEXITCODE\n}\n\nWrite-Output '{\"decision\":\"review\",\"reason\":\"agentsec binary not found\"}'\n",
            false,
        )?;
    } else {
        create_parented_file(
            Path::new(hook_script_path),
            "#!/usr/bin/env sh\nset -u\n\nSCRIPT_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\nREPO_ROOT=$(CDPATH= cd -- \"$SCRIPT_DIR/../..\" && pwd)\nPOLICY_PATH=\"$REPO_ROOT/.agentsec/policy.yaml\"\n\nif command -v agentsec >/dev/null 2>&1; then\n  exec agentsec hook-eval --policy \"$POLICY_PATH\"\nfi\n\nif [ -x \"$REPO_ROOT/target/release/agentsec\" ]; then\n  exec \"$REPO_ROOT/target/release/agentsec\" hook-eval --policy \"$POLICY_PATH\"\nfi\n\nif [ -x \"$REPO_ROOT/target/debug/agentsec\" ]; then\n  exec \"$REPO_ROOT/target/debug/agentsec\" hook-eval --policy \"$POLICY_PATH\"\nfi\n\necho '{\"decision\":\"review\",\"reason\":\"agentsec binary not found\"}'\n",
            false,
        )?;
    }
    create_parented_file(
        Path::new(".claude/settings.json"),
        &format!(
            "{{\n  \"hooks\": {{\n    \"PreToolUse\": [\n      {{\n        \"matcher\": \"*\",\n        \"hooks\": [\n          {{\n            \"type\": \"command\",\n            \"command\": \"{claude_hook_command}\"\n          }}\n        ]\n      }}\n    ],\n    \"PermissionRequest\": [\n      {{\n        \"matcher\": \"*\",\n        \"hooks\": [\n          {{\n            \"type\": \"command\",\n            \"command\": \"{claude_hook_command}\"\n          }}\n        ]\n      }}\n    ]\n  }}\n}}\n"
        ),
        false,
    )?;
    create_parented_file(
        Path::new(".codex/config.toml"),
        &format!(
            "[features]\nhooks = true\n\n[[hooks.PreToolUse]]\nmatcher = \".*\"\n\n[[hooks.PreToolUse.hooks]]\ntype = \"command\"\ncommand = '{codex_hook_command}'\ntimeout = 30\nstatusMessage = \"AgentSec policy check\"\n\n[[hooks.PermissionRequest]]\nmatcher = \".*\"\n\n[[hooks.PermissionRequest.hooks]]\ntype = \"command\"\ncommand = '{codex_hook_command}'\ntimeout = 30\nstatusMessage = \"AgentSec approval check\"\n"
        ),
        false,
    )?;

    let copilot_json = serde_json::to_string_pretty(&json!({
        "hooks": {
            "preToolUse": [hook_script_path]
        }
    }))?;
    create_parented_file(
        Path::new(".github/hooks/agentsec-policy.json"),
        &(copilot_json + "\n"),
        false,
    )?;

    let report_path = Path::new("AI_AGENT_POLICY.md");
    let doctor = analyze(&policy);
    let report = render_markdown_report(&policy, &doctor);
    create_parented_file(report_path, &report, true)?;

    println!("Generated baseline policy and hook/config files.");
    Ok(())
}

fn create_parented_file(path: &Path, content: &str, overwrite: bool) -> Result<(), AppError> {
    if path.exists() && !overwrite {
        println!(
            "File `{}` already exists, skipping generation.",
            path.display()
        );
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| AppError::MissingParent(path.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| AppError::WriteFile {
        path: parent.display().to_string(),
        source,
    })?;
    fs::write(path, content).map_err(|source| AppError::WriteFile {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

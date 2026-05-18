use std::io::{self, Read};
use std::path::Path;

use globset::Glob;
use serde::Serialize;
use serde_json::Value;

use crate::error::AppError;
use crate::policy::Policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ActionKind {
    FileRead,
    FileWrite,
    Shell,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Decision {
    decision: &'static str,
    reason: String,
    rule: Option<&'static str>,
    action: Option<&'static str>,
    target: Option<String>,
}

#[derive(Debug, Serialize)]
struct HookOutput<'a> {
    decision: &'a str,
    reason: &'a str,
    policy: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    rule: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a str>,
}

pub fn run_hook_eval(policy: &Policy) -> Result<(), AppError> {
    let mut input = String::new();
    io::stdin()
        .read_to_string(&mut input)
        .map_err(AppError::ReadStdin)?;

    let raw_event = input.trim();
    let decision = evaluate_hook_event(policy, raw_event)?;

    let event_kind = serde_json::from_str::<Value>(raw_event)
        .ok()
        .and_then(|value| string_field(&value, &[&["hook_event_name"]]));

    match event_kind.as_deref() {
        Some("PreToolUse") => emit_pre_tool_use(&decision)?,
        Some("PermissionRequest") => emit_permission_request(&decision)?,
        _ => {
            let output = HookOutput {
                decision: decision.decision,
                reason: &decision.reason,
                policy: &policy.profile,
                rule: decision.rule,
                action: decision.action,
                target: decision.target.as_deref(),
            };
            println!("{}", serde_json::to_string(&output)?);
        }
    }

    Ok(())
}

fn emit_pre_tool_use(decision: &Decision) -> Result<(), AppError> {
    if decision.decision == "allow" {
        println!("{{}}");
        return Ok(());
    }

    let output = serde_json::json!({
        "decision": "block",
        "reason": decision.reason,
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": decision.reason
        }
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn emit_permission_request(decision: &Decision) -> Result<(), AppError> {
    if decision.decision == "allow" {
        println!("{{}}");
        return Ok(());
    }

    let output = serde_json::json!({
        "decision": "block",
        "reason": decision.reason,
        "hookSpecificOutput": {
            "hookEventName": "PermissionRequest",
            "decision": {
                "behavior": "deny",
                "message": decision.reason
            },
            "permissionDecision": "deny",
            "permissionDecisionReason": decision.reason
        }
    });
    println!("{}", serde_json::to_string(&output)?);
    Ok(())
}

fn evaluate_hook_event(policy: &Policy, raw_event: &str) -> Result<Decision, AppError> {
    if raw_event.is_empty() {
        return Ok(Decision {
            decision: "allow",
            reason: "No hook payload provided.".to_string(),
            rule: None,
            action: None,
            target: None,
        });
    }

    let event: Value = match serde_json::from_str(raw_event) {
        Ok(value) => value,
        Err(_) => {
            return Ok(Decision {
                decision: "review",
                reason: "Invalid hook payload JSON.".to_string(),
                rule: None,
                action: None,
                target: None,
            });
        }
    };

    Ok(evaluate_from_value(policy, &event))
}

fn evaluate_from_value(policy: &Policy, event: &Value) -> Decision {
    let action = detect_action(event);
    let path = extract_path(event);
    let command = extract_command(event);

    match action {
        ActionKind::FileRead => evaluate_file_read(policy, path),
        ActionKind::FileWrite => evaluate_file_write(policy, path),
        ActionKind::Shell => evaluate_shell(policy, command),
        ActionKind::Unknown => Decision {
            decision: "allow",
            reason: "No actionable hook event detected.".to_string(),
            rule: None,
            action: None,
            target: None,
        },
    }
}

fn evaluate_file_read(policy: &Policy, path: Option<String>) -> Decision {
    let Some(path_value) = path else {
        return Decision {
            decision: "allow",
            reason: "Read action without file path.".to_string(),
            rule: None,
            action: Some("file_read"),
            target: None,
        };
    };

    if matches_any_file_pattern(&policy.rules.files.deny_read, &path_value) {
        return Decision {
            decision: "deny",
            reason: format!("File read denied by policy for `{path_value}`."),
            rule: Some("files.deny_read"),
            action: Some("file_read"),
            target: Some(path_value),
        };
    }

    if matches_any_file_pattern(&policy.rules.files.require_human_review, &path_value) {
        return Decision {
            decision: "review",
            reason: format!("File read requires human review for `{path_value}`."),
            rule: Some("files.require_human_review"),
            action: Some("file_read"),
            target: Some(path_value),
        };
    }

    Decision {
        decision: "allow",
        reason: "No matching file read rule.".to_string(),
        rule: None,
        action: Some("file_read"),
        target: Some(path_value),
    }
}

fn evaluate_file_write(policy: &Policy, path: Option<String>) -> Decision {
    let Some(path_value) = path else {
        return Decision {
            decision: "allow",
            reason: "Write action without file path.".to_string(),
            rule: None,
            action: Some("file_write"),
            target: None,
        };
    };

    if matches_any_file_pattern(&policy.rules.files.deny_write, &path_value) {
        return Decision {
            decision: "deny",
            reason: format!("File write denied by policy for `{path_value}`."),
            rule: Some("files.deny_write"),
            action: Some("file_write"),
            target: Some(path_value),
        };
    }

    if matches_any_file_pattern(&policy.rules.files.require_human_review, &path_value) {
        return Decision {
            decision: "review",
            reason: format!("File write requires human review for `{path_value}`."),
            rule: Some("files.require_human_review"),
            action: Some("file_write"),
            target: Some(path_value),
        };
    }

    Decision {
        decision: "allow",
        reason: "No matching file write rule.".to_string(),
        rule: None,
        action: Some("file_write"),
        target: Some(path_value),
    }
}

fn evaluate_shell(policy: &Policy, command: Option<String>) -> Decision {
    let Some(command_value) = command else {
        return Decision {
            decision: "allow",
            reason: "Shell action without command.".to_string(),
            rule: None,
            action: Some("shell"),
            target: None,
        };
    };

    if matches_any_shell_pattern(&policy.rules.shell.deny, &command_value) {
        return Decision {
            decision: "deny",
            reason: format!("Shell command denied by policy: `{command_value}`."),
            rule: Some("shell.deny"),
            action: Some("shell"),
            target: Some(command_value),
        };
    }

    if matches_any_shell_pattern(&policy.rules.shell.require_human_review, &command_value) {
        return Decision {
            decision: "review",
            reason: format!("Shell command requires human review: `{command_value}`."),
            rule: Some("shell.require_human_review"),
            action: Some("shell"),
            target: Some(command_value),
        };
    }

    Decision {
        decision: "allow",
        reason: "No matching shell rule.".to_string(),
        rule: None,
        action: Some("shell"),
        target: Some(command_value),
    }
}

fn detect_action(event: &Value) -> ActionKind {
    let action_hint = string_field(
        event,
        &[
            &["action"],
            &["event"],
            &["tool_action"],
            &["tool_input", "action"],
            &["input", "action"],
        ],
    );
    if let Some(action_value) = action_hint {
        let normalized = action_value.to_ascii_lowercase();
        if normalized.contains("read") {
            return ActionKind::FileRead;
        }
        if normalized.contains("write") || normalized.contains("edit") {
            return ActionKind::FileWrite;
        }
        if normalized.contains("shell") || normalized.contains("bash") || normalized.contains("cmd")
        {
            return ActionKind::Shell;
        }
    }

    let tool_hint = string_field(
        event,
        &[
            &["tool_name"],
            &["tool"],
            &["name"],
            &["tool_input", "tool_name"],
            &["input", "tool_name"],
        ],
    );
    if let Some(tool_value) = tool_hint {
        let normalized = tool_value.to_ascii_lowercase();
        if normalized.contains("read") {
            return ActionKind::FileRead;
        }
        if normalized.contains("write")
            || normalized.contains("edit")
            || normalized.contains("multiedit")
        {
            return ActionKind::FileWrite;
        }
        if normalized.contains("bash")
            || normalized.contains("shell")
            || normalized.contains("command")
        {
            return ActionKind::Shell;
        }
    }

    if extract_command(event).is_some() {
        return ActionKind::Shell;
    }

    ActionKind::Unknown
}

fn extract_path(event: &Value) -> Option<String> {
    let raw = string_field(
        event,
        &[
            &["path"],
            &["target"],
            &["file"],
            &["file_path"],
            &["tool_input", "path"],
            &["tool_input", "file_path"],
            &["tool_input", "target"],
            &["input", "path"],
            &["input", "file_path"],
            &["args", "path"],
            &["params", "path"],
        ],
    )?;

    Some(normalize_path(&raw))
}

fn extract_command(event: &Value) -> Option<String> {
    string_field(
        event,
        &[
            &["command"],
            &["cmd"],
            &["tool_input", "command"],
            &["tool_input", "cmd"],
            &["input", "command"],
            &["args", "command"],
            &["params", "command"],
        ],
    )
}

fn string_field(event: &Value, paths: &[&[&str]]) -> Option<String> {
    for path in paths {
        if let Some(value) = value_by_path(event, path) {
            if let Some(as_str) = value.as_str() {
                let trimmed = as_str.trim();
                if !trimmed.is_empty() {
                    return Some(trimmed.to_string());
                }
            }
        }
    }
    None
}

fn value_by_path<'a>(event: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = event;
    for segment in path {
        current = current.get(*segment)?;
    }
    Some(current)
}

fn normalize_path(path: &str) -> String {
    let replaced = path.replace('\\', "/");
    replaced.trim_start_matches("./").to_string()
}

fn matches_any_file_pattern(patterns: &[String], path: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| matches_file_pattern(pattern, path))
}

fn matches_file_pattern(pattern: &str, path: &str) -> bool {
    let normalized_pattern = normalize_path(pattern);
    let candidates = path_match_candidates(path);

    for candidate in &candidates {
        if candidate == &normalized_pattern {
            return true;
        }
    }

    if let Ok(glob) = Glob::new(&normalized_pattern) {
        let matcher = glob.compile_matcher();
        for candidate in &candidates {
            if matcher.is_match(candidate) {
                return true;
            }
        }
    }

    false
}

fn path_match_candidates(path: &str) -> Vec<String> {
    let normalized = normalize_path(path);
    let mut candidates = vec![normalized.clone()];

    if let Some(name) = Path::new(&normalized).file_name().and_then(|part| part.to_str()) {
        let file_name = name.to_string();
        if !candidates.contains(&file_name) {
            candidates.push(file_name);
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        let cwd_normalized = normalize_path(&cwd.to_string_lossy());
        let prefix = format!("{cwd_normalized}/");
        if let Some(relative) = normalized.strip_prefix(&prefix) {
            let relative_value = relative.to_string();
            if !candidates.contains(&relative_value) {
                candidates.push(relative_value);
            }
        }
    }

    candidates
}

fn matches_any_shell_pattern(patterns: &[String], command: &str) -> bool {
    patterns
        .iter()
        .any(|pattern| matches_shell_pattern(pattern, command))
}

fn matches_shell_pattern(pattern: &str, command: &str) -> bool {
    let normalized_pattern = pattern.trim();
    if normalized_pattern.is_empty() {
        return false;
    }

    if command == normalized_pattern || command.contains(normalized_pattern) {
        return true;
    }

    if let Ok(glob) = Glob::new(normalized_pattern) {
        return glob.compile_matcher().is_match(command);
    }

    false
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::policy::Policy;

    #[test]
    fn denies_secret_file_read() {
        let policy = Policy::default();
        let event = json!({
            "action": "file_read",
            "path": ".env"
        });

        let decision = evaluate_from_value(&policy, &event);
        assert_eq!(decision.decision, "deny");
        assert_eq!(decision.rule, Some("files.deny_read"));
    }

    #[test]
    fn reviews_sensitive_file_write() {
        let policy = Policy::default();
        let event = json!({
            "tool_name": "Edit",
            "tool_input": { "path": "auth/service.rs" }
        });

        let decision = evaluate_from_value(&policy, &event);
        assert_eq!(decision.decision, "review");
        assert_eq!(decision.rule, Some("files.require_human_review"));
    }

    #[test]
    fn denies_destructive_shell_command() {
        let policy = Policy::default();
        let event = json!({
            "tool_name": "Bash",
            "command": "terraform destroy -auto-approve"
        });

        let decision = evaluate_from_value(&policy, &event);
        assert_eq!(decision.decision, "deny");
        assert_eq!(decision.rule, Some("shell.deny"));
    }

    #[test]
    fn allows_non_matching_shell_command() {
        let policy = Policy::default();
        let event = json!({
            "action": "shell",
            "command": "cargo test"
        });

        let decision = evaluate_from_value(&policy, &event);
        assert_eq!(decision.decision, "allow");
        assert_eq!(decision.rule, None);
    }

    #[test]
    fn denies_secret_file_read_with_absolute_path() {
        let policy = Policy::default();
        let event = json!({
            "tool_name": "Read",
            "tool_input": { "file_path": "/Users/jean/Documents/developpement/agentsec/.env" }
        });

        let decision = evaluate_from_value(&policy, &event);
        assert_eq!(decision.decision, "deny");
        assert_eq!(decision.rule, Some("files.deny_read"));
    }
}

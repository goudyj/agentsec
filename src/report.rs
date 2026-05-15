use std::fs;
use std::path::Path;

use chrono::Utc;

use crate::doctor::{analyze, DoctorResult};
use crate::error::AppError;
use crate::policy::Policy;

pub fn run_report(policy: &Policy, output: &Path) -> Result<(), AppError> {
    let doctor = analyze(policy);
    let markdown = render_markdown_report(policy, &doctor);
    fs::write(output, markdown).map_err(|source| AppError::WriteFile {
        path: output.display().to_string(),
        source,
    })?;
    println!("Report written to {}", output.display());
    Ok(())
}

pub fn render_markdown_report(policy: &Policy, doctor: &DoctorResult) -> String {
    let now = Utc::now().to_rfc3339();
    let mut out = String::new();

    out.push_str("# AI Agent Security Policy Report\n\n");
    out.push_str(&format!("- Timestamp: `{now}`\n"));
    out.push_str(&format!("- Profile: `{}`\n\n", policy.profile));

    out.push_str("## Tools Detected\n\n");
    for tool in &doctor.detections {
        let status = if tool.detected { "detected" } else { "missing" };
        out.push_str(&format!("- {}: `{status}`\n", tool.name));
    }
    out.push('\n');

    out.push_str("## Active Rules\n\n");
    out.push_str(&format!(
        "- files.deny_read: {}\n",
        join_or_none(&policy.rules.files.deny_read)
    ));
    out.push_str(&format!(
        "- files.deny_write: {}\n",
        join_or_none(&policy.rules.files.deny_write)
    ));
    out.push_str(&format!(
        "- files.require_human_review: {}\n",
        join_or_none(&policy.rules.files.require_human_review)
    ));
    out.push_str(&format!(
        "- shell.deny: {}\n",
        join_or_none(&policy.rules.shell.deny)
    ));
    out.push_str(&format!(
        "- shell.require_human_review: {}\n",
        join_or_none(&policy.rules.shell.require_human_review)
    ));
    out.push_str(&format!("- mcp.rules: {}\n\n", join_or_none(&policy.rules.mcp.rules)));

    out.push_str("## Findings\n\n");
    for finding in &doctor.findings {
        out.push_str(&format!(
            "- **{}** {}. Remediation: {}\n",
            finding.severity.as_str().to_uppercase(),
            finding.title,
            finding.remediation
        ));
    }
    out.push('\n');
    out.push_str("## Coverage Limits\n\n");
    out.push_str(
        "- Hook coverage depends on each tool version and supported lifecycle events.\n",
    );
    out.push_str("- Non-hookable actions should be treated as residual risk.\n");

    out
}

fn join_or_none(values: &[String]) -> String {
    if values.is_empty() {
        "`none`".to_string()
    } else {
        format!("`{}`", values.join("`, `"))
    }
}

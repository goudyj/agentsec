use std::path::Path;

use crate::cli::SeverityArg;
use crate::error::AppError;
use crate::policy::Policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub severity: Severity,
    pub title: String,
    pub remediation: String,
}

#[derive(Debug, Clone)]
pub struct ToolDetection {
    pub name: &'static str,
    pub detected: bool,
}

#[derive(Debug, Clone)]
pub struct DoctorResult {
    pub detections: Vec<ToolDetection>,
    pub findings: Vec<Finding>,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

fn threshold_from_arg(value: SeverityArg) -> Severity {
    match value {
        SeverityArg::Low => Severity::Low,
        SeverityArg::Medium => Severity::Medium,
        SeverityArg::High => Severity::High,
        SeverityArg::Critical => Severity::Critical,
    }
}

pub fn analyze(policy: &Policy) -> DoctorResult {
    let detections = vec![
        ToolDetection {
            name: "Claude Code",
            detected: Path::new(".claude/settings.json").exists(),
        },
        ToolDetection {
            name: "OpenAI Codex",
            detected: Path::new(".codex/config.toml").exists() || Path::new("codex/config.toml").exists(),
        },
        ToolDetection {
            name: "Copilot CLI",
            detected: Path::new(".github/hooks/agentsec-policy.json").exists(),
        },
    ];

    let mut findings = Vec::new();

    if policy.rules.files.deny_read.is_empty() {
        findings.push(Finding {
            severity: Severity::Critical,
            title: "No `files.deny_read` patterns configured".to_string(),
            remediation: "Add patterns for secrets (e.g. .env, credentials, *.pem).".to_string(),
        });
    }
    if policy.rules.shell.deny.is_empty() {
        findings.push(Finding {
            severity: Severity::High,
            title: "No `shell.deny` commands configured".to_string(),
            remediation: "Block obviously destructive commands (terraform destroy, rm -rf /)."
                .to_string(),
        });
    }
    if !detections.iter().any(|item| item.detected) {
        findings.push(Finding {
            severity: Severity::Medium,
            title: "No tool-specific security configuration detected".to_string(),
            remediation: "Run `agentsec generate` to create baseline hooks/config files."
                .to_string(),
        });
    }
    if findings.is_empty() {
        findings.push(Finding {
            severity: Severity::Low,
            title: "No critical gaps detected by minimal doctor checks".to_string(),
            remediation: "Review report coverage limits for non-hookable events.".to_string(),
        });
    }

    DoctorResult {
        detections,
        findings,
    }
}

pub fn run_doctor(policy: &Policy, fail_on: Option<SeverityArg>) -> Result<DoctorResult, AppError> {
    let result = analyze(policy);

    println!("Profile: {}", policy.profile);
    println!("Tools:");
    for detection in &result.detections {
        let status = if detection.detected { "detected" } else { "missing" };
        println!("  - {}: {}", detection.name, status);
    }
    println!("Findings:");
    for finding in &result.findings {
        println!(
            "  - [{}] {} | remediation: {}",
            finding.severity.as_str(),
            finding.title,
            finding.remediation
        );
    }

    if let Some(threshold_arg) = fail_on {
        let threshold = threshold_from_arg(threshold_arg);
        let reached = result
            .findings
            .iter()
            .any(|finding| finding.severity >= threshold);
        if reached {
            return Err(AppError::FailOnTriggered(threshold.as_str().to_string()));
        }
    }

    Ok(result)
}

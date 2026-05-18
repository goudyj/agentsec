use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AppError;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Policy {
    pub profile: String,
    pub rules: Rules,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    pub files: FileRules,
    pub shell: ShellRules,
    pub mcp: McpRules,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct FileRules {
    pub deny_read: Vec<String>,
    pub deny_write: Vec<String>,
    pub require_human_review: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShellRules {
    pub deny: Vec<String>,
    pub require_human_review: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct McpRules {
    pub rules: Vec<String>,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            profile: "team-backend".to_string(),
            rules: Rules {
                files: FileRules {
                    deny_read: vec![
                        ".env".to_string(),
                        ".env.*".to_string(),
                        ".aws/credentials".to_string(),
                        "**/*.pem".to_string(),
                    ],
                    deny_write: vec![],
                    require_human_review: vec!["auth/**".to_string(), "payments/**".to_string()],
                },
                shell: ShellRules {
                    deny: vec![
                        "rm -rf".to_string(),
                        "rm -f".to_string(),
                        "git push --force".to_string(),
                        "git push -f".to_string(),
                        "git reset --hard".to_string(),
                        "git clean -fd".to_string(),
                        "DROP TABLE".to_string(),
                        "drop table".to_string(),
                        "DROP DATABASE".to_string(),
                        "drop database".to_string(),
                        "TRUNCATE".to_string(),
                        "truncate".to_string(),
                        "kubectl apply".to_string(),
                        "kubectl delete".to_string(),
                        "terraform apply".to_string(),
                        "terraform destroy".to_string(),
                        "cdk deploy".to_string(),
                        "cdk destroy".to_string(),
                    ],
                    require_human_review: vec![
                        "ssh".to_string(),
                        "scp".to_string(),
                        "rsync".to_string(),
                        "ngrok".to_string(),
                        "curl".to_string(),
                    ],
                },
                mcp: McpRules {
                    rules: vec!["scan-only".to_string()],
                },
            },
        }
    }
}

pub fn load_policy(path: &Path) -> Result<Policy, AppError> {
    let raw = fs::read_to_string(path).map_err(|source| AppError::ReadFile {
        path: path.display().to_string(),
        source,
    })?;

    let parsed = serde_yaml::from_str::<Policy>(&raw).map_err(|source| AppError::ParsePolicy {
        path: path.display().to_string(),
        source,
    })?;

    if parsed.profile.trim().is_empty() {
        return Err(AppError::EmptyProfile);
    }

    Ok(parsed)
}

pub fn write_default_policy(path: &Path, profile: Option<&str>) -> Result<(), AppError> {
    if path.exists() {
        return Ok(());
    }

    let mut policy = Policy::default();
    if let Some(profile_value) = profile {
        policy.profile = profile_value.to_string();
    }

    let yaml = serde_yaml::to_string(&policy).map_err(|source| AppError::WritePolicy {
        path: path.display().to_string(),
        source,
    })?;

    let parent = path
        .parent()
        .ok_or_else(|| AppError::MissingParent(path.to_path_buf()))?;
    fs::create_dir_all(parent).map_err(|source| AppError::WriteFile {
        path: parent.display().to_string(),
        source,
    })?;
    fs::write(path, yaml).map_err(|source| AppError::WriteFile {
        path: path.display().to_string(),
        source,
    })?;
    Ok(())
}

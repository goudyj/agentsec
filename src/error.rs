use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("failed to read file `{path}`: {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to write file `{path}`: {source}")]
    WriteFile {
        path: String,
        source: std::io::Error,
    },
    #[error("failed to parse yaml policy `{path}`: {source}")]
    ParsePolicy {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("failed to write yaml policy `{path}`: {source}")]
    WritePolicy {
        path: String,
        source: serde_yaml::Error,
    },
    #[error("policy profile cannot be empty")]
    EmptyProfile,
    #[error("`--fail-on` threshold reached with severity `{0}`")]
    FailOnTriggered(String),
    #[error("missing parent directory for path `{0}`")]
    MissingParent(PathBuf),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

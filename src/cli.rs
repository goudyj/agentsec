use std::path::PathBuf;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Debug, Clone, ValueEnum)]
pub enum SeverityArg {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Parser)]
#[command(name = "agentsec", version, about = "AI coding agent security CLI")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    Doctor {
        #[arg(long, default_value = ".agentsec/policy.yaml")]
        policy: PathBuf,
        #[arg(long)]
        fail_on: Option<SeverityArg>,
    },
    Generate {
        #[arg(long, default_value = ".agentsec/policy.yaml")]
        policy: PathBuf,
        #[arg(long)]
        profile: Option<String>,
    },
    Report {
        #[arg(long, default_value = ".agentsec/policy.yaml")]
        policy: PathBuf,
        #[arg(long, default_value = "AI_AGENT_POLICY.md")]
        output: PathBuf,
    },
    HookEval {
        #[arg(long, default_value = ".agentsec/policy.yaml")]
        policy: PathBuf,
    },
}

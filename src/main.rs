mod cli;
mod doctor;
mod error;
mod generate;
mod hook_eval;
mod policy;
mod report;

use clap::Parser;

use crate::cli::{Cli, Commands};
use crate::doctor::run_doctor;
use crate::error::AppError;
use crate::generate::run_generate;
use crate::hook_eval::run_hook_eval;
use crate::policy::load_policy;
use crate::report::run_report;

fn main() -> Result<(), AppError> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Doctor { policy, fail_on } => {
            let loaded_policy = load_policy(&policy)?;
            run_doctor(&loaded_policy, fail_on)?;
        }
        Commands::Generate { policy, profile } => {
            run_generate(&policy, profile.as_deref())?;
        }
        Commands::Report { policy, output } => {
            let loaded_policy = load_policy(&policy)?;
            run_report(&loaded_policy, &output)?;
        }
        Commands::HookEval { policy } => {
            let loaded_policy = load_policy(&policy)?;
            run_hook_eval(&loaded_policy)?;
        }
    }

    Ok(())
}

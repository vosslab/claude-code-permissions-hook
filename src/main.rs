#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![warn(rust_2018_idioms)]
#![warn(rust_2024_compatibility)]
#![warn(deprecated_safe)]

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use env_logger::Env;
use std::path::PathBuf;

use claude_code_permissions_hook::auditing::{audit_passthrough, audit_tool_use};
use claude_code_permissions_hook::{
    Decision, HookInput, HookOutput, load_config, process_hook_input_with_rules, validate_config,
};

#[derive(Debug, Parser)]
#[clap(author, version, about = "Claude Code command permissions hook")]
struct Opts {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the hook (reads JSON from stdin, outputs decision to stdout)
    Run {
        #[clap(short, long, value_parser)]
        config: PathBuf,
    },
    /// Validate a configuration file
    Validate {
        #[clap(short, long, value_parser)]
        config: PathBuf,
    },
}

fn run_hook(config_path: PathBuf) -> Result<()> {
    let (config, deny_rules, allow_rules) =
        load_config(&config_path).context("Failed to load configuration")?;

    let input = HookInput::read_from_stdin().context("Failed to read hook input")?;

    // Use pre-compiled rules to avoid recompiling regex on every call
    let result = process_hook_input_with_rules(&deny_rules, &allow_rules, &input);

    // Audit the decision
    audit_tool_use(
        &config.audit.audit_file,
        config.audit.audit_level,
        &input,
        result.decision,
        result.reason.as_deref(),
    );

    // Log passthrough decisions to dedicated file when configured
    if result.decision == Decision::Passthrough {
        if let Some(ref pt_path) = config.audit.passthrough_log_file {
            audit_passthrough(pt_path, &input);
        }
    }

    // Output decision to stdout (passthrough = no output)
    match result.decision {
        Decision::Allow => {
            let output = HookOutput::allow(result.reason.unwrap_or_default());
            output.write_to_stdout()?;
        }
        Decision::Deny => {
            let output = HookOutput::deny(result.reason.unwrap_or_default());
            output.write_to_stdout()?;
        }
        Decision::Passthrough => {
            // No output for passthrough
        }
    }

    Ok(())
}

fn run_validate_config(config_path: PathBuf) -> Result<()> {
    let (deny_count, allow_count) = validate_config(&config_path)?;

    let config = claude_code_permissions_hook::Config::load_from_file(&config_path)?;

    let total = deny_count + allow_count;
    println!("Valid: loaded {} rules ({} deny, {} allow)", total, deny_count, allow_count);
    println!("  Audit file:  {}", config.audit.audit_file.display());
    println!("  Audit level: {:?}", config.audit.audit_level);

    Ok(())
}

fn main() -> Result<()> {
    // Initialize diagnostic logger from RUST_LOG env var (default: warn)
    env_logger::Builder::from_env(Env::default().default_filter_or("warn")).init();

    let opts = Opts::parse();

    match opts.command {
        Commands::Run { config } => run_hook(config),
        Commands::Validate { config } => run_validate_config(config),
    }
}

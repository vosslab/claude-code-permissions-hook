#![forbid(unsafe_code)]
#![warn(clippy::all)]
#![warn(rust_2018_idioms)]
#![warn(rust_2024_compatibility)]
#![warn(deprecated_safe)]

pub mod auditing;
pub mod config;
pub mod hook_io;
pub mod matcher;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use env_logger::Env;
use log::info;
use std::path::PathBuf;

use crate::auditing::{Decision, audit_tool_use};
use crate::config::Config;
use crate::hook_io::{HookInput, HookOutput};
use crate::matcher::check_rules;

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
    let config = Config::load_from_file(&config_path).context("Failed to load configuration")?;

    let (deny_rules, allow_rules) = config.compile_rules().context("Failed to compile rules")?;

    let input = HookInput::read_from_stdin().context("Failed to read hook input")?;

    // Check deny rules first
    if let Some(reason) = check_rules(&deny_rules, &input) {
        audit_tool_use(
            &config.audit.audit_file,
            config.audit.audit_level,
            &input,
            Decision::Deny,
            Some(&reason),
        );
        let output = HookOutput::deny(reason);
        output.write_to_stdout()?;
        return Ok(());
    }

    // Check allow rules
    if let Some(reason) = check_rules(&allow_rules, &input) {
        audit_tool_use(
            &config.audit.audit_file,
            config.audit.audit_level,
            &input,
            Decision::Allow,
            Some(&reason),
        );
        let output = HookOutput::allow(reason);
        output.write_to_stdout()?;
        return Ok(());
    }

    // No match - passthrough to normal Claude Code permission flow
    audit_tool_use(
        &config.audit.audit_file,
        config.audit.audit_level,
        &input,
        Decision::Passthrough,
        None,
    );
    Ok(())
}

fn validate_config(config_path: PathBuf) -> Result<()> {
    let config = Config::load_from_file(&config_path).context("Failed to load configuration")?;

    let (deny_rules, allow_rules) = config.compile_rules().context("Failed to compile rules")?;

    info!("Configuration is valid!");
    info!("  Deny rules: {}", deny_rules.len());
    info!("  Allow rules: {}", allow_rules.len());
    info!("  Audit file: {}", config.audit.audit_file.display());
    info!("  Audit level: {:?}", config.audit.audit_level);

    Ok(())
}

fn main() -> Result<()> {
    // Initialize diagnostic logger from RUST_LOG env var (default: warn)
    env_logger::Builder::from_env(Env::default().default_filter_or("warn")).init();

    let opts = Opts::parse();

    match opts.command {
        Commands::Run { config } => run_hook(config),
        Commands::Validate { config } => validate_config(config),
    }
}

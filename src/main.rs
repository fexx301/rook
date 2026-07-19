#![forbid(unsafe_code)]

//! Rook - an AI-agent honeypot and adversarial trap server.
//!
//! It looks like a normal website but is engineered to detect, fingerprint,
//! log, and benignly derail autonomous AI bots/LLM-agents.

mod config;
mod dashboard;
mod detect;
mod persona;
mod server;
mod session;
mod store;
mod telemetry;
mod traps;

use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    telemetry::init();

    let config_path = std::env::var_os("ROOK_CONFIG")
        .or_else(|| std::env::var_os("AGENTSBANE_CONFIG"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("config.toml"));
    let config = config::Config::load(&config_path)?
        .with_environment_overrides()?
        .validate()?;

    tracing::info!(
        "Loaded config — persona: \"{}\", bind: {}",
        config.persona.name,
        config.bind_addr()
    );

    server::run(config).await
}

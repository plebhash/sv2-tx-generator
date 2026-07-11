//! Binary entry point for the sv2-tx-generator.
//!
//! Reads a `config.toml` path from the first CLI argument (defaults to `config.toml`),
//! creates a [`TxGenerator`](sv2_tx_generator::TxGenerator), and starts the main loop.

use sv2_tx_generator::TxGenerator;
use tracing_subscriber::filter::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    let config = sv2_tx_generator::Config::from_file(&config_path)?;
    let mut generator = TxGenerator::new(config)?;
    generator.run().await
}

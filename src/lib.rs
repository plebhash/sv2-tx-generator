//! # sv2-tx-generator
//!
//! A Rust crate that periodically sends Bitcoin transactions to a node using BDK wallet.
//!
//! ## Binary usage
//!
//! Create a `config.toml` and run:
//!
//! ```sh
//! cargo run -- config.toml
//! ```
//!
//! ## Library usage
//!
//! ```rust,no_run
//! use sv2_tx_generator::{Config, Mode, NetworkConfig, TxGenerator};
//!
//! # fn main() -> anyhow::Result<()> {
//! let config = Config {
//!     interval_secs: 30,
//!     mode: Mode::Unit,
//!     batch_size: None,
//!     seed_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
//!     sender_account_index: 0,
//!     receiver_account_index: 1,
//!     change_account_index: None,
//!     amount_sat: 1000,
//!     fee_rate_sat_per_vb: 5,
//!     network: NetworkConfig::Regtest,
//!     rpc_address: "127.0.0.1".into(),
//!     rpc_port: 18443,
//!     rpc_username: "user".into(),
//!     rpc_password: "pass".into(),
//! };
//!
//! let mut _generator = TxGenerator::new(config)?;
//! // generator.run().await?;  // starts the infinite loop
//! # Ok(())
//! # }
//! ```

pub mod config;
pub mod generator;

pub use config::{Config, Mode, NetworkConfig};
pub use generator::TxGenerator;

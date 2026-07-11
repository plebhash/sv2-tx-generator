//! Configuration types for sv2-tx-generator.
//!
//! Supports deserialization from a `config.toml` file or programmatic construction
//! for library usage.

use serde::{Deserialize, Serialize};

/// Top-level configuration for the transaction generator.
///
/// All fields are required unless marked with `#[serde(default)]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Interval between transaction batches, in seconds.
    pub interval_secs: u64,

    /// Transaction generation mode: [`Mode::Unit`] (one tx per tick)
    /// or [`Mode::Batch`] (batch of txs per tick).
    pub mode: Mode,

    /// Number of transactions per batch. Required when mode is `"batch"`,
    /// ignored when mode is `"unit"`.
    #[serde(default)]
    pub batch_size: Option<u32>,

    /// BIP39 mnemonic seed phrase. Sender and receiver addresses are derived
    /// from this single master key.
    pub seed_phrase: String,

    /// BIP84 account index for the sending wallet.
    /// Derives the sender external address at `m/84'/{coin_type}'/{idx}'/0/0`.
    pub sender_account_index: u32,

    /// BIP84 account index for the receiving address.
    /// Derives the receiver address at `m/84'/{coin_type}'/{idx}'/0/0`.
    pub receiver_account_index: u32,

    /// BIP84 account index for the fixed change address.
    ///
    /// All change outputs are sent to `m/84'/{coin_type}'/{idx}'/0/0`
    /// derived from this account. When omitted, defaults to the sender
    /// account index (`sender_account_index`), so change returns to the
    /// sender's own address.
    #[serde(default)]
    pub change_account_index: Option<u32>,

    /// Amount to send per transaction, in satoshis.
    pub amount_sat: u64,

    /// Fee rate for each transaction, in satoshis per virtual byte.
    pub fee_rate_sat_per_vb: u64,

    /// Bitcoin network to use.
    pub network: NetworkConfig,

    /// Bitcoin Core RPC hostname or IP address.
    pub rpc_address: String,

    /// Bitcoin Core RPC port (e.g. 8332 mainnet, 18332 testnet, 18443 regtest).
    pub rpc_port: u16,

    /// Bitcoin Core RPC username.
    pub rpc_username: String,

    /// Bitcoin Core RPC password.
    pub rpc_password: String,
}

/// Transaction generation mode.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// One transaction per interval tick.
    Unit,
    /// A batch of `batch_size` transactions per interval tick.
    Batch,
}

/// Supported Bitcoin networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkConfig {
    /// Mainnet (BIP44 coin type 0).
    Bitcoin,
    /// Testnet3 (BIP44 coin type 1).
    Testnet,
    /// Regtest (BIP44 coin type 1).
    Regtest,
    /// Signet (BIP44 coin type 1).
    Signet,
}

impl Config {
    /// Load and validate configuration from a TOML file.
    ///
    /// Validates that `batch_size` is set when mode is `"batch"`,
    /// and that numeric fields are non-zero.
    pub fn from_file(path: &str) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        config.validate()?;
        Ok(config)
    }

    /// Validate the configuration.
    ///
    /// Ensures:
    /// - `batch_size` is present when mode is `Batch`
    /// - `interval_secs`, `amount_sat`, and `fee_rate_sat_per_vb` are non-zero
    pub fn validate(&self) -> anyhow::Result<()> {
        if matches!(self.mode, Mode::Batch) {
            match self.batch_size {
                None => anyhow::bail!("batch_size is required when mode is 'batch'"),
                Some(0) => anyhow::bail!("batch_size must be greater than 0"),
                Some(_) => {}
            }
        }
        if self.interval_secs == 0 {
            anyhow::bail!("interval_secs must be greater than 0");
        }
        if self.amount_sat == 0 {
            anyhow::bail!("amount_sat must be greater than 0");
        }
        if self.fee_rate_sat_per_vb == 0 {
            anyhow::bail!("fee_rate_sat_per_vb must be greater than 0");
        }
        Ok(())
    }

    /// Returns the number of transactions to create per interval tick.
    ///
    /// Always `1` for [`Mode::Unit`]; uses `batch_size` for [`Mode::Batch`].
    pub fn batch_count(&self) -> u32 {
        match self.mode {
            Mode::Unit => 1,
            Mode::Batch => self.batch_size.unwrap_or(1),
        }
    }

    /// BIP44 coin type for the configured network.
    ///
    /// Returns `0` for Bitcoin mainnet, `1` for testnet/regtest/signet.
    pub fn coin_type(&self) -> u32 {
        match self.network {
            NetworkConfig::Bitcoin => 0,
            _ => 1,
        }
    }

    /// Returns the effective change account index.
    ///
    /// When `change_account_index` is set it is used directly; otherwise
    /// falls back to `sender_account_index`.
    pub fn effective_change_account_index(&self) -> u32 {
        self.change_account_index
            .unwrap_or(self.sender_account_index)
    }

    /// Convert [`NetworkConfig`] to [`bdk_wallet::bitcoin::Network`].
    pub fn btc_network(&self) -> bdk_wallet::bitcoin::Network {
        match self.network {
            NetworkConfig::Bitcoin => bdk_wallet::bitcoin::Network::Bitcoin,
            NetworkConfig::Testnet => bdk_wallet::bitcoin::Network::Testnet,
            NetworkConfig::Regtest => bdk_wallet::bitcoin::Network::Regtest,
            NetworkConfig::Signet => bdk_wallet::bitcoin::Network::Signet,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config() -> Config {
        Config {
            interval_secs: 30,
            mode: Mode::Unit,
            batch_size: None,
            seed_phrase: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".into(),
            sender_account_index: 0,
            receiver_account_index: 1,
            change_account_index: None,
            amount_sat: 1000,
            fee_rate_sat_per_vb: 5,
            network: NetworkConfig::Regtest,
            rpc_address: "127.0.0.1".into(),
            rpc_port: 18443,
            rpc_username: "user".into(),
            rpc_password: "pass".into(),
        }
    }

    #[test]
    fn unit_mode_always_has_batch_count_one() {
        let cfg = base_config();
        assert_eq!(cfg.batch_count(), 1);
    }

    #[test]
    fn unit_mode_ignores_batch_size() {
        let mut cfg = base_config();
        cfg.mode = Mode::Unit;
        cfg.batch_size = Some(10);
        assert_eq!(cfg.batch_count(), 1);
    }

    #[test]
    fn batch_mode_uses_configured_batch_size() {
        let mut cfg = base_config();
        cfg.mode = Mode::Batch;
        cfg.batch_size = Some(5);
        assert_eq!(cfg.batch_count(), 5);
    }

    #[test]
    fn batch_mode_without_size_is_rejected() {
        let mut cfg = base_config();
        cfg.mode = Mode::Batch;
        cfg.batch_size = None;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_interval_is_rejected() {
        let mut cfg = base_config();
        cfg.interval_secs = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_amount_is_rejected() {
        let mut cfg = base_config();
        cfg.amount_sat = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn zero_fee_rate_is_rejected() {
        let mut cfg = base_config();
        cfg.fee_rate_sat_per_vb = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn unit_mode_validates_successfully() {
        let cfg = base_config();
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn missing_change_account_defaults_to_sender() {
        let cfg = base_config();
        assert_eq!(
            cfg.effective_change_account_index(),
            cfg.sender_account_index
        );
    }

    #[test]
    fn explicit_change_account_is_used() {
        let mut cfg = base_config();
        cfg.change_account_index = Some(7);
        assert_eq!(cfg.effective_change_account_index(), 7);
    }

    #[test]
    fn coin_type_zero_for_mainnet_only() {
        let mut cfg = base_config();
        cfg.network = NetworkConfig::Bitcoin;
        assert_eq!(cfg.coin_type(), 0);
        for net in [
            NetworkConfig::Testnet,
            NetworkConfig::Regtest,
            NetworkConfig::Signet,
        ] {
            let mut c = base_config();
            c.network = net;
            assert_eq!(c.coin_type(), 1, "coin_type should be 1 for {:?}", net);
        }
    }

    #[test]
    fn batch_size_zero_is_rejected() {
        let mut cfg = base_config();
        cfg.mode = Mode::Batch;
        cfg.batch_size = Some(0);
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn batch_size_one_is_valid() {
        let mut cfg = base_config();
        cfg.mode = Mode::Batch;
        cfg.batch_size = Some(1);
        assert!(cfg.validate().is_ok());
    }
}

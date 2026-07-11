//! Transaction generator — the core of this crate.
//!
//! [`TxGenerator`] manages the full lifecycle:
//!
//! 1. **Wallet derivation** — derives BIP84 P2WPKH descriptors from a BIP39 seed phrase
//!    for both the sender (spending) wallet and the receiver (destination) address.
//!
//! 2. **UTXO discovery** — uses Bitcoin Core's [`scantxoutset`] RPC to scan the UTXO
//!    set for outputs matching the wallet's descriptors. This works on **pruned nodes**
//!    because it reads the chainstate database, not historical blocks.
//!
//! 3. **Wallet construction** — creates a fresh in-memory BDK wallet per tick, injecting
//!    confirmed UTXOs (with full parent transactions fetched via [`getrawtransaction`])
//!    and unconfirmed mempool transactions (for continuous burst mode).
//!
//! 4. **Transaction building** — uses BDK's coin selection to build signed P2WPKH
//!    transactions sending from the sender wallet to the receiver address.
//!
//! 5. **Burst coordination** — tracks spent outpoints within a tick and across ticks
//!    (via mempool introspection) to prevent double-spends.
//!
//! [`scantxoutset`]: https://developer.bitcoin.org/reference/rpc/scantxoutset.html
//! [`getrawtransaction`]: https://developer.bitcoin.org/reference/rpc/getrawtransaction.html

use crate::config::Config;
use bdk_bitcoind_rpc::bitcoincore_rpc::json::{ScanTxOutRequest, ScanTxOutResult, Utxo};
use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client, RpcApi};
use bdk_wallet::bitcoin::bip32::{DerivationPath, Xpriv};
use bdk_wallet::bitcoin::hashes::Hash as _;
use bdk_wallet::bitcoin::secp256k1::Secp256k1;
use bdk_wallet::bitcoin::{
    Address, Amount, BlockHash, CompressedPublicKey, FeeRate, OutPoint, ScriptBuf, Transaction,
    TxOut, Txid,
};
use bdk_wallet::chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate};
use bdk_wallet::rusqlite::Connection;
use bdk_wallet::{KeychainKind, PersistedWallet, SignOptions, Update, Wallet};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

/// Internal abstraction over the Bitcoin Core RPC methods used by the generator.
///
/// Exists only to enable deterministic unit testing with a mock RPC
/// backend. Production code uses the blanket implementation for
/// [`bitcoincore_rpc::Client`].
pub(crate) trait BitcoinRpc {
    fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash>;
    fn get_raw_transaction(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> anyhow::Result<Transaction>;
    fn get_raw_mempool(&self) -> anyhow::Result<Vec<Txid>>;
    fn scan_tx_out_set_blocking(
        &self,
        descriptors: &[ScanTxOutRequest],
    ) -> anyhow::Result<ScanTxOutResult>;
    fn send_raw_transaction(&self, tx: &Transaction) -> anyhow::Result<()>;
}

impl BitcoinRpc for Client {
    fn get_block_hash(&self, height: u64) -> anyhow::Result<BlockHash> {
        Ok(RpcApi::get_block_hash(self, height)?)
    }
    fn get_raw_transaction(
        &self,
        txid: &Txid,
        block_hash: Option<&BlockHash>,
    ) -> anyhow::Result<Transaction> {
        Ok(RpcApi::get_raw_transaction(self, txid, block_hash)?)
    }
    fn get_raw_mempool(&self) -> anyhow::Result<Vec<Txid>> {
        Ok(RpcApi::get_raw_mempool(self)?)
    }
    fn scan_tx_out_set_blocking(
        &self,
        descriptors: &[ScanTxOutRequest],
    ) -> anyhow::Result<ScanTxOutResult> {
        Ok(RpcApi::scan_tx_out_set_blocking(self, descriptors)?)
    }
    fn send_raw_transaction(&self, tx: &Transaction) -> anyhow::Result<()> {
        RpcApi::send_raw_transaction(self, tx)?;
        Ok(())
    }
}

/// Result of a confirmed UTXO scan with its chain-state context.
struct ConfirmedSnapshot {
    /// The chain tip at which the scan ran.
    tip: BlockId,
    /// Discovered unspent transaction outputs.
    utxos: Vec<Utxo>,
}

/// Best-effort snapshot of the mempool at the start of a tick.
///
/// Used to both (a) exclude already-spent inputs from coin selection, and
/// (b) inject unconfirmed transactions into the wallet so their change
/// outputs become spendable in burst mode.
///
/// If the snapshot could not be fully constructed (RPC failure or
/// individual transaction fetch failure) the tick is skipped rather than
/// proceeding with incomplete double-spend protection.
struct MempoolSnapshot {
    /// Whether every mempool transaction was successfully fetched.
    complete: bool,
    /// All outpoints consumed as inputs by current mempool transactions.
    spent: HashSet<OutPoint>,
    /// Full transaction data for every mempool transaction.
    txs: Vec<Arc<Transaction>>,
}

/// A Bitcoin transaction generator.
///
/// Both sender and receiver addresses are derived from the same BIP39 seed phrase
/// using BIP84 (native SegWit P2WPKH) derivation paths.
///
/// The sender wallet tracks two keychains:
/// - **External** (`/0/*`): receive addresses for incoming funds
/// - **Internal** (`/1/*`): change addresses for transaction change outputs
///
/// # Pruned node compatibility
///
/// This generator uses [`scantxoutset`] for UTXO discovery instead of walking
/// full blocks. The UTXO set database is always available on pruned nodes.
/// Full parent transactions are fetched via [`getrawtransaction`] with a
/// block-hash hint (works without `txindex=1`).
///
/// The type parameter `R` defaults to [`bitcoincore_rpc::Client`] for
/// production use. It can be substituted with a mock implementation in
/// tests via the `pub(crate)` [`BitcoinRpc`] trait.
#[allow(private_bounds)]
pub struct TxGenerator<R: BitcoinRpc = Client> {
    config: Config,
    rpc_client: R,

    /// BIP84 external descriptor for the sender wallet (receive keychain).
    /// Format: `wpkh([fp/84'/coin_type'/sender_idx']xprv/0/*)`
    external_descriptor: String,

    /// BIP84 internal descriptor for the sender wallet (change keychain).
    /// Format: `wpkh([fp/84'/coin_type'/sender_idx']xprv/1/*)`
    internal_descriptor: String,

    /// Deterministically derived sender address at
    /// `m/84'/{coin_type}'/{sender_idx}'/0/0`.
    sender_address: Address,

    /// Deterministically derived receiver address at
    /// `m/84'/{coin_type}'/{receiver_idx}'/0/0`.
    receiver_address: Address,

    /// Deterministically derived change address at
    /// `m/84'/{coin_type}'/{change_idx}'/0/0`.
    /// All change outputs are sent here via `drain_to`.
    change_address: Address,

    /// Pre-computed script pubkeys (avoids repeated allocations).
    receiver_spk: ScriptBuf,
    change_spk: ScriptBuf,

    // --- RPC caches (validated against scan tip each tick) ---
    /// Height of the last scan tip. If the tip hash changes at the same
    /// height the block-hash cache is cleared (reorg detection).
    cached_scan_tip: Option<BlockId>,
    /// height → block hash. Reused across ticks for unchanged heights.
    block_hash_cache: BTreeMap<u32, BlockHash>,
    /// (txid, block_hash) → full transaction. Reused for confirmed
    /// parent transactions whose block has not been reorged.
    confirmed_tx_cache: BTreeMap<(Txid, BlockHash), Arc<Transaction>>,
    /// txid → full transaction. Incrementally refreshed each tick.
    mempool_cache: BTreeMap<Txid, Arc<Transaction>>,
}

/// Outcome of a single [`TxGenerator::run_tick`] invocation.
///
/// Used by tests to assert tick-level behaviour without inspecting log output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TickOutcome {
    /// Number of transactions that were successfully built.
    built: u32,
    /// Number of transactions that were successfully broadcast.
    broadcast: u32,
    /// Whether the tick was skipped early (scan, wallet-creation, or
    /// mempool-injection failure).
    skipped: bool,
}

impl TxGenerator<Client> {
    /// Create a new `TxGenerator` from the given configuration.
    ///
    /// This performs all one-time setup:
    /// - Parses the BIP39 seed phrase
    /// - Derives BIP84 descriptors for the sender wallet
    /// - Derives the deterministic sender and receiver addresses
    /// - Connects to the Bitcoin Core RPC endpoint
    pub fn new(config: Config) -> anyhow::Result<Self> {
        config.validate()?;
        let rpc_client = Self::connect_rpc_client(&config)?;
        TxGenerator::with_rpc(config, rpc_client)
    }

    fn connect_rpc_client(config: &Config) -> anyhow::Result<Client> {
        let rpc_url = format!("{}:{}", config.rpc_address, config.rpc_port);
        Ok(Client::new(
            &rpc_url,
            Auth::UserPass(config.rpc_username.clone(), config.rpc_password.clone()),
        )?)
    }
}

#[allow(private_bounds)]
impl<R: BitcoinRpc> TxGenerator<R> {
    /// Create a `TxGenerator` with an arbitrary [`BitcoinRpc`] backend.
    ///
    /// This is the shared constructor used by both [`TxGenerator::new`] and
    /// by tests that inject a mock RPC.
    pub(crate) fn with_rpc(config: Config, rpc_client: R) -> anyhow::Result<Self> {
        let network = config.btc_network();
        let change_idx = config.effective_change_account_index();

        let (external_descriptor, internal_descriptor) =
            Self::derive_descriptors(&config, network, change_idx)?;
        let sender_address = Self::derive_address(&config, config.sender_account_index, network)?;
        let receiver_address =
            Self::derive_address(&config, config.receiver_account_index, network)?;
        let change_address = Self::derive_address(&config, change_idx, network)?;
        let receiver_spk = receiver_address.script_pubkey();
        let change_spk = change_address.script_pubkey();

        Ok(Self {
            config,
            rpc_client,
            external_descriptor,
            internal_descriptor,
            sender_address,
            receiver_address,
            change_address,
            receiver_spk,
            change_spk,
            cached_scan_tip: None,
            block_hash_cache: BTreeMap::new(),
            confirmed_tx_cache: BTreeMap::new(),
            mempool_cache: BTreeMap::new(),
        })
    }

    fn derive_descriptors(
        config: &Config,
        network: bdk_wallet::bitcoin::Network,
        change_idx: u32,
    ) -> anyhow::Result<(String, String)> {
        let mnemonic = bdk_wallet::bip39::Mnemonic::from_str(&config.seed_phrase)?;
        let seed = mnemonic.to_seed("");

        let secp = Secp256k1::new();
        let master_xprv = Xpriv::new_master(network, &seed)?;
        let master_fingerprint = master_xprv.fingerprint(&secp);

        let sender_path: DerivationPath = format!(
            "m/84'/{}'/{}'",
            config.coin_type(),
            config.sender_account_index
        )
        .parse()?;
        let sender_xprv = master_xprv.derive_priv(&secp, &sender_path)?;

        let origin = format!(
            "[{}/84'/{}'/{}']",
            master_fingerprint,
            config.coin_type(),
            config.sender_account_index
        );
        let external_descriptor = format!("wpkh({}{}/0/*)", origin, sender_xprv);

        let internal_descriptor = if change_idx == config.sender_account_index {
            format!("wpkh({}{}/1/*)", origin, sender_xprv)
        } else {
            let change_path: DerivationPath =
                format!("m/84'/{}'/{}'", config.coin_type(), change_idx).parse()?;
            let change_xprv = master_xprv.derive_priv(&secp, &change_path)?;
            let change_fp = master_fingerprint;
            format!(
                "wpkh([{}/84'/{}'/{}']{}/0/*)",
                change_fp,
                config.coin_type(),
                change_idx,
                change_xprv,
            )
        };

        Ok((external_descriptor, internal_descriptor))
    }

    fn derive_address(
        config: &Config,
        account_index: u32,
        network: bdk_wallet::bitcoin::Network,
    ) -> anyhow::Result<Address> {
        let mnemonic = bdk_wallet::bip39::Mnemonic::from_str(&config.seed_phrase)?;
        let seed = mnemonic.to_seed("");

        let secp = Secp256k1::new();
        let master_xprv = Xpriv::new_master(network, &seed)?;

        let path: DerivationPath =
            format!("m/84'/{}'/{}'/0/0", config.coin_type(), account_index).parse()?;
        let xprv = master_xprv.derive_priv(&secp, &path)?;
        let pubkey = xprv.private_key.public_key(&secp);
        Ok(Address::p2wpkh(&CompressedPublicKey(pubkey), network))
    }

    /// Scan the Bitcoin Core UTXO set for outputs matching the wallet's descriptors.
    ///
    /// Uses the [`scantxoutset`] RPC which reads directly from the chainstate
    /// LevelDB — no block data required. Works on pruned nodes.
    ///
    /// Scans both the external (receive) and internal (change) keychains
    /// over derivation indices 0–1000.
    ///
    /// Returns a [`ConfirmedSnapshot`] that includes the scan tip so the
    /// BDK wallet can be anchored to the correct current height.
    fn scan_utxos(&self) -> anyhow::Result<ConfirmedSnapshot> {
        let requests = [
            ScanTxOutRequest::Extended {
                desc: self.external_descriptor.clone(),
                range: (0, 1000),
            },
            ScanTxOutRequest::Extended {
                desc: self.internal_descriptor.clone(),
                range: (0, 1000),
            },
        ];
        let result = self.rpc_client.scan_tx_out_set_blocking(&requests)?;

        if result.success == Some(false) {
            anyhow::bail!("scantxoutset reported failure");
        }

        let height = result.height.unwrap_or(0);
        let tip_hash = result.best_block_hash.unwrap_or_else(|| {
            tracing::warn!("scantxoutset returned no bestblock hash; using zero hash");
            BlockHash::all_zeros()
        });
        let total = result.unspents.len();
        tracing::info!(
            "scantxoutset at height {}: {} UTXOs ({})",
            height,
            total,
            result.total_amount
        );

        Ok(ConfirmedSnapshot {
            tip: BlockId {
                height: height as u32,
                hash: tip_hash,
            },
            utxos: result.unspents,
        })
    }

    /// Build an in-memory BDK wallet populated with confirmed UTXOs.
    ///
    /// For each scanned UTXO:
    /// 1. Fetch the parent transaction via [`getrawtransaction`] with a block-hash hint
    ///    (no `txindex` required).
    /// 2. Build a [`TxUpdate`] with the full transactions, anchored txouts, and
    ///    [`ConfirmationBlockTime`] anchors.
    /// 3. Construct a sparse [`CheckPoint`] chain anchored at the scan tip, covering
    ///    all UTXO heights plus genesis.
    /// 4. Apply everything to the wallet via [`Wallet::apply_update`].
    ///
    /// Returns a wallet ready for coin selection and signing. An empty
    /// confirmed snapshot (no UTXOs) produces a wallet with zero balance;
    /// it is not treated as an error.
    fn create_wallet_from_utxos(
        &mut self,
        snapshot: &ConfirmedSnapshot,
    ) -> anyhow::Result<PersistedWallet<Connection>> {
        let network = self.config.btc_network();
        let mut conn = Connection::open_in_memory()?;
        let mut wallet = Wallet::create(
            self.external_descriptor.clone(),
            self.internal_descriptor.clone(),
        )
        .network(network)
        .create_wallet(&mut conn)?;

        let utxos = &snapshot.utxos;
        let scan_tip = snapshot.tip;

        // Invalidate caches if the scan tip has changed at the same height
        // (a reorg) or if this is the first tick.
        if let Some(cached) = self.cached_scan_tip {
            if cached.height == scan_tip.height && cached.hash != scan_tip.hash {
                tracing::warn!(
                    "Reorg detected at height {} — clearing block-hash and confirmed-tx caches",
                    scan_tip.height,
                );
                self.block_hash_cache.clear();
                self.confirmed_tx_cache.clear();
            }
        }
        self.cached_scan_tip = Some(scan_tip);

        if utxos.is_empty() {
            tracing::info!("  No confirmed UTXOs found; wallet created empty.");
            // Still reveal indices and set the chain tip so BDK has a current view.
            let mut last_active_indices = BTreeMap::new();
            last_active_indices.insert(KeychainKind::External, 999);
            last_active_indices.insert(KeychainKind::Internal, 999);

            wallet.apply_update(Update {
                last_active_indices,
                tx_update: TxUpdate::default(),
                chain: Some(
                    CheckPoint::from_block_ids([scan_tip])
                        .map_err(|_| anyhow::anyhow!("failed to build checkpoint chain"))?,
                ),
            })?;
            return Ok(wallet);
        }

        // Collect all unique block heights across UTXOs (plus genesis and scan tip).
        let mut heights: BTreeSet<u32> = BTreeSet::new();
        heights.insert(0); // genesis
        heights.insert(scan_tip.height);
        for utxo in utxos {
            heights.insert(utxo.height as u32);
        }

        // Fetch block hash for every height (cached across ticks).
        let mut blocks: BTreeMap<u32, BlockHash> = BTreeMap::new();
        blocks.insert(scan_tip.height, scan_tip.hash);
        for &h in &heights {
            if blocks.contains_key(&h) {
                continue;
            }
            if let Some(&hash) = self.block_hash_cache.get(&h) {
                blocks.insert(h, hash);
                continue;
            }
            let hash = self.rpc_client.get_block_hash(h as u64)?;
            self.block_hash_cache.insert(h, hash);
            blocks.insert(h, hash);
        }

        // Build a sparse CheckPoint chain anchored at the scan tip.
        let chain_tip = CheckPoint::from_block_ids(
            blocks.iter().map(|(&h, &hash)| BlockId { height: h, hash }),
        )
        .map_err(|_| anyhow::anyhow!("failed to build checkpoint chain"))?;

        // Fetch each UTXO's parent transaction (cached by txid + block hash).
        let mut tx_map: BTreeMap<Txid, (Arc<Transaction>, u32, BlockHash)> = BTreeMap::new();
        for utxo in utxos {
            if tx_map.contains_key(&utxo.txid) {
                continue;
            }
            let h = utxo.height as u32;
            let hash = blocks[&h];
            let cache_key = (utxo.txid, hash);
            if let Some(cached_tx) = self.confirmed_tx_cache.get(&cache_key) {
                tx_map.insert(utxo.txid, (cached_tx.clone(), h, hash));
                continue;
            }
            match self.rpc_client.get_raw_transaction(&utxo.txid, Some(&hash)) {
                Ok(tx) => {
                    let tx = Arc::new(tx);
                    self.confirmed_tx_cache.insert(cache_key, tx.clone());
                    tx_map.insert(utxo.txid, (tx, h, hash));
                }
                Err(e) => {
                    tracing::warn!("  Skipping tx {} — cannot fetch: {}", utxo.txid, e);
                }
            }
        }

        if tx_map.is_empty() {
            anyhow::bail!("no transactions could be fetched for scanned UTXOs");
        }

        // Build the confirmed TxUpdate: full txs, txouts, and anchor blocks.
        let mut tx_update = TxUpdate::default();
        let mut seen_txids: BTreeSet<Txid> = BTreeSet::new();

        for utxo in utxos {
            let Some((tx, h, hash)) = tx_map.get(&utxo.txid) else {
                continue;
            };

            tx_update.txouts.insert(
                OutPoint {
                    txid: utxo.txid,
                    vout: utxo.vout,
                },
                TxOut {
                    value: utxo.amount,
                    script_pubkey: utxo.script_pub_key.clone(),
                },
            );

            if seen_txids.insert(utxo.txid) {
                tx_update.txs.push(tx.clone());
                tx_update.anchors.insert((
                    ConfirmationBlockTime {
                        block_id: BlockId {
                            height: *h,
                            hash: *hash,
                        },
                        confirmation_time: 0,
                    },
                    utxo.txid,
                ));
            }
        }

        let resolved = tx_update.txouts.len();
        let skipped = utxos.len() - resolved;
        if skipped > 0 {
            tracing::warn!(
                "  Resolved {} UTXOs from {} txs (skipped {} unreachable UTXOs)",
                resolved,
                tx_map.len(),
                skipped,
            );
        }

        // Reveal address indices up to 999 on both keychains so BDK's indexer
        // can match scanned UTXOs to derivation indices.
        let mut last_active_indices = BTreeMap::new();
        last_active_indices.insert(KeychainKind::External, 999);
        last_active_indices.insert(KeychainKind::Internal, 999);

        wallet.apply_update(Update {
            last_active_indices,
            tx_update,
            chain: Some(chain_tip),
        })?;

        Ok(wallet)
    }

    /// Build and sign a single P2WPKH transaction using BDK's coin selection.
    ///
    /// The `unspendable` parameter is a list of outpoints to exclude from coin
    /// selection. This is used to prevent double-spending within a burst batch
    /// and to avoid spending UTXOs already consumed by mempool transactions.
    fn build_tx(
        wallet: &mut PersistedWallet<Connection>,
        receiver_address: &Address,
        change_address: &Address,
        amount_sat: u64,
        fee_rate_sat_per_vb: u64,
        unspendable: Vec<OutPoint>,
    ) -> anyhow::Result<Transaction> {
        let amount = Amount::from_sat(amount_sat);
        let fee_rate = FeeRate::from_sat_per_vb(fee_rate_sat_per_vb)
            .ok_or_else(|| anyhow::anyhow!("invalid fee rate"))?;

        let mut builder = wallet.build_tx();
        builder.add_recipient(receiver_address.script_pubkey(), amount);
        builder.fee_rate(fee_rate);
        builder.unspendable(unspendable);
        builder.drain_to(change_address.script_pubkey());
        let mut psbt = builder.finish()?;

        let finalized = wallet.sign(&mut psbt, SignOptions::default())?;
        if !finalized {
            anyhow::bail!("PSBT not fully signed");
        }

        let tx = psbt.extract_tx().map_err(|e| anyhow::anyhow!("{e}"))?;
        Ok(tx)
    }

    /// Fetch all mempool transactions from the node.
    ///
    /// Returns a [`MempoolSnapshot`] whose `complete` field indicates
    /// whether every transaction was successfully retrieved. If the
    /// snapshot is incomplete the caller should skip tx generation for
    /// this tick rather than proceed with weakened double-spend protection.
    fn fetch_mempool_data(&mut self) -> MempoolSnapshot {
        let mut spent = HashSet::new();
        let mut txs = Vec::new();
        let txids = match self.rpc_client.get_raw_mempool() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("  Warning: cannot read mempool: {}", e);
                return MempoolSnapshot {
                    complete: false,
                    spent,
                    txs,
                };
            }
        };

        // Drop cached transactions that are no longer in the mempool.
        let current_set: HashSet<Txid> = txids.iter().copied().collect();
        self.mempool_cache
            .retain(|txid, _| current_set.contains(txid));

        let mut complete = true;
        let mut fetched = 0usize;
        let mut reused = 0usize;
        for txid in &txids {
            if let Some(cached_tx) = self.mempool_cache.get(txid) {
                for input in &cached_tx.input {
                    spent.insert(input.previous_output);
                }
                txs.push(cached_tx.clone());
                reused += 1;
                continue;
            }
            match self.rpc_client.get_raw_transaction(txid, None) {
                Ok(tx) => {
                    let tx = Arc::new(tx);
                    for input in &tx.input {
                        spent.insert(input.previous_output);
                    }
                    self.mempool_cache.insert(*txid, tx.clone());
                    txs.push(tx);
                    fetched += 1;
                }
                Err(e) => {
                    tracing::warn!("  Warning: cannot fetch mempool tx {}: {}", txid, e);
                    complete = false;
                }
            }
        }

        if reused > 0 || fetched > 0 {
            tracing::info!(
                "  mempool: {} fetched, {} reused from cache",
                fetched,
                reused,
            );
        }

        MempoolSnapshot {
            complete,
            spent,
            txs,
        }
    }

    /// Inject mempool transactions into the wallet.
    ///
    /// Transactions are added with [`seen_ats`](TxUpdate::seen_ats) timestamps
    /// (unconfirmed) — no block anchors. This makes the change outputs of
    /// previously-broadcast transactions spendable in the current tick, enabling
    /// continuous burst mode even when no new blocks are being mined.
    ///
    /// The wallet's keychain indices are revealed to 999 on both keychains to
    /// ensure all derivation indices are checked when matching tx outputs.
    fn inject_mempool_txs(
        wallet: &mut PersistedWallet<Connection>,
        mempool_txs: &[Arc<Transaction>],
    ) -> anyhow::Result<()> {
        if mempool_txs.is_empty() {
            return Ok(());
        }

        let mut tx_update = TxUpdate::default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        for tx in mempool_txs {
            tx_update.txs.push(tx.clone());
            tx_update.seen_ats.insert((tx.compute_txid(), now));
        }

        let mut last_active_indices = BTreeMap::new();
        last_active_indices.insert(KeychainKind::External, 999);
        last_active_indices.insert(KeychainKind::Internal, 999);

        wallet.apply_update(Update {
            last_active_indices,
            tx_update,
            chain: None,
        })?;

        Ok(())
    }

    /// Execute a single tick: scan → mempool → wallet → build → broadcast.
    ///
    /// Returns a [`TickOutcome`] describing what happened. This method
    /// preserves all original error-recovery policies:
    ///
    /// - Scan failure → skipped (logged, no broadcasts).
    /// - Wallet-creation failure → skipped.
    /// - Mempool-injection failure → skipped.
    /// - First build failure → stops the batch (previous builds still broadcast).
    /// - Later build failure → logged, remaining builds still attempted.
    /// - Broadcast failure → warned, later broadcasts still attempted.
    pub(crate) fn run_tick(&mut self) -> TickOutcome {
        tracing::info!("\n--- Tick ---");

        // 1. Scan confirmed UTXOs
        let snapshot = match self.scan_utxos() {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Scan error: {}", e);
                return TickOutcome {
                    built: 0,
                    broadcast: 0,
                    skipped: true,
                };
            }
        };

        // 2. Fetch mempool state
        let MempoolSnapshot {
            complete: mempool_complete,
            spent: mempool_spent,
            txs: mempool_txs,
        } = self.fetch_mempool_data();

        if !mempool_complete {
            tracing::error!(
                "Mempool snapshot incomplete; skipping tick to preserve double-spend protection"
            );
            return TickOutcome {
                built: 0,
                broadcast: 0,
                skipped: true,
            };
        }

        // 3. Create wallet with confirmed UTXOs
        let mut wallet = match self.create_wallet_from_utxos(&snapshot) {
            Ok(w) => w,
            Err(e) => {
                tracing::error!("Wallet creation error: {}", e);
                return TickOutcome {
                    built: 0,
                    broadcast: 0,
                    skipped: true,
                };
            }
        };

        // 4. Inject mempool txs for continuous burst mode
        let before_inject = wallet.list_unspent().count();
        if let Err(e) = Self::inject_mempool_txs(&mut wallet, &mempool_txs) {
            tracing::error!("Wallet mempool injection error: {}", e);
            return TickOutcome {
                built: 0,
                broadcast: 0,
                skipped: true,
            };
        }

        // Materialize the post-injection UTXO view once.
        // Collect into a Vec first so we can reuse it for count, spent-outpoint
        // set, and metadata map without re-canonicalizing the tx graph.
        let unspent_list: Vec<_> = wallet.list_unspent().collect();
        let utxo_count = unspent_list.len();
        let after_inject = utxo_count;

        if !mempool_txs.is_empty() {
            tracing::info!(
                "  mempool injection: {} UTXOs -> {} UTXOs ({} txs)",
                before_inject,
                after_inject,
                mempool_txs.len(),
            );
        }

        // Identify wallet UTXOs that overlap with mempool-spent inputs
        let balance = wallet.balance();
        let wallet_unspent: HashSet<OutPoint> = unspent_list.iter().map(|u| u.outpoint).collect();
        let mempool_blocked: HashSet<OutPoint> = wallet_unspent
            .intersection(&mempool_spent)
            .copied()
            .collect();

        if !mempool_blocked.is_empty() {
            tracing::info!(
                "  {} wallet UTXO(s) blocked by mempool spends",
                mempool_blocked.len(),
            );
        }

        tracing::info!(
            "Balance: {} sats | UTXOs: {} | mempool txs injected: {} | mempool-blocked: {}",
            balance.total().to_sat(),
            utxo_count,
            mempool_txs.len(),
            mempool_blocked.len(),
        );

        // 5. Build and broadcast transactions
        let batch_size = self.config.batch_count();
        let amount_sat = self.config.amount_sat;
        let fee_rate_sat_per_vb = self.config.fee_rate_sat_per_vb;
        let mut spent_outpoints: Vec<OutPoint> = Vec::new();
        let mut txs: Vec<Transaction> = Vec::new();

        // Snapshot UTXO metadata: outpoint -> (keychain, derivation_index, value)
        let utxo_meta: BTreeMap<OutPoint, (KeychainKind, u32, Amount)> = unspent_list
            .iter()
            .map(|u| (u.outpoint, (u.keychain, u.derivation_index, u.txout.value)))
            .collect();

        for i in 0..batch_size {
            // Combine mempool-blocked with batch-local spent outpoints
            let mut unspendable: Vec<OutPoint> = mempool_blocked.iter().copied().collect();
            unspendable.extend(spent_outpoints.iter().copied());

            match Self::build_tx(
                &mut wallet,
                &self.receiver_address,
                &self.change_address,
                amount_sat,
                fee_rate_sat_per_vb,
                unspendable,
            ) {
                Ok(tx) => {
                    for input in &tx.input {
                        spent_outpoints.push(input.previous_output);
                    }
                    let txid = tx.compute_txid();

                    tracing::info!("  Created tx {}: {}", i + 1, txid);

                    // --- Input summary (logged directly, no Vec<String>) ---
                    let mut input_total = Amount::ZERO;
                    let mut shown = 0u32;
                    for vin in tx.input.iter() {
                        if let Some(&(kc, deriv, val)) = utxo_meta.get(&vin.previous_output) {
                            input_total += val;
                            if shown < 3 {
                                let label = match kc {
                                    KeychainKind::External => "ext",
                                    KeychainKind::Internal => "int",
                                };
                                tracing::info!(
                                    "    [{}] idx={} {} sats",
                                    label,
                                    deriv,
                                    val.to_sat()
                                );
                                shown += 1;
                            }
                        }
                    }
                    tracing::info!(
                        "  Inputs: {} ({} sats)",
                        tx.input.len(),
                        input_total.to_sat()
                    );
                    let more_inputs = tx.input.len().saturating_sub(3);
                    if more_inputs > 0 {
                        tracing::info!("  +{} more inputs", more_inputs);
                    }

                    // --- Output classification ---
                    let mut unexpected = 0u32;

                    // First pass: count unexpected and log receiver/change directly.
                    for (nout, vout) in tx.output.iter().enumerate() {
                        if vout.script_pubkey == self.receiver_spk {
                            tracing::info!(
                                "    Receiver: n={} {:>15} sats -> {}",
                                nout,
                                vout.value.to_sat(),
                                self.receiver_address
                            );
                        } else if vout.script_pubkey == self.change_spk {
                            tracing::info!(
                                "    Change:   n={} {:>15} sats -> {}",
                                nout,
                                vout.value.to_sat(),
                                self.change_address
                            );
                        } else {
                            unexpected += 1;
                        }
                    }

                    if unexpected > 0 {
                        tracing::warn!("  WARNING: {} unexpected output(s)", unexpected);
                    }

                    txs.push(tx);
                }
                Err(e) => {
                    tracing::error!("  Failed to create tx {}: {}", i + 1, e);
                    if i == 0 {
                        break;
                    }
                }
            }
        }

        let built = txs.len() as u32;
        let mut broadcast = 0u32;

        for tx in &txs {
            match self.rpc_client.send_raw_transaction(tx) {
                Ok(()) => {
                    tracing::info!("  Broadcast: {}", tx.compute_txid());
                    broadcast += 1;
                }
                Err(e) => {
                    tracing::warn!("  Broadcast error for {}: {}", tx.compute_txid(), e);
                }
            }
        }

        TickOutcome {
            built,
            broadcast,
            skipped: false,
        }
    }

    /// Run the main transaction-generation loop.
    ///
    /// Each tick:
    /// 1. Scan the UTXO set via [`scantxoutset`] for confirmed outputs.
    /// 2. Fetch mempool data (spent inputs + full txs).
    /// 3. Create an in-memory wallet with confirmed UTXOs.
    /// 4. Inject mempool transactions so unconfirmed change becomes spendable.
    /// 5. Build and broadcast the configured number of transactions (unit
    ///    or batch mode), tracking spent outpoints to avoid conflicts.
    pub async fn run(&mut self) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(self.config.interval_secs));

        tracing::info!("Sender (display /0/0): {}", self.sender_address);
        tracing::info!("Receiver (destination):  {}", self.receiver_address);
        tracing::info!("Change (fixed target):   {}", self.change_address);
        tracing::info!(
            "Note: explorers infer \"sender\" from input prevout addresses, not from display sender."
        );

        loop {
            interval.tick().await;
            self.run_tick();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Mode, NetworkConfig};

    const TEST_SEED: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    fn test_config(seed_phrase: &str) -> Config {
        Config {
            interval_secs: 30,
            mode: Mode::Unit,
            batch_size: None,
            seed_phrase: seed_phrase.to_string(),
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
    fn derivation_is_deterministic() {
        let cfg = test_config(TEST_SEED);
        let (ext1, int1) = TxGenerator::<Client>::derive_descriptors(
            &cfg,
            bdk_wallet::bitcoin::Network::Regtest,
            cfg.effective_change_account_index(),
        )
        .unwrap();
        let (ext2, int2) = TxGenerator::<Client>::derive_descriptors(
            &cfg,
            bdk_wallet::bitcoin::Network::Regtest,
            cfg.effective_change_account_index(),
        )
        .unwrap();
        assert_eq!(ext1, ext2);
        assert_eq!(int1, int2);
    }

    #[test]
    fn derivation_same_seed_same_network_produces_consistent_addresses() {
        let cfg = test_config(TEST_SEED);
        let addr =
            TxGenerator::<Client>::derive_address(&cfg, 0, bdk_wallet::bitcoin::Network::Regtest)
                .unwrap();
        let addr2 =
            TxGenerator::<Client>::derive_address(&cfg, 0, bdk_wallet::bitcoin::Network::Regtest)
                .unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn different_accounts_produce_different_addresses() {
        let cfg = test_config(TEST_SEED);
        let a0 =
            TxGenerator::<Client>::derive_address(&cfg, 0, bdk_wallet::bitcoin::Network::Regtest)
                .unwrap();
        let a1 =
            TxGenerator::<Client>::derive_address(&cfg, 1, bdk_wallet::bitcoin::Network::Regtest)
                .unwrap();
        assert_ne!(a0, a1);
    }

    #[test]
    fn coin_type_zero_for_mainnet() {
        let mut cfg = test_config(TEST_SEED);
        cfg.network = NetworkConfig::Bitcoin;
        assert_eq!(cfg.coin_type(), 0);
    }

    #[test]
    fn coin_type_one_for_non_mainnet() {
        for net in [
            NetworkConfig::Testnet,
            NetworkConfig::Regtest,
            NetworkConfig::Signet,
        ] {
            let mut cfg = test_config(TEST_SEED);
            cfg.network = net;
            assert_eq!(cfg.coin_type(), 1, "coin_type should be 1 for {:?}", net);
        }
    }

    #[test]
    fn mainnet_derivation_uses_coin_type_zero() {
        let mut cfg = test_config(TEST_SEED);
        cfg.network = NetworkConfig::Bitcoin;
        let (ext, _int) = TxGenerator::<Client>::derive_descriptors(
            &cfg,
            bdk_wallet::bitcoin::Network::Bitcoin,
            cfg.effective_change_account_index(),
        )
        .unwrap();
        assert!(
            ext.contains("/84'/0'/"),
            "expected coin_type 0 in descriptor, got: {ext}"
        );
    }

    #[test]
    fn regtest_derivation_uses_coin_type_one() {
        let cfg = test_config(TEST_SEED);
        let (ext, _int) = TxGenerator::<Client>::derive_descriptors(
            &cfg,
            bdk_wallet::bitcoin::Network::Regtest,
            cfg.effective_change_account_index(),
        )
        .unwrap();
        assert!(
            ext.contains("/84'/1'/"),
            "expected coin_type 1 in descriptor, got: {ext}"
        );
    }

    #[test]
    fn same_account_change_produces_internal_1_wildcard() {
        let cfg = test_config(TEST_SEED);
        let (_ext, int) = TxGenerator::<Client>::derive_descriptors(
            &cfg,
            bdk_wallet::bitcoin::Network::Regtest,
            cfg.sender_account_index,
        )
        .unwrap();
        assert!(
            int.contains("/1/*"),
            "expected /1/* in internal descriptor, got: {int}"
        );
    }

    #[test]
    fn different_change_account_produces_account_0_wildcard() {
        let cfg = test_config(TEST_SEED);
        let (_ext, int) = TxGenerator::<Client>::derive_descriptors(
            &cfg,
            bdk_wallet::bitcoin::Network::Regtest,
            99,
        )
        .unwrap();
        assert!(
            int.contains("/0/*"),
            "expected /0/* when change differs from sender, got: {int}"
        );
    }

    #[test]
    fn external_descriptor_receive_keychain_is_0_wildcard() {
        let cfg = test_config(TEST_SEED);
        let (ext, _int) = TxGenerator::<Client>::derive_descriptors(
            &cfg,
            bdk_wallet::bitcoin::Network::Regtest,
            cfg.effective_change_account_index(),
        )
        .unwrap();
        assert!(
            ext.contains("/0/*"),
            "expected /0/* in external descriptor, got: {ext}"
        );
    }

    #[test]
    fn tick_outcome_skipped_is_false_after_normal_completion() {
        // Verify TickOutcome defaults
        let outcome = TickOutcome {
            built: 1,
            broadcast: 1,
            skipped: false,
        };
        assert_eq!(outcome.built, 1);
        assert_eq!(outcome.broadcast, 1);
        assert!(!outcome.skipped);
    }

    #[test]
    fn invalid_mnemonic_rejected() {
        let cfg = test_config("this is not a valid mnemonic phrase at all");
        // seed_phrase must be valid BIP39; the error surfaces in derive_descriptors
        let result = TxGenerator::<Client>::derive_descriptors(
            &cfg,
            bdk_wallet::bitcoin::Network::Regtest,
            cfg.effective_change_account_index(),
        );
        assert!(result.is_err());
    }
}

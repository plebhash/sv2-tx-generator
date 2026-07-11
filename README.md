# sv2-tx-generator

A Rust crate that periodically sends Bitcoin transactions to a node using [`bdk_wallet`](https://crates.io/crates/bdk_wallet).

Both the sender wallet and receiver address are derived from a **single BIP39 seed phrase** using BIP84 (native SegWit P2WPKH).

This is meant to help development on [Stratum V2 Reference Implementation](https://github.com/stratum-mining).

## Features

- **Two modes**: unit (1 tx per interval) and batch (N txs per interval)
- **Pruned-node compatible**: uses `scantxoutset` RPC instead of block-by-block sync
- **Continuous batch**: change outputs from unconfirmed txs are reused across ticks
- **Double-spend protection**: tracks spent outpoints within batches and across mempool
- **Dual interface**: runs as a standalone binary (`config.toml`) or as a Rust library

## Requirements

- Rust 1.85+
- Bitcoin Core node with RPC enabled (pruned or archival)
- The node must have `-rpcuser` / `-rpcpassword` (or cookie auth)

## Quick start (binary)

1. Create `config.toml` (see [config.toml](config.toml) for an example):

```toml
interval_secs = 30
mode = "batch"
batch_size = 10
seed_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
sender_account_index = 0
receiver_account_index = 1
# change_account_index = 0   # optional — defaults to sender_account_index when omitted
amount_sat = 1000
fee_rate_sat_per_vb = 5
network = "regtest"
rpc_address = "127.0.0.1"
rpc_port = 18443
rpc_username = "user"
rpc_password = "password"
```

2. Run:

```sh
cargo run -- config.toml
```

## Quick start (library)

```rust
use sv2_tx_generator::{Config, Mode, NetworkConfig, TxGenerator};

let config = Config {
    interval_secs: 30,
    mode: Mode::Batch,
    batch_size: Some(10),
    seed_phrase: "abandon abandon ...".into(),
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
};

let mut generator = TxGenerator::new(config)?;
generator.run().await?;
```

## Architecture

```
┌──────────────┐     ┌───────────────┐     ┌───────────────┐
│  config.toml │────▶│  TxGenerator  │────▶│  Bitcoin Core │
│   (binary)   │     │  ::new()      │     │     RPC       │
└──────────────┘     └──────┬────────┘     └───────┬───────┘
                            │                      │
                     ┌──────▼───────┐      ┌───────▼───────┐
                     │   run() loop │      │ scantxoutset  │
                     │              │      │ getrawtx      │
                     │  per tick:   │      │ getblockhash  │
                     │  1. scan     │      │ getrawmempool │
                     │  2. wallet   │      │ sendrawtx     │
                     │  3. mempool  │      └───────────────┘
                     │  4. build    │
                     │  5. broadcast│
                     └──────────────┘
```

### Per-tick flow

1. **`scantxoutset`** — scans the UTXO set for outputs matching wallet descriptors (works on pruned nodes)
2. **`fetch_mempool_data`** — reads all mempool txs to build spent-outpoint exclusion set
3. **`create_wallet_from_utxos`** — creates a fresh in-memory BDK wallet, fetches full parent txs, applies them with block anchors
4. **`inject_mempool_txs`** — adds unconfirmed mempool txs to the wallet so change outputs become spendable
5. **`build_tx`** — BDK coin selection + PSBT signing (P2WPKH)
6. **`sendrawtransaction`** — broadcasts all txs in the batch

### Key design decisions

| Decision | Rationale |
|---|---|
| Fresh wallet per tick | Avoids stale UTXO accumulation; each scan is the source of truth |
| `scantxoutset` for discovery | Works on pruned nodes — reads chainstate, not blocks |
| Full parent tx fetch | BDK requires full txs for canonicalization and spending |
| Mempool tx injection | Enables continuous batch mode across ticks without block confirmation |
| `unspendable` outpoints | Prevents double-spends within a batch and against mempool txs |
| In-memory SQLite | No disk files; wallet state is ephemeral |

> **Explorer note:** block explorers infer a "sender" from input prevout addresses.
> That address may differ from the displayed `Sender (display /0/0)` printed on startup,
> because the generator uses coin selection from all wallet UTXOs — not only `/0/0`.

## Configuration reference

| Field | Type | Description |
|---|---|---|
| `interval_secs` | u64 | Seconds between transaction batches |
| `mode` | string | `"unit"` or `"batch"` |
| `batch_size` | u32 | Txs per tick (only for batch mode) |
| `seed_phrase` | string | BIP39 mnemonic (12/24 words) |
| `sender_account_index` | u32 | BIP84 account for sending wallet |
| `receiver_account_index` | u32 | BIP84 account for receiving address |
| `change_account_index` | u32 | (Optional) BIP84 account for fixed change address; defaults to sender |
| `amount_sat` | u64 | Amount per tx in satoshis |
| `fee_rate_sat_per_vb` | u64 | Fee rate in sats/vbyte |
| `network` | string | `"bitcoin"`, `"testnet"`, `"regtest"`, or `"signet"` |
| `rpc_address` | string | Bitcoin Core RPC host |
| `rpc_port` | u16 | Bitcoin Core RPC port |
| `rpc_username` | string | RPC auth username |
| `rpc_password` | string | RPC auth password |

## Derivation paths

Both sender and receiver use BIP84 (native SegWit, `wpkh` descriptors):

```
Sender wallet descriptors:
  External:  m/84'/{coin_type}'/{sender_idx}'/0/*

Receiver address:
  m/84'/{coin_type}'/{receiver_idx}'/0/0

Displayed sender address:
  m/84'/{coin_type}'/{sender_idx}'/0/0

Change address (drain_to target):
  m/84'/{coin_type}'/{change_idx}'/0/0

Wallet internal descriptor:
  When change_idx == sender_idx:
    Internal:  m/84'/{coin_type}'/{sender_idx}'/1/*
  When change_idx != sender_idx:
    Internal:  m/84'/{coin_type}'/{change_idx}'/0/*
```

Coin types:
- Mainnet: `0'`
- Testnet / Regtest / Signet: `1'`

## License

MIT OR Apache-2.0
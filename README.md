# sliprun

**Bitcoin transaction builder with Ordinal inscriptions, powered by the [Marathon Slipstream API](https://slipstream.mara.com).**

Submit raw Bitcoin transactions — including Ordinals commit/reveal pairs and OP_RETURN embeds — directly into Marathon's private mempool for faster, more predictable inclusion.

Works with a local [Electrum](https://electrum.org) wallet for UTXO discovery and transaction signing.

---

## Features

| Feature | Description |
|---|---|
| **Ordinal inscriptions** | Full commit + reveal flow via BIP-341 tapscript |
| **OP_RETURN embeds** | Up to 80 bytes of arbitrary data in one transaction |
| **Simple BTC sends** | Electrum-signed sends broadcast via Slipstream |
| **Dry-run mode** | Validate transactions without broadcasting (`--test`) |
| **Fee auto-detection** | Pulls live sat/vByte rates from Slipstream |
| **Electrum integration** | UTXO discovery, address export, signing delegation |

---

## Requirements

- Python 3.10+
- [Electrum](https://electrum.org/#download) (for wallet integration)
- A funded Bitcoin wallet

---

## Installation

```bash
git clone https://github.com/ManjulShah/sliprun.git
cd sliprun

# Recommended: use a virtual environment
python -m venv .venv
source .venv/bin/activate

pip install -e .
```

For development / tests:
```bash
pip install -e ".[dev]"
pytest -v
```

---

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

```dotenv
# Marathon Slipstream API
SLIPSTREAM_BASE_URL=https://slipstream.mara.com
SLIPSTREAM_CLIENT_CODE=          # optional, for volume discounts

# Bitcoin network: mainnet | testnet | signet
BITCOIN_NETWORK=mainnet

# Electrum daemon
ELECTRUM_HOST=127.0.0.1
ELECTRUM_PORT=7777
ELECTRUM_USER=user
ELECTRUM_PASSWORD=password
```

### Start Electrum daemon

```bash
electrum daemon start
electrum daemon load_wallet       # loads your default wallet
```

The daemon listens on `127.0.0.1:7777` by default.

---

## Usage

### Check Slipstream status and fee rates

```bash
sliprun status
sliprun rates
```

### Inscribe a file as an Ordinal

```bash
# Auto-detect content type, use Slipstream medium fee rate
sliprun inscribe art.png \
    --address bc1qYourAddress \
    --recipient bc1qRecipientAddress

# Explicit fee rate and WIF key
sliprun inscribe poem.txt \
    --privkey L1YourWIFKeyHere \
    --fee-rate 15 \
    --recipient bc1pRecipientAddress

# Dry-run (validate without broadcasting)
sliprun inscribe logo.svg --privkey L1... --test
```

**How it works:**

1. Builds the inscription tapscript leaf (Ordinals protocol)
2. Creates a **commit** transaction paying to `P2TR(key, [inscription_script])`
3. Creates a **reveal** transaction that spends via script path, embedding the inscription in the witness
4. Submits both as a `POST /api/transactions/packages` to Slipstream

### Embed data via OP_RETURN (up to 80 bytes)

```bash
sliprun op-return "Hello, Bitcoin!" --privkey L1...
sliprun op-return deadbeef01 --hex-data --privkey L1...
```

### Send BTC

```bash
# Electrum handles signing; Slipstream handles broadcast
sliprun send bc1qRecipientAddress 0.001
sliprun send bc1pAddress 0.005 --fee-rate 20 --test
```

### Check transaction status

```bash
sliprun tx-status <txid>
```

### Validate raw hex without broadcasting

```bash
sliprun test 0200000001abcdef...
sliprun test <commit_hex> <reveal_hex>
```

### Wallet information

```bash
sliprun wallet-info
sliprun wallet-info --show-utxos
```

---

## Architecture

```
sliprun/
├── api/
│   └── slipstream.py     # Marathon Slipstream API client
│                         # (system, rates, submit, packages, test)
├── wallet/
│   └── electrum.py       # Electrum JSON-RPC client
│                         # (UTXOs, signing, key export)
├── bitcoin/
│   ├── transaction.py    # Address → scriptPubKey, fee estimation
│   └── inscription.py    # Ordinals commit/reveal builder
│                         # OP_RETURN helper
├── cli.py                # Click-based command-line interface
└── config.py             # .env-backed configuration
```

### Inscription flow

```
Electrum wallet
     │
     ├── list_unspent()   ──► pick funding UTXO
     └── get_private_keys() ──► WIF key (or supply --privkey)

InscriptionBuilder
     │
     ├── build_inscription_script(pubkey, content_type, content)
     │       └── P2TR tapscript leaf with Ordinals envelope
     │
     ├── create_commit_tx(utxo → P2TR(key, [leaf]))
     │       └── P2WPKH input signed with Schnorr/ECDSA
     │
     └── create_reveal_tx(commit_utxo → recipient)
             └── P2TR script-path spend witness:
                 [schnorr_sig, inscription_script, control_block]

Slipstream API
     └── POST /api/transactions/packages([commit_hex, reveal_hex])
```

---

## API Reference

The Slipstream client wraps these endpoints:

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/system` | Version, chain, block height, fee floor |
| `GET` | `/api/block-info` | Blockchain status |
| `GET` | `/api/rates` | Current fee rates (sat/vByte) |
| `GET` | `/api/transactions/status` | Transaction status by txid |
| `POST` | `/api/transactions` | Submit single raw transaction |
| `POST` | `/api/transactions/packages` | Submit 2–25 related transactions |
| `POST` | `/api/mempool/tests` | Dry-run validation |

---

## Security

- **Never commit your private key.** Use `--privkey` via environment variable (`BITCOIN_WIF_KEY`) or Electrum key export.
- Electrum password is passed as a CLI option; avoid putting it in shell history (`HISTCONTROL=ignorespace`).
- The `.env` file is gitignored by default in this project.

---

## License

MIT

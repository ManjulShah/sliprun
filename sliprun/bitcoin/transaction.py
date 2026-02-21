"""
Bitcoin transaction utilities.

Uses python-bitcoinutils for address parsing and script conversion.
"""

from __future__ import annotations

from bitcoinutils.script import Script
from bitcoinutils.setup import setup as btc_setup


def configure_network(network: str = "mainnet") -> None:
    """Configure python-bitcoinutils for the given network."""
    mapping = {"mainnet": "mainnet", "testnet": "testnet", "signet": "testnet"}
    btc_setup(mapping.get(network, "mainnet"))


def btc_to_sat(btc: float) -> int:
    """Convert BTC to satoshis (integer)."""
    return round(btc * 100_000_000)


def sat_to_btc(satoshis: int) -> float:
    """Convert satoshis to BTC."""
    return satoshis / 100_000_000


def address_to_script_pubkey(address: str) -> Script:
    """
    Convert a Bitcoin address to its scriptPubKey.

    Supports P2PKH (1...), P2SH (3...), P2WPKH/P2WSH (bc1q...) and
    P2TR (bc1p...) addresses.
    """
    from bitcoinutils.keys import (
        P2pkhAddress,
        P2shAddress,
        P2trAddress,
        P2wpkhAddress,
        P2wshAddress,
    )

    addr_str = address.strip()

    # P2TR — native segwit v1 (bc1p... / tb1p...)
    if addr_str.lower().startswith(("bc1p", "tb1p")):
        return P2trAddress(addr_str).to_script_pub_key()

    # P2WPKH / P2WSH — native segwit v0 (bc1q... / tb1q...)
    if addr_str.lower().startswith(("bc1q", "tb1q")):
        try:
            return P2wpkhAddress(addr_str).to_script_pub_key()
        except Exception:
            return P2wshAddress(addr_str).to_script_pub_key()

    # P2SH (3... / 2...)
    if addr_str.startswith(("3", "2")):
        return P2shAddress(addr_str).to_script_pub_key()

    # P2PKH (1... / m... / n...)
    return P2pkhAddress(addr_str).to_script_pub_key()


# ---------------------------------------------------------------------------
# Fee estimation (virtual bytes)
# ---------------------------------------------------------------------------

# Ordinals commit: 1-input P2WPKH → 1-output P2TR + optional change
_COMMIT_BASE_VBYTES = 154

# Ordinals reveal: 1-input P2TR (script path) → 1-output
# Base: ~105 vbytes + witness discount on script size
_REVEAL_BASE_VBYTES = 105


def estimate_commit_fee(fee_rate_sat_vb: float) -> int:
    """Estimate commit transaction fee in satoshis."""
    return round(_COMMIT_BASE_VBYTES * fee_rate_sat_vb)


def estimate_reveal_fee(content_bytes: int, fee_rate_sat_vb: float) -> int:
    """
    Estimate reveal transaction fee in satoshis.

    Witness data is discounted by 4x under segwit rules, so inscription
    content is cheap per byte.
    """
    # Each content byte sits in the witness, contributing 0.25 vbytes
    witness_vbytes = content_bytes // 4
    total_vbytes = _REVEAL_BASE_VBYTES + witness_vbytes
    return round(total_vbytes * fee_rate_sat_vb)

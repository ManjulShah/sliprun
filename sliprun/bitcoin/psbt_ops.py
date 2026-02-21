"""
PSBT (Partially Signed Bitcoin Transaction) operations — BIP-174.

Workflow:
  1. create_psbt()      → base64 PSBT string (unsigned)
  2. sign_psbt()        → base64 PSBT string (signed, local WIF key)
     sign_psbt_electrum() → base64 PSBT string (signed, via Electrum)
  3. decode_psbt()      → human-readable dict
  4. finalize_psbt()    → signed transaction hex ready for broadcast

PSBTs are useful for:
- Hardware wallet signing (export PSBT, sign on device, import back)
- Multi-party signing (each party signs their inputs)
- Air-gapped signing workflows
"""

from __future__ import annotations

import base64
import struct
from io import BytesIO
from typing import Any

# bitcoin-utils 0.7.3 ships a psbt.py that imports `read_varint` from
# bitcoinutils.utils, but that function was never added to utils.py.
# Patch it in before the import so downstream code works correctly.
import bitcoinutils.utils as _btu
if not hasattr(_btu, "read_varint"):
    def _read_varint(stream: BytesIO) -> int:
        """Read a Bitcoin variable-length integer from a binary stream."""
        raw = stream.read(1)
        if not raw:
            raise EOFError("Empty stream in read_varint")
        i = struct.unpack("<B", raw)[0]
        if i == 0xFD:
            return struct.unpack("<H", stream.read(2))[0]
        if i == 0xFE:
            return struct.unpack("<I", stream.read(4))[0]
        if i == 0xFF:
            return struct.unpack("<Q", stream.read(8))[0]
        return i
    _btu.read_varint = _read_varint  # type: ignore[attr-defined]

from bitcoinutils.keys import PrivateKey
from bitcoinutils.psbt import PSBT, PSBTInput
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput

from .transaction import (
    address_to_script_pubkey,
    btc_to_sat,
    configure_network,
    estimate_commit_fee,
)

_DUST_LIMIT = 546
_DEFAULT_FEE_RATE = 10.0


class PSBTError(Exception):
    pass


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------

def create_psbt(
    utxos: list[dict],
    recipient: str,
    amount_btc: float,
    change_address: str,
    fee_rate: float = _DEFAULT_FEE_RATE,
    network: str = "mainnet",
) -> str:
    """
    Build an unsigned PSBT for a simple payment.

    Args:
        utxos:          List of UTXO dicts (from Electrum: prevout_hash,
                        prevout_n, satoshis, address).
        recipient:      Destination Bitcoin address.
        amount_btc:     Amount to send in BTC.
        change_address: Address for change output.
        fee_rate:       Fee rate in sat/vByte.
        network:        'mainnet', 'testnet', or 'signet'.

    Returns:
        Base64-encoded PSBT string.
    """
    configure_network(network)

    amount_sat = btc_to_sat(amount_btc)

    # Select UTXOs (simple: pick largest first until covered)
    selected, total_in = _select_utxos(utxos, amount_sat, fee_rate)

    # Estimate fee for 1+ inputs, 2 outputs (P2WPKH)
    n_inputs = len(selected)
    fee = round((10 + n_inputs * 68 + 2 * 31) * fee_rate)
    change_sat = total_in - amount_sat - fee

    if change_sat < 0:
        raise PSBTError(
            f"Insufficient funds: need {amount_sat + fee} sat, have {total_in} sat"
        )

    # Build unsigned transaction
    inputs = [TxInput(u["prevout_hash"], int(u["prevout_n"])) for u in selected]
    outputs = [TxOutput(amount_sat, address_to_script_pubkey(recipient))]
    if change_sat >= _DUST_LIMIT:
        outputs.append(TxOutput(change_sat, address_to_script_pubkey(change_address)))

    unsigned_tx = Transaction(inputs, outputs, has_segwit=True)

    # Build PSBT and annotate inputs with UTXO info (required for signing)
    psbt = PSBT(unsigned_tx)
    for i, utxo in enumerate(selected):
        psbt.inputs[i].witness_utxo = TxOutput(
            int(utxo["satoshis"]),
            address_to_script_pubkey(utxo["address"]),
        )

    return psbt.to_base64()


def _select_utxos(
    utxos: list[dict], target_sat: int, fee_rate: float
) -> tuple[list[dict], int]:
    """Greedy UTXO selection: largest first."""
    sorted_utxos = sorted(utxos, key=lambda u: int(u["satoshis"]), reverse=True)
    selected: list[dict] = []
    total = 0
    # Rough fee estimate per input
    per_input_fee = round(68 * fee_rate)
    for u in sorted_utxos:
        selected.append(u)
        total += int(u["satoshis"])
        if total >= target_sat + per_input_fee * len(selected) + round(2 * 31 * fee_rate):
            break
    if total < target_sat:
        raise PSBTError(
            f"Not enough UTXOs: need {target_sat} sat, available {total} sat"
        )
    return selected, total


# ---------------------------------------------------------------------------
# Sign (local WIF key)
# ---------------------------------------------------------------------------

def sign_psbt(
    psbt_b64: str,
    wif_private_key: str,
    network: str = "mainnet",
) -> str:
    """
    Sign all inputs in a PSBT using a local WIF private key.

    Args:
        psbt_b64:        Base64-encoded PSBT.
        wif_private_key: WIF-encoded private key.
        network:         Network for address/script validation.

    Returns:
        Base64-encoded PSBT with signatures added.
    """
    configure_network(network)
    psbt = PSBT.from_base64(psbt_b64)
    privkey = PrivateKey(wif_private_key)

    for i in range(len(psbt.inputs)):
        psbt.sign_input(i, privkey)

    return psbt.to_base64()


# ---------------------------------------------------------------------------
# Sign via Electrum
# ---------------------------------------------------------------------------

def sign_psbt_electrum(psbt_b64: str, electrum_client) -> str:
    """
    Sign a PSBT using Electrum's wallet.

    Electrum's `signtransaction` can accept PSBT (base64) in newer versions.
    Falls back to extracting the unsigned tx hex for older versions.

    Args:
        psbt_b64:        Base64-encoded PSBT.
        electrum_client: An `ElectrumClient` instance.

    Returns:
        Base64-encoded signed PSBT (or signed tx hex if Electrum returns hex).
    """
    # Try passing PSBT directly to signtransaction
    result = electrum_client.sign_transaction(psbt_b64)

    # If Electrum returned a signed PSBT (base64), return it as-is.
    # If it returned a raw hex tx, wrap it back as a finalised PSBT.
    if result and not result.startswith("02"):
        # Looks like base64 PSBT
        return result

    # Electrum returned a signed raw tx hex; re-wrap into a finalized PSBT
    # so downstream callers can call finalize_psbt() uniformly.
    psbt = PSBT.from_base64(psbt_b64)
    # Overwrite the PSBT with the signed tx by re-creating from signed hex
    signed_tx = Transaction.from_raw(result)
    # Mark inputs as finalized using the signed tx witnesses
    for i, (psbt_in, txin, wit) in enumerate(
        zip(psbt.inputs, signed_tx.inputs, signed_tx.witnesses or [])
    ):
        if wit and wit.witness_items:
            psbt_in.final_scriptwitness = [
                bytes.fromhex(item) for item in wit.witness_items
            ]

    return psbt.to_base64()


# ---------------------------------------------------------------------------
# Decode
# ---------------------------------------------------------------------------

def decode_psbt(psbt_b64: str, network: str = "mainnet") -> dict[str, Any]:
    """
    Decode a PSBT into a human-readable dictionary.

    Returns:
        Dict with keys: version, inputs, outputs, unsigned_tx_hex, complete.
    """
    configure_network(network)
    psbt = PSBT.from_base64(psbt_b64)

    inputs_info = []
    for i, inp in enumerate(psbt.inputs):
        info: dict[str, Any] = {"index": i}
        if inp.witness_utxo:
            info["utxo_amount_sat"] = inp.witness_utxo.amount
            info["utxo_script"] = inp.witness_utxo.script_pubkey.to_hex()
        if inp.partial_sigs:
            info["partial_sigs"] = len(inp.partial_sigs)
        if inp.final_scriptwitness:
            info["finalized"] = True
        inputs_info.append(info)

    outputs_info = []
    for i, out in enumerate(psbt.tx.outputs):
        outputs_info.append({
            "index": i,
            "amount_sat": out.amount,
            "script": out.script_pubkey.to_hex(),
        })

    # Check if all inputs are finalized
    complete = all(
        bool(inp.final_scriptwitness or inp.final_scriptsig)
        for inp in psbt.inputs
    )

    return {
        "version": psbt.version,
        "unsigned_tx_hex": psbt.tx.serialize(),
        "inputs": inputs_info,
        "outputs": outputs_info,
        "complete": complete,
        "input_count": len(psbt.inputs),
        "output_count": len(psbt.tx.outputs),
    }


# ---------------------------------------------------------------------------
# Finalize
# ---------------------------------------------------------------------------

def finalize_psbt(psbt_b64: str, network: str = "mainnet") -> str:
    """
    Finalize a fully-signed PSBT and extract the signed transaction hex.

    Args:
        psbt_b64: Base64-encoded PSBT with all required signatures.
        network:  Network for script validation.

    Returns:
        Signed transaction hex ready for submission to Slipstream.

    Raises:
        PSBTError: If not all inputs can be finalized.
    """
    configure_network(network)
    psbt = PSBT.from_base64(psbt_b64)
    final_tx = psbt.finalize()
    if final_tx is None:
        raise PSBTError(
            "PSBT could not be finalized — one or more inputs are missing signatures."
        )
    return final_tx.serialize()

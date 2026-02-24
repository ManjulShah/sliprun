"""
Ordinal inscription builder for Bitcoin.

Implements the two-phase commit/reveal pattern used by the Ordinals protocol:

  Phase 1 — COMMIT
    Build a transaction that pays to a P2TR address whose tapscript contains
    the inscription.  The output locks funds to:
        P2TR(internal_key, [inscription_script_leaf])

  Phase 2 — REVEAL
    Build a transaction that spends the commit output via a tapscript path,
    revealing the inscription in the witness.  The witness stack is:
        [<schnorr_sig>, <inscription_script>, <control_block>]

Both transactions are returned as signed hex and submitted together as a
package to the Slipstream API (POST /api/transactions/packages).

Inscription script format (BIP-341 tapscript leaf):
    <internal_pubkey_x> OP_CHECKSIG
    OP_FALSE OP_IF
        <"ord">
        OP_1
        <content_type_bytes>
        OP_0
        <content_chunk_1>
        [<content_chunk_2> ...]
    OP_ENDIF

The OP_FALSE guard means the IF branch is never executed, so the inscription
data has no effect on script execution.  The OP_CHECKSIG at the top is what
actually validates the spend.
"""

from __future__ import annotations

import mimetypes
from dataclasses import dataclass
from pathlib import Path

from bitcoinutils.script import Script
from bitcoinutils.transactions import Transaction, TxInput, TxOutput, TxWitnessInput
from bitcoinutils.keys import PrivateKey
from bitcoinutils.utils import ControlBlock


# Maximum bytes per script push (consensus limit)
_MAX_CHUNK = 520

# Dust limit for a P2TR output (sat)
_DUST_LIMIT = 546


class InscriptionError(Exception):
    pass


@dataclass
class OrdinalInscription:
    """Holds the data for a single inscription."""
    content_type: str    # MIME type, e.g. "text/plain;charset=utf-8"
    content: bytes       # Raw content bytes


@dataclass
class CommitRevealPair:
    commit_tx_hex: str
    reveal_tx_hex: str
    commit_txid: str
    inscription_address: str  # P2TR address of the commit output


def _chunk(data: bytes, size: int = _MAX_CHUNK) -> list[bytes]:
    """Split data into at-most-`size`-byte chunks."""
    return [data[i : i + size] for i in range(0, len(data), size)]


def _build_inscription_script(
    internal_pubkey_hex: str,
    content_type: str,
    content: bytes,
) -> Script:
    """
    Build the Ordinals inscription tapscript leaf.

    The internal pubkey is the x-only (32-byte) representation as hex.
    """
    chunks = _chunk(content)

    items: list[str | int] = [
        internal_pubkey_hex,
        "OP_CHECKSIG",
        "OP_0",    # OP_FALSE — the IF branch is always skipped
        "OP_IF",
        b"ord".hex(),
        "OP_1",
        content_type.encode().hex(),
        "OP_0",
    ]
    for chunk in chunks:
        items.append(chunk.hex())
    items.append("OP_ENDIF")

    return Script(items)


class InscriptionBuilder:
    """
    High-level builder for Ordinal inscription commit/reveal transactions.

    Usage:
        builder = InscriptionBuilder(private_key_wif, network="mainnet")
        pair = builder.build(
            inscription=OrdinalInscription("text/plain", b"Hello, Ordinals!"),
            funding_utxo={
                "prevout_hash": "abcd...",
                "prevout_n": 0,
                "satoshis": 10000,
                "address": "bc1q...",
            },
            recipient="bc1q...",   # where the inscribed sat lands
            fee_rate=10.0,         # sat/vByte
        )
        # Submit pair.commit_tx_hex and pair.reveal_tx_hex as a package
    """

    def __init__(self, wif_private_key: str, network: str = "mainnet"):
        from .transaction import configure_network
        configure_network(network)
        self._privkey = PrivateKey(wif_private_key)
        self._pubkey = self._privkey.get_public_key()
        # x-only pubkey hex (32 bytes = 64 hex chars)
        self._pubkey_x_hex = self._pubkey.to_hex()[2:] if len(self._pubkey.to_hex()) == 66 else self._pubkey.to_hex()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def build(
        self,
        inscription: OrdinalInscription,
        funding_utxo: dict,
        recipient: str,
        fee_rate: float = 10.0,
        change_address: str | None = None,
    ) -> CommitRevealPair:
        """
        Build and sign both commit and reveal transactions.

        Args:
            inscription:   OrdinalInscription with content_type and content.
            funding_utxo:  UTXO dict from Electrum (needs 'prevout_hash',
                           'prevout_n', 'satoshis', 'address').
            recipient:     Bitcoin address that will receive the inscribed sat.
            fee_rate:      Fee rate in sat/vByte.
            change_address: Where to send change (defaults to funding address).

        Returns:
            CommitRevealPair with signed hex for both transactions.
        """
        from .transaction import estimate_commit_fee, estimate_reveal_fee

        script = _build_inscription_script(
            self._pubkey_x_hex, inscription.content_type, inscription.content
        )

        # P2TR address with inscription as the sole tapscript leaf
        p2tr_addr = self._pubkey.get_taproot_address([[script]])
        inscription_address = p2tr_addr.to_string()

        reveal_fee = estimate_reveal_fee(len(inscription.content), fee_rate)
        commit_fee = estimate_commit_fee(fee_rate)

        # The commit output must cover the reveal fee + dust for the reveal output
        commit_output_amount = _DUST_LIMIT + reveal_fee

        funding_sats = int(funding_utxo["satoshis"])
        change_sats = funding_sats - commit_output_amount - commit_fee
        if change_sats < 0:
            raise InscriptionError(
                f"Insufficient funds: need {commit_output_amount + commit_fee} sat, "
                f"have {funding_sats} sat"
            )

        # ------------------------------------------------------------------
        # Phase 1: Commit transaction
        # ------------------------------------------------------------------
        commit_tx = self._build_commit(
            utxo=funding_utxo,
            p2tr_script_pubkey=p2tr_addr.to_script_pub_key(),
            commit_amount=commit_output_amount,
            change_address=change_address or funding_utxo.get("address", ""),
            change_amount=change_sats,
            fee_rate=fee_rate,
        )

        commit_txid = commit_tx.get_txid()

        # ------------------------------------------------------------------
        # Phase 2: Reveal transaction
        # ------------------------------------------------------------------
        reveal_tx = self._build_reveal(
            commit_txid=commit_txid,
            commit_amount=commit_output_amount,
            p2tr_script_pubkey=p2tr_addr.to_script_pub_key(),
            inscription_script=script,
            p2tr_addr=p2tr_addr,
            recipient=recipient,
            reveal_fee=reveal_fee,
        )

        return CommitRevealPair(
            commit_tx_hex=commit_tx.serialize(),
            reveal_tx_hex=reveal_tx.serialize(),
            commit_txid=commit_txid,
            inscription_address=inscription_address,
        )

    @classmethod
    def from_file(
        cls,
        wif_private_key: str,
        file_path: str | Path,
        network: str = "mainnet",
        content_type: str | None = None,
    ) -> tuple["InscriptionBuilder", OrdinalInscription]:
        """
        Convenience factory: create a builder and load an inscription from a file.

        Args:
            wif_private_key: WIF-encoded private key.
            file_path:       Path to the file to inscribe.
            network:         'mainnet', 'testnet', or 'signet'.
            content_type:    Override MIME type (auto-detected if None).

        Returns:
            (InscriptionBuilder, OrdinalInscription)
        """
        path = Path(file_path)
        if not path.exists():
            raise InscriptionError(f"File not found: {path}")

        content = path.read_bytes()

        if content_type is None:
            guessed, _ = mimetypes.guess_type(str(path))
            content_type = guessed or "application/octet-stream"

        return cls(wif_private_key, network), OrdinalInscription(content_type, content)

    # ------------------------------------------------------------------
    # Internal transaction builders
    # ------------------------------------------------------------------

    def _build_commit(
        self,
        utxo: dict,
        p2tr_script_pubkey: Script,
        commit_amount: int,
        change_address: str,
        change_amount: int,
        fee_rate: float,
    ) -> Transaction:
        from .transaction import address_to_script_pubkey

        txin = TxInput(utxo["prevout_hash"], int(utxo["prevout_n"]))
        outputs = [TxOutput(commit_amount, p2tr_script_pubkey)]

        if change_amount >= _DUST_LIMIT and change_address:
            outputs.append(
                TxOutput(change_amount, address_to_script_pubkey(change_address))
            )

        tx = Transaction([txin], outputs, has_segwit=True)

        # Sign commit input — P2WPKH spend (BIP143 scriptCode = P2PKH script)
        from .transaction import p2wpkh_signing_script
        signing_script = p2wpkh_signing_script(self._pubkey)
        sig = self._privkey.sign_segwit_input(
            tx,
            0,
            signing_script,
            utxo["satoshis"],
        )
        tx.witnesses.append(
            TxWitnessInput([sig, self._pubkey.to_hex()])
        )
        return tx

    def _build_reveal(
        self,
        commit_txid: str,
        commit_amount: int,
        p2tr_script_pubkey: Script,
        inscription_script: Script,
        p2tr_addr,
        recipient: str,
        reveal_fee: int,
    ) -> Transaction:
        from .transaction import address_to_script_pubkey

        txin = TxInput(commit_txid, 0)
        reveal_amount = commit_amount - reveal_fee
        if reveal_amount < _DUST_LIMIT:
            raise InscriptionError(
                f"Reveal output ({reveal_amount} sat) would be below dust limit "
                f"({_DUST_LIMIT} sat). Increase commit amount or lower fee rate."
            )

        txout = TxOutput(reveal_amount, address_to_script_pubkey(recipient))
        tx = Transaction([txin], [txout], has_segwit=True)

        # Sign via tapscript (script path spend)
        # sign_taproot_input(tx, index, utxo_scripts, amounts, ...)
        sig = self._privkey.sign_taproot_input(
            tx,
            0,
            [p2tr_script_pubkey],
            [commit_amount],
            script_path=True,
            tapleaf_script=inscription_script,
            tweak=False,
        )

        # Control block: [leaf_version | parity_bit][internal_pubkey_x][merkle_path...]
        # Single-leaf tree has an empty merkle path.
        cb = ControlBlock(
            self._pubkey,
            scripts=[[inscription_script]],
            index=0,
            is_odd=p2tr_addr.is_odd(),
        )

        tx.witnesses.append(
            TxWitnessInput([sig, inscription_script.to_hex(), cb.to_hex()])
        )
        return tx


# ---------------------------------------------------------------------------
# OP_RETURN helper (simple data embedding, not Ordinals)
# ---------------------------------------------------------------------------

def build_op_return_tx(
    wif_private_key: str,
    funding_utxo: dict,
    data: bytes,
    change_address: str,
    fee_rate: float = 5.0,
    network: str = "mainnet",
) -> str:
    """
    Build and sign a transaction embedding up to 80 bytes of data via OP_RETURN.

    This is a simple, one-phase alternative to Ordinals for small payloads
    (hashes, timestamps, short text).

    Returns:
        Signed transaction hex ready for Slipstream submission.
    """
    from .transaction import address_to_script_pubkey, configure_network

    configure_network(network)

    if len(data) > 80:
        raise InscriptionError(f"OP_RETURN data must be ≤ 80 bytes, got {len(data)}")

    privkey = PrivateKey(wif_private_key)
    pubkey = privkey.get_public_key()

    # Estimate fee: ~170 vbytes for 1-in / 2-out P2WPKH + OP_RETURN
    fee = round(170 * fee_rate)
    funding_sats = int(funding_utxo["satoshis"])
    change_sats = funding_sats - fee
    if change_sats < 0:
        raise InscriptionError(
            f"Insufficient funds: need {fee} sat fee, have {funding_sats} sat"
        )

    txin = TxInput(funding_utxo["prevout_hash"], int(funding_utxo["prevout_n"]))
    op_return_script = Script(["OP_RETURN", data.hex()])
    outputs = [TxOutput(0, op_return_script)]

    if change_sats >= _DUST_LIMIT:
        outputs.append(
            TxOutput(change_sats, address_to_script_pubkey(change_address))
        )

    tx = Transaction([txin], outputs, has_segwit=True)

    signing_script = pubkey.get_address().to_script_pub_key()  # BIP143 P2PKH scriptCode
    sig = privkey.sign_segwit_input(tx, 0, signing_script, funding_sats)
    tx.witnesses.append(TxWitnessInput([sig, pubkey.to_hex()]))

    return tx.serialize()

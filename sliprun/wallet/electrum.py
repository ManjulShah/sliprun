"""
Electrum wallet JSON-RPC client.

Electrum must be running in daemon mode before use:

    electrum daemon start
    electrum daemon load_wallet   # loads default wallet

By default the daemon listens on 127.0.0.1:7777 with credentials user:password.
Override via .env (ELECTRUM_HOST / ELECTRUM_PORT / ELECTRUM_USER / ELECTRUM_PASSWORD).

Key methods used by sliprun:
  - listunspent()          -> UTXOs for funding transactions
  - getunusedaddress()     -> fresh change / recipient address
  - signtransaction(hex)   -> sign a raw PSBT or legacy tx
  - getprivatekeys(addr)   -> export WIF key for a wallet address
  - payto(addr, amount)    -> build a simple payment transaction
  - broadcast(hex)         -> optional local broadcast (we use Slipstream instead)
"""

from __future__ import annotations

import json
from typing import Any

import requests
from requests.auth import HTTPBasicAuth


class ElectrumError(Exception):
    """Raised when Electrum returns an error or is unreachable."""


class ElectrumClient:
    """JSON-RPC 2.0 client for an Electrum daemon."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 7777,
        user: str = "user",
        password: str = "password",
        timeout: int = 30,
    ):
        self._url = f"http://{host}:{port}"
        self._auth = HTTPBasicAuth(user, password)
        self._timeout = timeout
        self._id = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    def _call(self, method: str, *params: Any) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id(),
            "method": method,
            "params": list(params),
        }
        try:
            resp = requests.post(
                self._url,
                json=payload,
                auth=self._auth,
                timeout=self._timeout,
            )
        except requests.ConnectionError as exc:
            raise ElectrumError(
                "Cannot connect to Electrum daemon. "
                "Make sure it is running:\n"
                "  electrum daemon start\n"
                "  electrum daemon load_wallet"
            ) from exc

        if resp.status_code == 401:
            raise ElectrumError("Electrum authentication failed. Check ELECTRUM_USER / ELECTRUM_PASSWORD.")

        resp.raise_for_status()
        data = resp.json()

        if data.get("error"):
            err = data["error"]
            msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
            raise ElectrumError(f"Electrum RPC error [{method}]: {msg}")

        return data.get("result")

    # ------------------------------------------------------------------
    # Wallet info
    # ------------------------------------------------------------------

    def get_info(self) -> dict:
        """Return daemon / wallet info."""
        return self._call("getinfo")

    def get_balance(self) -> dict:
        """Return wallet balance dict: {confirmed, unconfirmed, unmatured}."""
        return self._call("getbalance")

    def get_unused_address(self) -> str:
        """Return a fresh, unused receiving address."""
        return self._call("getunusedaddress")

    def list_unspent(self) -> list[dict]:
        """
        Return UTXOs for the loaded wallet.

        Each entry looks like:
            {
                "address": "bc1q...",
                "value": 0.00050000,          # BTC
                "prevout_hash": "abcd...",
                "prevout_n": 0,
                "height": 800000,
            }
        """
        return self._call("listunspent")

    def is_mine(self, address: str) -> bool:
        """Return True if address belongs to the loaded wallet."""
        return bool(self._call("ismine", address))

    # ------------------------------------------------------------------
    # Transaction operations
    # ------------------------------------------------------------------

    def payto(
        self,
        destination: str,
        amount: float,
        fee_rate: float | None = None,
        unsigned: bool = True,
    ) -> str:
        """
        Create a payment transaction.

        Args:
            destination: Bitcoin address.
            amount:      Amount in BTC.
            fee_rate:    Fee rate in sat/vByte (optional).
            unsigned:    If True, return unsigned tx hex (we sign locally or
                         pass to sign_transaction).

        Returns:
            Raw transaction hex (unsigned by default).
        """
        kwargs: dict[str, Any] = {}
        if fee_rate is not None:
            kwargs["fee_rate"] = fee_rate
        if unsigned:
            kwargs["unsigned"] = True

        result = self._call("payto", destination, amount, kwargs) if kwargs else self._call("payto", destination, amount)

        # Electrum may return a dict or a hex string depending on version
        if isinstance(result, dict):
            return result.get("hex", result.get("tx", ""))
        return result

    def sign_transaction(self, tx_hex: str, password: str = "") -> str:
        """
        Sign a transaction with the wallet's keys.

        Args:
            tx_hex:   Unsigned (or partially signed) transaction hex.
            password: Wallet password if the wallet is encrypted.

        Returns:
            Signed transaction hex.
        """
        args = [tx_hex]
        if password:
            args.append(password)
        result = self._call("signtransaction", *args)
        if isinstance(result, dict):
            return result.get("hex", result.get("tx", ""))
        return result

    def get_private_keys(self, address: str, password: str = "") -> list[str]:
        """
        Export WIF private key(s) for a wallet address.

        Returns a list because some address types (multisig) have multiple keys.
        Requires an unlocked wallet.
        """
        args = [address]
        if password:
            args.append(password)
        result = self._call("getprivatekeys", *args)
        if isinstance(result, list):
            return result
        return [result]

    def broadcast(self, tx_hex: str) -> str:
        """
        Broadcast a signed transaction via Electrum's connected servers.

        NOTE: Prefer SlipstreamClient.submit_transaction() for access to
        Marathon's private mempool with better fee economics.

        Returns:
            txid on success.
        """
        return self._call("broadcast", tx_hex)

    def bump_fee(self, txid: str, new_fee_rate: float) -> str:
        """
        Replace an unconfirmed transaction with a higher-fee version (RBF).

        Electrum rebuilds the transaction spending the same inputs but pays a
        higher fee by reducing the change output.  The wallet must contain the
        original transaction and its inputs must signal RBF.

        Args:
            txid:         The txid of the stuck transaction.
            new_fee_rate: New fee rate in sat/vByte (must be higher than original).

        Returns:
            Signed replacement transaction hex ready for broadcast.
        """
        result = self._call("bumpfee", txid, {"fee_rate": new_fee_rate})
        if isinstance(result, dict):
            return result.get("hex", result.get("tx", ""))
        return result

    def get_transaction(self, txid: str) -> dict:
        """Return full transaction details by txid."""
        return self._call("gettransaction", txid)

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def utxos_above(self, min_satoshis: int) -> list[dict]:
        """
        Return UTXOs with at least `min_satoshis` value, sorted largest first.

        Converts Electrum's BTC values to satoshis and adds a 'satoshis' key.
        """
        utxos = self.list_unspent()
        enriched = []
        for u in utxos:
            sats = round(float(u.get("value", 0)) * 1e8)
            if sats >= min_satoshis:
                u["satoshis"] = sats
                enriched.append(u)
        enriched.sort(key=lambda u: u["satoshis"], reverse=True)
        return enriched

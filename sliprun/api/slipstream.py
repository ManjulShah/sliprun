"""
Marathon Slipstream API client.

Endpoints:
  GET  /api/system                  - chain info, block height, fee floor
  GET  /api/block-info              - structured blockchain status
  GET  /api/rates                   - current fee rates (sat/vByte)
  GET  /api/transactions/status     - transaction status by txid
  POST /api/transactions            - submit single raw transaction
  POST /api/transactions/packages   - submit 2-25 transactions as a package
  POST /api/mempool/tests           - test transactions against consensus rules
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import requests


class SlipstreamError(Exception):
    def __init__(self, status_code: int, body: str):
        self.status_code = status_code
        self.body = body
        super().__init__(f"Slipstream API error {status_code}: {body}")


@dataclass
class SystemInfo:
    version: str
    chain: str
    block_height: int
    fee_rate_floor: float

    @classmethod
    def from_dict(cls, d: dict) -> "SystemInfo":
        return cls(
            version=d.get("version", ""),
            chain=d.get("chain_name", d.get("chain", "")),
            block_height=d.get("block_height", 0),
            fee_rate_floor=d.get("fee_rate_floor", 0.0),
        )


@dataclass
class FeeRates:
    low: float
    medium: float
    high: float
    unit: str = "sat/vByte"

    @classmethod
    def from_dict(cls, d: dict) -> "FeeRates":
        # Slipstream returns rates in various shapes; normalise here
        return cls(
            low=d.get("low", d.get("economy", 0.0)),
            medium=d.get("medium", d.get("normal", 0.0)),
            high=d.get("high", d.get("priority", 0.0)),
        )


@dataclass
class TxSubmitResult:
    txid: str
    status: str
    message: str

    @classmethod
    def from_dict(cls, d: dict) -> "TxSubmitResult":
        return cls(
            txid=d.get("txid", d.get("tx_id", "")),
            status=d.get("status", ""),
            message=d.get("message", ""),
        )


class SlipstreamClient:
    """HTTP client for the Marathon Slipstream API."""

    BASE_URL = "https://slipstream.mara.com"

    def __init__(
        self,
        base_url: str = BASE_URL,
        client_code: str | None = None,
        timeout: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.client_code = client_code
        self._timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {"Content-Type": "application/json", "Accept": "application/json"}
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get(self, path: str, params: dict[str, Any] | None = None) -> Any:
        url = f"{self.base_url}{path}"
        resp = self._session.get(url, params=params or {}, timeout=self._timeout)
        if not resp.ok:
            raise SlipstreamError(resp.status_code, resp.text)
        return resp.json()

    def _post(self, path: str, payload: dict) -> Any:
        url = f"{self.base_url}{path}"
        resp = self._session.post(url, json=payload, timeout=self._timeout)
        if not resp.ok:
            raise SlipstreamError(resp.status_code, resp.text)
        return resp.json()

    def _with_client_code(self, d: dict) -> dict:
        if self.client_code:
            d["client_code"] = self.client_code
        return d

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_system_info(self) -> dict:
        """Returns API version, chain name, block height, and fee rate floor."""
        return self._get("/api/system")

    def get_block_info(self) -> dict:
        """Returns structured blockchain status data."""
        return self._get("/api/block-info")

    def get_rates(self) -> dict:
        """Returns current fee rates in sat/vByte."""
        params: dict[str, Any] = {}
        if self.client_code:
            params["client_code"] = self.client_code
        return self._get("/api/rates", params)

    def get_transaction_status(self, tx_id: str) -> dict:
        """Returns detailed status for a transaction by its txid."""
        return self._get("/api/transactions/status", {"tx_id": tx_id})

    def submit_transaction(self, tx_hex: str) -> dict:
        """
        Submit a single raw Bitcoin transaction.

        Args:
            tx_hex: Signed transaction in hexadecimal format.

        Returns:
            API response with status and txid.
        """
        payload = self._with_client_code({"tx_hex": tx_hex})
        return self._post("/api/transactions", payload)

    def submit_package(self, tx_hexes: list[str]) -> dict:
        """
        Submit a package of 2-25 related transactions (e.g. commit + reveal).

        The API processes them as a unit, which is required for CPFP / Ordinals
        commit-reveal pairs where the reveal depends on the unconfirmed commit.

        Args:
            tx_hexes: Ordered list of raw transaction hexes (2-25 items).

        Returns:
            API response mapping txids to per-transaction results.
        """
        if not (2 <= len(tx_hexes) <= 25):
            raise ValueError(
                f"Package must contain 2-25 transactions, got {len(tx_hexes)}"
            )
        payload = self._with_client_code({"tx_hexes": tx_hexes})
        return self._post("/api/transactions/packages", payload)

    def test_transaction(self, tx_hexes: list[str]) -> dict:
        """
        Dry-run: test transactions against consensus and policy rules without
        broadcasting.

        Args:
            tx_hexes: List of raw transaction hexes to validate.

        Returns:
            Validation results per transaction.
        """
        return self._post("/api/mempool/tests", {"tx_hexes": tx_hexes})

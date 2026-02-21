"""
Unit tests for sliprun.

Run with:  pytest -v
Requires:  pip install -e ".[dev]"
"""

from __future__ import annotations

import pytest
import responses as rsps_lib
import responses

from sliprun.api.slipstream import SlipstreamClient, SlipstreamError
from sliprun.bitcoin.inscription import (
    OrdinalInscription,
    _build_inscription_script,
    _chunk,
    build_op_return_tx,
)
from sliprun.bitcoin.transaction import btc_to_sat, sat_to_btc, estimate_reveal_fee


# ===========================================================================
# Helpers
# ===========================================================================

BASE = "https://slipstream.mara.com"


def make_client(**kwargs) -> SlipstreamClient:
    return SlipstreamClient(base_url=BASE, **kwargs)


# ===========================================================================
# Unit tests — bitcoin utilities
# ===========================================================================

class TestConversions:
    def test_btc_to_sat(self):
        assert btc_to_sat(1.0) == 100_000_000
        assert btc_to_sat(0.001) == 100_000
        assert btc_to_sat(0.00000001) == 1

    def test_sat_to_btc(self):
        assert sat_to_btc(100_000_000) == 1.0
        assert sat_to_btc(1) == 1e-8

    def test_roundtrip(self):
        for amount in [0.001, 0.1, 1.23456789]:
            assert btc_to_sat(sat_to_btc(btc_to_sat(amount))) == btc_to_sat(amount)


class TestChunking:
    def test_small_data_single_chunk(self):
        data = b"hello"
        chunks = _chunk(data, 520)
        assert chunks == [b"hello"]

    def test_exact_boundary(self):
        data = b"x" * 520
        chunks = _chunk(data, 520)
        assert len(chunks) == 1
        assert chunks[0] == data

    def test_multi_chunk(self):
        data = b"x" * 1100
        chunks = _chunk(data, 520)
        assert len(chunks) == 3
        assert len(chunks[0]) == 520
        assert len(chunks[1]) == 520
        assert len(chunks[2]) == 60

    def test_empty(self):
        assert _chunk(b"") == []


class TestInscriptionScript:
    def test_script_contains_ord(self):
        # Using a dummy 32-byte pubkey
        pubkey_hex = "02" + "a" * 62  # not valid crypto, just for script building
        script = _build_inscription_script(
            internal_pubkey_hex=pubkey_hex[2:],  # x-only (64 hex = 32 bytes)
            content_type="text/plain",
            content=b"Hello",
        )
        items = script.script
        # Should contain "ord" as hex
        assert b"ord".hex() in items or "6f7264" in items

    def test_script_contains_checksig(self):
        pubkey_hex = "a" * 64
        script = _build_inscription_script(
            internal_pubkey_hex=pubkey_hex,
            content_type="text/plain",
            content=b"test",
        )
        items_str = str(script.script)
        assert "OP_CHECKSIG" in items_str

    def test_large_content_splits_into_chunks(self):
        pubkey_hex = "a" * 64
        big_content = b"x" * 1200
        script = _build_inscription_script(
            internal_pubkey_hex=pubkey_hex,
            content_type="application/octet-stream",
            content=big_content,
        )
        # Should have multiple data pushes (3 chunks for 1200 bytes)
        items = script.script
        data_pushes = [i for i in items if isinstance(i, str) and len(i) > 10 and i not in (
            "OP_CHECKSIG", "OP_0", "OP_IF", "OP_ENDIF", "OP_1"
        )]
        # At minimum: pubkey, ord hex, content_type, 3 data chunks
        assert len(data_pushes) >= 5


class TestFeeEstimation:
    def test_zero_content(self):
        fee = estimate_reveal_fee(0, 10.0)
        assert fee == round(105 * 10.0)

    def test_larger_content_costs_more(self):
        small = estimate_reveal_fee(100, 10.0)
        large = estimate_reveal_fee(10_000, 10.0)
        assert large > small


# ===========================================================================
# Unit tests — Slipstream API client (mocked HTTP)
# ===========================================================================

class TestSlipstreamClient:

    @responses.activate
    def test_get_system_info(self):
        responses.add(
            responses.GET,
            f"{BASE}/api/system",
            json={"version": "0.1.0-beta", "chain_name": "mainnet", "block_height": 850000, "fee_rate_floor": 1.0},
        )
        client = make_client()
        result = client.get_system_info()
        assert result["chain_name"] == "mainnet"
        assert result["block_height"] == 850000

    @responses.activate
    def test_get_rates(self):
        responses.add(
            responses.GET,
            f"{BASE}/api/rates",
            json={"low": 2.0, "medium": 10.0, "high": 50.0},
        )
        client = make_client()
        rates = client.get_rates()
        assert rates["medium"] == 10.0

    @responses.activate
    def test_get_rates_passes_client_code(self):
        responses.add(
            responses.GET,
            f"{BASE}/api/rates",
            json={"low": 1.5, "medium": 5.0, "high": 20.0},
        )
        client = make_client(client_code="TEST123")
        client.get_rates()
        assert "client_code=TEST123" in responses.calls[0].request.url

    @responses.activate
    def test_submit_transaction_success(self):
        responses.add(
            responses.POST,
            f"{BASE}/api/transactions",
            json={"status": "accepted", "txid": "abc123", "message": "OK"},
        )
        client = make_client()
        result = client.submit_transaction("0200000001dead...")
        assert result["status"] == "accepted"

    @responses.activate
    def test_submit_transaction_error(self):
        responses.add(
            responses.POST,
            f"{BASE}/api/transactions",
            json={"error": "invalid transaction"},
            status=400,
        )
        client = make_client()
        with pytest.raises(SlipstreamError) as exc_info:
            client.submit_transaction("badtx")
        assert "400" in str(exc_info.value)

    @responses.activate
    def test_submit_package(self):
        responses.add(
            responses.POST,
            f"{BASE}/api/transactions/packages",
            json={"results": {"tx1": "accepted", "tx2": "accepted"}},
        )
        client = make_client()
        result = client.submit_package(["hex1", "hex2"])
        assert "results" in result

    def test_submit_package_size_validation(self):
        client = make_client()
        with pytest.raises(ValueError, match="2-25"):
            client.submit_package(["onlyone"])
        with pytest.raises(ValueError, match="2-25"):
            client.submit_package(["x"] * 26)

    @responses.activate
    def test_get_transaction_status(self):
        txid = "abc" * 21 + "d"
        responses.add(
            responses.GET,
            f"{BASE}/api/transactions/status",
            json={"tx_id": txid, "status": "confirmed", "confirmations": 3},
        )
        client = make_client()
        result = client.get_transaction_status(txid)
        assert result["status"] == "confirmed"

    @responses.activate
    def test_test_transaction(self):
        responses.add(
            responses.POST,
            f"{BASE}/api/mempool/tests",
            json={"valid": True, "results": []},
        )
        client = make_client()
        result = client.test_transaction(["deadbeef"])
        assert result["valid"] is True

    @responses.activate
    def test_client_code_in_transaction_payload(self):
        responses.add(
            responses.POST,
            f"{BASE}/api/transactions",
            json={"status": "accepted"},
        )
        client = make_client(client_code="MYCODE")
        client.submit_transaction("hexdata")
        import json as _json
        body = _json.loads(responses.calls[0].request.body)
        assert body.get("client_code") == "MYCODE"

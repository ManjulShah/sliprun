"""
sliprun — Bitcoin inscription CLI via Marathon Slipstream API.

Commands:
  status          Show Slipstream API health and current fee rates
  rates           Display current fee rates
  inscribe        Create an Ordinal inscription (commit + reveal)
  op-return       Embed up to 80 bytes of data via OP_RETURN
  send            Send BTC using Electrum wallet
  tx-status       Query a transaction status on Slipstream
  test            Dry-run: validate raw transaction(s) without broadcasting
  wallet-info     Show Electrum wallet balance and UTXOs
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table
from rich import print as rprint

from sliprun.api.slipstream import SlipstreamClient, SlipstreamError
from sliprun.config import config
from sliprun.wallet.electrum import ElectrumClient, ElectrumError

console = Console()


def _slipstream() -> SlipstreamClient:
    return SlipstreamClient(
        base_url=config.slipstream_base_url,
        client_code=config.slipstream_client_code,
    )


def _electrum() -> ElectrumClient:
    return ElectrumClient(
        host=config.electrum_host,
        port=config.electrum_port,
        user=config.electrum_user,
        password=config.electrum_password,
    )


def _get_wif_key(privkey: str | None, address: str | None, wallet_password: str) -> str:
    """Resolve a WIF private key — from CLI arg or from Electrum."""
    if privkey:
        return privkey
    if address:
        console.print(f"[yellow]Exporting private key for {address} from Electrum...[/yellow]")
        keys = _electrum().get_private_keys(address, wallet_password)
        return keys[0]
    raise click.UsageError(
        "Provide either --privkey (WIF) or --address to export the key from Electrum."
    )


def _pick_utxo(min_sats: int) -> dict:
    """Pick the best UTXO from Electrum with at least `min_sats`."""
    ec = _electrum()
    utxos = ec.utxos_above(min_sats)
    if not utxos:
        raise click.ClickException(
            f"No UTXOs with ≥ {min_sats} sat found in Electrum wallet. "
            "Fund your wallet and try again."
        )
    utxo = utxos[0]
    console.print(
        f"[dim]Using UTXO: {utxo['prevout_hash'][:12]}...:{utxo['prevout_n']}  "
        f"({utxo['satoshis']:,} sat)[/dim]"
    )
    return utxo


# ===========================================================================
# CLI group
# ===========================================================================

@click.group()
@click.version_option(version="0.1.0", prog_name="sliprun")
def main():
    """sliprun — BTC transactions & inscriptions via Marathon Slipstream."""


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@main.command()
def status():
    """Show Slipstream API status, block height, and fee floor."""
    ss = _slipstream()
    try:
        info = ss.get_system_info()
        rates = ss.get_rates()
    except SlipstreamError as exc:
        console.print(f"[red]Slipstream error: {exc}[/red]")
        sys.exit(1)

    table = Table(title="Slipstream Status", show_header=False)
    table.add_column("Key", style="cyan")
    table.add_column("Value")

    for k, v in info.items():
        table.add_row(str(k), str(v))

    console.print(table)
    console.print("\n[bold]Fee Rates[/bold]")
    rprint(json.dumps(rates, indent=2))


# ---------------------------------------------------------------------------
# rates
# ---------------------------------------------------------------------------

@main.command()
def rates():
    """Display current fee rates (sat/vByte) from Slipstream."""
    try:
        data = _slipstream().get_rates()
    except SlipstreamError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    rprint(json.dumps(data, indent=2))


# ---------------------------------------------------------------------------
# inscribe
# ---------------------------------------------------------------------------

@main.command()
@click.argument("file", type=click.Path(exists=True))
@click.option("--content-type", "-c", default=None, help="MIME type (auto-detected if omitted)")
@click.option("--recipient", "-r", default=None, help="Destination address for the inscription")
@click.option("--fee-rate", "-f", default=None, type=float, help="Fee rate in sat/vByte (uses Slipstream medium rate if omitted)")
@click.option("--privkey", "-k", default=None, envvar="BITCOIN_WIF_KEY", help="WIF private key for signing")
@click.option("--address", "-a", default=None, help="Wallet address to export key from Electrum")
@click.option("--wallet-password", default="", help="Electrum wallet password (if encrypted)")
@click.option("--change-address", default=None, help="Change address (defaults to signing address)")
@click.option("--test", is_flag=True, help="Validate without broadcasting")
@click.option("--json-output", is_flag=True, help="Output raw JSON result")
def inscribe(
    file, content_type, recipient, fee_rate, privkey, address,
    wallet_password, change_address, test, json_output
):
    """
    Inscribe FILE as an Ordinal on Bitcoin.

    Creates a commit+reveal transaction pair and submits it to Slipstream as
    a package.  The inscription follows the Ordinals protocol (BIP-341
    tapscript, single-leaf tree).

    \b
    Examples:
      # Inscribe an image using Electrum key for bc1q...
      sliprun inscribe art.png --address bc1q... --recipient bc1q...

      # Inscribe with an explicit WIF key and fee rate
      sliprun inscribe poem.txt --privkey L1... --fee-rate 15 --recipient bc1p...

      # Dry-run (validate only, no broadcast)
      sliprun inscribe logo.svg --privkey L1... --test
    """
    from sliprun.bitcoin.inscription import (
        InscriptionBuilder,
        InscriptionError,
        OrdinalInscription,
    )

    # ---- resolve fee rate ----
    ss = _slipstream()
    if fee_rate is None:
        try:
            r = ss.get_rates()
            fee_rate = float(r.get("medium", r.get("normal", 10.0)))
            console.print(f"[dim]Auto fee rate: {fee_rate} sat/vByte[/dim]")
        except SlipstreamError:
            fee_rate = 10.0
            console.print(f"[dim]Could not fetch rates, using {fee_rate} sat/vByte[/dim]")

    # ---- load inscription content ----
    path = Path(file)
    content = path.read_bytes()
    if content_type is None:
        import mimetypes
        guessed, _ = mimetypes.guess_type(str(path))
        content_type = guessed or "application/octet-stream"

    console.print(
        f"[bold]Inscribing[/bold]: {path.name}  "
        f"({len(content):,} bytes, {content_type})"
    )

    # ---- resolve signing key ----
    try:
        wif = _get_wif_key(privkey, address, wallet_password)
    except (ElectrumError, click.UsageError) as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    # ---- pick funding UTXO ----
    from sliprun.bitcoin.transaction import estimate_commit_fee, estimate_reveal_fee
    min_needed = (
        estimate_commit_fee(fee_rate)
        + estimate_reveal_fee(len(content), fee_rate)
        + 1000  # buffer
    )
    try:
        utxo = _pick_utxo(min_needed)
    except (ElectrumError, click.ClickException) as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    # ---- resolve recipient ----
    if recipient is None:
        try:
            recipient = _electrum().get_unused_address()
            console.print(f"[dim]Recipient: {recipient}[/dim]")
        except ElectrumError as exc:
            console.print(f"[red]Could not get address from Electrum: {exc}[/red]")
            sys.exit(1)

    # ---- build commit+reveal ----
    try:
        builder = InscriptionBuilder(wif, network=config.network)
        pair = builder.build(
            inscription=OrdinalInscription(content_type, content),
            funding_utxo=utxo,
            recipient=recipient,
            fee_rate=fee_rate,
            change_address=change_address,
        )
    except (InscriptionError, Exception) as exc:
        console.print(f"[red]Build error: {exc}[/red]")
        sys.exit(1)

    console.print(f"[green]Commit txid:[/green]  {pair.commit_txid}")
    console.print(f"[green]Inscription address:[/green] {pair.inscription_address}")

    if test:
        # Validate only
        try:
            result = ss.test_transaction([pair.commit_tx_hex, pair.reveal_tx_hex])
            console.print("[yellow]TEST MODE — not broadcast[/yellow]")
            if json_output:
                click.echo(json.dumps(result, indent=2))
            else:
                rprint(result)
        except SlipstreamError as exc:
            console.print(f"[red]Validation error: {exc}[/red]")
            sys.exit(1)
        return

    # ---- submit as package ----
    try:
        result = ss.submit_package([pair.commit_tx_hex, pair.reveal_tx_hex])
    except SlipstreamError as exc:
        console.print(f"[red]Slipstream submission error: {exc}[/red]")
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        console.print("[bold green]Successfully submitted to Slipstream![/bold green]")
        rprint(result)


# ---------------------------------------------------------------------------
# op-return
# ---------------------------------------------------------------------------

@main.command("op-return")
@click.argument("data")
@click.option("--hex-data", is_flag=True, help="Treat DATA as hex string")
@click.option("--fee-rate", "-f", default=5.0, type=float, help="Fee rate in sat/vByte")
@click.option("--privkey", "-k", default=None, envvar="BITCOIN_WIF_KEY", help="WIF private key")
@click.option("--address", "-a", default=None, help="Wallet address to export key from Electrum")
@click.option("--wallet-password", default="", help="Electrum wallet password")
@click.option("--change-address", default=None, help="Change address")
@click.option("--test", is_flag=True, help="Validate without broadcasting")
def op_return(data, hex_data, fee_rate, privkey, address, wallet_password, change_address, test):
    """
    Embed up to 80 bytes of arbitrary data in an OP_RETURN output.

    DATA can be a UTF-8 string or hex bytes (with --hex-data).

    \b
    Examples:
      sliprun op-return "Hello, Bitcoin!" --privkey L1...
      sliprun op-return deadbeef --hex-data --privkey L1...
    """
    from sliprun.bitcoin.inscription import InscriptionError, build_op_return_tx

    raw = bytes.fromhex(data) if hex_data else data.encode()
    if len(raw) > 80:
        raise click.UsageError(f"Data is {len(raw)} bytes; OP_RETURN max is 80.")

    try:
        wif = _get_wif_key(privkey, address, wallet_password)
    except (ElectrumError, click.UsageError) as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    min_needed = round(170 * fee_rate) + 1000
    try:
        utxo = _pick_utxo(min_needed)
    except (ElectrumError, click.ClickException) as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    change = change_address
    if change is None:
        try:
            change = _electrum().get_unused_address()
        except ElectrumError as exc:
            console.print(f"[red]{exc}[/red]")
            sys.exit(1)

    try:
        tx_hex = build_op_return_tx(
            wif_private_key=wif,
            funding_utxo=utxo,
            data=raw,
            change_address=change,
            fee_rate=fee_rate,
            network=config.network,
        )
    except (InscriptionError, Exception) as exc:
        console.print(f"[red]Build error: {exc}[/red]")
        sys.exit(1)

    ss = _slipstream()

    if test:
        result = ss.test_transaction([tx_hex])
        console.print("[yellow]TEST MODE — not broadcast[/yellow]")
        rprint(result)
        return

    result = ss.submit_transaction(tx_hex)
    console.print("[bold green]Submitted![/bold green]")
    rprint(result)


# ---------------------------------------------------------------------------
# send
# ---------------------------------------------------------------------------

@main.command()
@click.argument("address")
@click.argument("amount", type=float)
@click.option("--fee-rate", "-f", default=None, type=float, help="Fee rate sat/vByte")
@click.option("--wallet-password", default="", help="Electrum wallet password")
@click.option("--test", is_flag=True, help="Build and validate without broadcasting")
@click.option("--json-output", is_flag=True)
def send(address, amount, fee_rate, wallet_password, test, json_output):
    """
    Send AMOUNT BTC to ADDRESS via Electrum signing + Slipstream broadcast.

    \b
    Examples:
      sliprun send bc1q... 0.001
      sliprun send bc1p... 0.005 --fee-rate 20 --test
    """
    ec = _electrum()
    ss = _slipstream()

    if fee_rate is None:
        try:
            r = ss.get_rates()
            fee_rate = float(r.get("medium", r.get("normal", 5.0)))
        except SlipstreamError:
            fee_rate = 5.0

    try:
        unsigned_hex = ec.payto(address, amount, fee_rate=fee_rate, unsigned=True)
    except ElectrumError as exc:
        console.print(f"[red]Electrum error: {exc}[/red]")
        sys.exit(1)

    try:
        signed_hex = ec.sign_transaction(unsigned_hex, password=wallet_password)
    except ElectrumError as exc:
        console.print(f"[red]Signing error: {exc}[/red]")
        sys.exit(1)

    if test:
        try:
            result = ss.test_transaction([signed_hex])
            console.print("[yellow]TEST MODE — not broadcast[/yellow]")
            click.echo(json.dumps(result, indent=2) if json_output else str(result))
        except SlipstreamError as exc:
            console.print(f"[red]{exc}[/red]")
            sys.exit(1)
        return

    try:
        result = ss.submit_transaction(signed_hex)
    except SlipstreamError as exc:
        console.print(f"[red]Slipstream error: {exc}[/red]")
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        console.print("[bold green]Transaction submitted![/bold green]")
        rprint(result)


# ---------------------------------------------------------------------------
# tx-status
# ---------------------------------------------------------------------------

@main.command("tx-status")
@click.argument("txid")
@click.option("--json-output", is_flag=True)
def tx_status(txid, json_output):
    """Query the status of a transaction on Slipstream."""
    try:
        result = _slipstream().get_transaction_status(txid)
    except SlipstreamError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        rprint(result)


# ---------------------------------------------------------------------------
# test
# ---------------------------------------------------------------------------

@main.command("test")
@click.argument("tx_hexes", nargs=-1, required=True)
def test_tx(tx_hexes):
    """
    Validate raw transaction hex(es) against Slipstream's mempool rules.

    Accepts one or more hex strings as arguments, or pipe via stdin.

    \b
    Examples:
      sliprun test 0200000001abcd...
      sliprun test commit_hex reveal_hex
    """
    try:
        result = _slipstream().test_transaction(list(tx_hexes))
    except SlipstreamError as exc:
        console.print(f"[red]{exc}[/red]")
        sys.exit(1)
    rprint(result)


# ---------------------------------------------------------------------------
# wallet-info
# ---------------------------------------------------------------------------

@main.command("wallet-info")
@click.option("--show-utxos", is_flag=True, help="List all UTXOs")
def wallet_info(show_utxos):
    """Show Electrum wallet balance and optionally list UTXOs."""
    ec = _electrum()

    try:
        bal = ec.get_balance()
    except ElectrumError as exc:
        console.print(f"[red]Electrum error: {exc}[/red]")
        sys.exit(1)

    table = Table(title="Wallet Balance", show_header=False)
    table.add_column("", style="cyan")
    table.add_column("")
    for k, v in bal.items():
        table.add_row(k, str(v))
    console.print(table)

    if show_utxos:
        utxos = ec.list_unspent()
        if not utxos:
            console.print("[dim]No UTXOs found.[/dim]")
            return
        t = Table(title="UTXOs")
        t.add_column("txid:vout", style="dim")
        t.add_column("value (BTC)")
        t.add_column("satoshis", justify="right")
        t.add_column("height", justify="right")
        for u in utxos:
            sats = round(float(u.get("value", 0)) * 1e8)
            t.add_row(
                f"{u['prevout_hash'][:16]}...:{u['prevout_n']}",
                str(u.get("value", "?")),
                f"{sats:,}",
                str(u.get("height", "?")),
            )
        console.print(t)

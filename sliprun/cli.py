"""
sliprun — Bitcoin inscription CLI via Marathon Slipstream API.

Commands:
  status          Show Slipstream API health and current fee rates
  rates           Display current fee rates
  inscribe        Create an Ordinal inscription (commit + reveal)
  op-return       Embed up to 80 bytes of data via OP_RETURN
  send            Send BTC using Electrum wallet
  bump-fee        Replace a stuck transaction with a higher-fee version (RBF)
  tx-status       Query a transaction status on Slipstream
  test            Dry-run: validate raw transaction(s) without broadcasting
  wallet-info     Show Electrum wallet balance and UTXOs
  psbt create     Build an unsigned PSBT
  psbt sign       Sign a PSBT with a local key or Electrum
  psbt decode     Display PSBT contents
  psbt finalize   Extract signed tx hex and optionally broadcast

Global flag:
  --network mainnet|testnet|signet  Override BITCOIN_NETWORK env var
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
        base_url=config.slipstream_url_for(),
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
@click.option(
    "--network",
    type=click.Choice(["mainnet", "testnet", "signet"]),
    default=None,
    envvar="BITCOIN_NETWORK",
    help="Bitcoin network (overrides BITCOIN_NETWORK env var).",
)
def main(network: str | None):
    """sliprun — BTC transactions & inscriptions via Marathon Slipstream."""
    if network:
        config.network = network


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


# ===========================================================================
# bump-fee
# ===========================================================================

@main.command("bump-fee")
@click.argument("txid")
@click.option("--fee-rate", "-f", required=True, type=float, help="New fee rate in sat/vByte")
@click.option("--privkey", "-k", default=None, envvar="BITCOIN_WIF_KEY", help="WIF key (manual mode)")
@click.option("--address", "-a", default=None, help="Wallet address to export key from Electrum")
@click.option("--wallet-password", default="", help="Electrum wallet password")
@click.option("--raw-tx", default=None, help="Original raw tx hex (manual mode, no Electrum)")
@click.option("--change-vout", default=None, type=int, help="Change output index (manual mode)")
@click.option("--test", is_flag=True, help="Validate without broadcasting")
@click.option("--json-output", is_flag=True)
def bump_fee(txid, fee_rate, privkey, address, wallet_password, raw_tx, change_vout, test, json_output):
    """
    Replace a stuck unconfirmed transaction with a higher-fee version (RBF).

    Electrum mode (default): Electrum rebuilds and re-signs the transaction.
    The wallet must contain the original TX and its inputs must signal RBF.

    Manual mode (--raw-tx + --privkey + --change-vout): Re-signs locally
    without Electrum. Useful for P2WPKH transactions only.

    \b
    Examples:
      # Electrum mode (recommended)
      sliprun bump-fee abc123... --fee-rate 25

      # Manual mode
      sliprun bump-fee abc123... --fee-rate 25 \\
          --privkey L1... --raw-tx 0200... --change-vout 1

      # Dry-run
      sliprun bump-fee abc123... --fee-rate 20 --test
    """
    from sliprun.bitcoin.feebump import FeeBumpError, bump_fee_electrum, bump_fee_manual

    ss = _slipstream()

    if raw_tx is not None:
        # ---- Manual mode ----
        if change_vout is None:
            raise click.UsageError("--change-vout is required in manual mode (--raw-tx).")
        try:
            wif = _get_wif_key(privkey, address, wallet_password)
        except (ElectrumError, click.UsageError) as exc:
            console.print(f"[red]{exc}[/red]")
            sys.exit(1)
        try:
            new_tx_hex = bump_fee_manual(
                raw_tx_hex=raw_tx,
                wif_private_key=wif,
                change_vout=change_vout,
                new_fee_rate=fee_rate,
                network=config.network,
            )
        except (FeeBumpError, Exception) as exc:
            console.print(f"[red]Fee bump error: {exc}[/red]")
            sys.exit(1)
    else:
        # ---- Electrum mode ----
        try:
            new_tx_hex = bump_fee_electrum(_electrum(), txid, fee_rate)
        except ElectrumError as exc:
            console.print(f"[red]Electrum error: {exc}[/red]")
            sys.exit(1)
        except Exception as exc:
            console.print(f"[red]Fee bump error: {exc}[/red]")
            sys.exit(1)

    if test:
        try:
            result = ss.test_transaction([new_tx_hex])
            console.print("[yellow]TEST MODE — not broadcast[/yellow]")
            click.echo(json.dumps(result, indent=2) if json_output else str(result))
        except SlipstreamError as exc:
            console.print(f"[red]{exc}[/red]")
            sys.exit(1)
        return

    try:
        result = ss.submit_transaction(new_tx_hex)
    except SlipstreamError as exc:
        console.print(f"[red]Slipstream error: {exc}[/red]")
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(result, indent=2))
    else:
        console.print("[bold green]Replacement transaction submitted![/bold green]")
        rprint(result)


# ===========================================================================
# psbt group
# ===========================================================================

@main.group()
def psbt():
    """Create, sign, decode, and finalize Partially Signed Bitcoin Transactions."""


# ---------------------------------------------------------------------------
# psbt create
# ---------------------------------------------------------------------------

@psbt.command("create")
@click.option("--to", "recipient", required=True, help="Destination Bitcoin address")
@click.option("--amount", required=True, type=float, help="Amount to send in BTC")
@click.option("--fee-rate", "-f", default=None, type=float, help="Fee rate sat/vByte")
@click.option("--privkey", "-k", default=None, envvar="BITCOIN_WIF_KEY", help="WIF key (also used to find change address)")
@click.option("--address", "-a", default=None, help="Wallet address to export key from Electrum")
@click.option("--wallet-password", default="", help="Electrum wallet password")
@click.option("--change-address", default=None, help="Change address (default: Electrum unused address)")
def psbt_create(recipient, amount, fee_rate, privkey, address, wallet_password, change_address):
    """
    Build an unsigned PSBT funded from the Electrum wallet.

    Prints the base64 PSBT to stdout — pipe it to `psbt sign` or save to a file.

    \b
    Examples:
      sliprun psbt create --to bc1q... --amount 0.001
      sliprun psbt create --to bc1p... --amount 0.005 --fee-rate 15
    """
    from sliprun.bitcoin.psbt_ops import PSBTError, create_psbt

    ss = _slipstream()
    if fee_rate is None:
        try:
            r = ss.get_rates()
            fee_rate = float(r.get("medium", r.get("normal", 10.0)))
        except SlipstreamError:
            fee_rate = 10.0

    try:
        ec = _electrum()
        utxos = ec.utxos_above(1000)
        if not utxos:
            console.print("[red]No UTXOs found in Electrum wallet.[/red]")
            sys.exit(1)

        if change_address is None:
            change_address = ec.get_unused_address()
    except ElectrumError as exc:
        console.print(f"[red]Electrum error: {exc}[/red]")
        sys.exit(1)

    try:
        psbt_b64 = create_psbt(
            utxos=utxos,
            recipient=recipient,
            amount_btc=amount,
            change_address=change_address,
            fee_rate=fee_rate,
            network=config.network,
        )
    except (PSBTError, Exception) as exc:
        console.print(f"[red]PSBT error: {exc}[/red]", err=True)
        sys.exit(1)

    click.echo(psbt_b64)


# ---------------------------------------------------------------------------
# psbt sign
# ---------------------------------------------------------------------------

@psbt.command("sign")
@click.argument("psbt_b64")
@click.option("--privkey", "-k", default=None, envvar="BITCOIN_WIF_KEY", help="WIF private key")
@click.option("--address", "-a", default=None, help="Wallet address to export key from Electrum")
@click.option("--wallet-password", default="", help="Electrum wallet password")
@click.option("--electrum", "use_electrum", is_flag=True, help="Use Electrum wallet to sign")
def psbt_sign(psbt_b64, privkey, address, wallet_password, use_electrum):
    """
    Sign a PSBT.  Pass `-` to read from stdin.

    Prints the signed base64 PSBT to stdout.

    \b
    Examples:
      sliprun psbt sign <base64> --privkey L1...
      sliprun psbt create --to bc1q... --amount 0.001 | sliprun psbt sign - --electrum
    """
    from sliprun.bitcoin.psbt_ops import PSBTError, sign_psbt, sign_psbt_electrum

    if psbt_b64 == "-":
        import sys as _sys
        psbt_b64 = _sys.stdin.read().strip()

    if use_electrum:
        try:
            result = sign_psbt_electrum(psbt_b64, _electrum())
        except (ElectrumError, Exception) as exc:
            console.print(f"[red]Electrum signing error: {exc}[/red]", err=True)
            sys.exit(1)
    else:
        try:
            wif = _get_wif_key(privkey, address, wallet_password)
        except (ElectrumError, click.UsageError) as exc:
            console.print(f"[red]{exc}[/red]", err=True)
            sys.exit(1)
        try:
            result = sign_psbt(psbt_b64, wif, network=config.network)
        except (PSBTError, Exception) as exc:
            console.print(f"[red]Signing error: {exc}[/red]", err=True)
            sys.exit(1)

    click.echo(result)


# ---------------------------------------------------------------------------
# psbt decode
# ---------------------------------------------------------------------------

@psbt.command("decode")
@click.argument("psbt_b64")
@click.option("--json-output", is_flag=True, help="Output raw JSON")
def psbt_decode(psbt_b64, json_output):
    """
    Display the contents of a PSBT in human-readable form.

    Pass `-` to read from stdin.

    \b
    Examples:
      sliprun psbt decode <base64>
      cat unsigned.psbt | sliprun psbt decode -
    """
    from sliprun.bitcoin.psbt_ops import PSBTError, decode_psbt

    if psbt_b64 == "-":
        import sys as _sys
        psbt_b64 = _sys.stdin.read().strip()

    try:
        info = decode_psbt(psbt_b64, network=config.network)
    except (PSBTError, Exception) as exc:
        console.print(f"[red]Decode error: {exc}[/red]")
        sys.exit(1)

    if json_output:
        click.echo(json.dumps(info, indent=2))
        return

    console.print(f"[bold]PSBT[/bold]  version={info['version']}  "
                  f"inputs={info['input_count']}  outputs={info['output_count']}  "
                  f"complete={'[green]yes[/green]' if info['complete'] else '[yellow]no[/yellow]'}")

    t = Table(title="Inputs")
    t.add_column("idx", justify="right")
    t.add_column("utxo amount (sat)", justify="right")
    t.add_column("sigs", justify="right")
    t.add_column("finalized")
    for inp in info["inputs"]:
        t.add_row(
            str(inp["index"]),
            f"{inp.get('utxo_amount_sat', '?'):,}" if "utxo_amount_sat" in inp else "?",
            str(inp.get("partial_sigs", 0)),
            "[green]yes[/green]" if inp.get("finalized") else "no",
        )
    console.print(t)

    t2 = Table(title="Outputs")
    t2.add_column("idx", justify="right")
    t2.add_column("amount (sat)", justify="right")
    t2.add_column("script (partial)")
    for out in info["outputs"]:
        t2.add_row(str(out["index"]), f"{out['amount_sat']:,}", out["script"][:32] + "...")
    console.print(t2)


# ---------------------------------------------------------------------------
# psbt finalize
# ---------------------------------------------------------------------------

@psbt.command("finalize")
@click.argument("psbt_b64")
@click.option("--broadcast", is_flag=True, help="Submit the finalized tx to Slipstream")
@click.option("--test", is_flag=True, help="Validate without broadcasting (implies --broadcast dry-run)")
@click.option("--json-output", is_flag=True)
def psbt_finalize(psbt_b64, broadcast, test, json_output):
    """
    Finalize a fully-signed PSBT and extract the signed transaction hex.

    Pass `-` to read from stdin.  Use --broadcast to send directly to Slipstream.

    \b
    Examples:
      sliprun psbt finalize <base64>
      sliprun psbt finalize <base64> --broadcast
      cat signed.psbt | sliprun psbt finalize - --broadcast --test
    """
    from sliprun.bitcoin.psbt_ops import PSBTError, finalize_psbt

    if psbt_b64 == "-":
        import sys as _sys
        psbt_b64 = _sys.stdin.read().strip()

    try:
        tx_hex = finalize_psbt(psbt_b64, network=config.network)
    except (PSBTError, Exception) as exc:
        console.print(f"[red]Finalize error: {exc}[/red]")
        sys.exit(1)

    console.print(f"[dim]Signed tx hex:[/dim] {tx_hex[:32]}...", err=True)

    if test:
        try:
            result = _slipstream().test_transaction([tx_hex])
            console.print("[yellow]TEST MODE — not broadcast[/yellow]", err=True)
            click.echo(json.dumps(result, indent=2) if json_output else tx_hex)
        except SlipstreamError as exc:
            console.print(f"[red]{exc}[/red]")
            sys.exit(1)
        return

    if broadcast:
        try:
            result = _slipstream().submit_transaction(tx_hex)
        except SlipstreamError as exc:
            console.print(f"[red]Slipstream error: {exc}[/red]")
            sys.exit(1)
        if json_output:
            click.echo(json.dumps(result, indent=2))
        else:
            console.print("[bold green]Transaction submitted![/bold green]")
            rprint(result)
    else:
        click.echo(tx_hex)

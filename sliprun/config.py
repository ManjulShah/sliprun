import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path.cwd() / ".env")


@dataclass
class Config:
    # Marathon Slipstream API
    slipstream_base_url: str = field(
        default_factory=lambda: os.getenv("SLIPSTREAM_BASE_URL", "https://slipstream.mara.com")
    )
    slipstream_client_code: str | None = field(
        default_factory=lambda: os.getenv("SLIPSTREAM_CLIENT_CODE") or None
    )

    # Electrum daemon
    electrum_host: str = field(
        default_factory=lambda: os.getenv("ELECTRUM_HOST", "127.0.0.1")
    )
    electrum_port: int = field(
        default_factory=lambda: int(os.getenv("ELECTRUM_PORT", "7777"))
    )
    electrum_user: str = field(
        default_factory=lambda: os.getenv("ELECTRUM_USER", "user")
    )
    electrum_password: str = field(
        default_factory=lambda: os.getenv("ELECTRUM_PASSWORD", "password")
    )

    # Bitcoin network
    network: str = field(
        default_factory=lambda: os.getenv("BITCOIN_NETWORK", "mainnet")
    )


config = Config()

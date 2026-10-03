from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DEMO_API_KEY = "demo-only-change-me"

DEFAULT_POLICY = {
    "tempMinC": 2.0,
    "tempMaxC": 8.0,
    "maxExcursionMinutes": 15,
    "shockLimitG": 2.5,
    "offlineGapMinutes": 20,
    "probeDisagreementC": 3.0,
}
POLICY_DISCLAIMER = (
    "Demo policy values chosen for this prototype. They are not universal vaccine safety "
    "limits and not a regulatory certification."
)


@dataclass(frozen=True)
class Config:
    data_dir: Path
    db_path: Path
    batch_size: int
    api_key: str
    cors_origins: tuple
    default_policy: dict
    deployment_path: Path = ROOT / "blockchain" / "deployment.json"
    artifacts_dir: Path = ROOT / "blockchain" / "artifacts"
    network_path: Path = ROOT / "blockchain" / "nodes" / "network.json"
    verifier_url: str = "http://127.0.0.1:8100"
    sync_interval: float = 0.0
    chain_enabled: bool = True
    gas_price: int | None = None
    rpc_url: str | None = None

    @staticmethod
    def from_env() -> "Config":
        data_dir = Path(os.environ.get("SMARTSEAL_DATA_DIR", "data")).resolve()
        policy = dict(DEFAULT_POLICY)
        for key in policy:
            env = os.environ.get("SMARTSEAL_POLICY_" + key.upper())
            if env is not None:
                policy[key] = type(policy[key])(float(env))
        return Config(
            data_dir=data_dir,
            db_path=Path(os.environ.get("SMARTSEAL_DB", data_dir / "smartseal.db")),
            batch_size=int(os.environ.get("SMARTSEAL_BATCH_SIZE", "4")),
            api_key=os.environ.get("SMARTSEAL_API_KEY", DEMO_API_KEY),
            cors_origins=tuple(os.environ.get("SMARTSEAL_CORS_ORIGINS", "*").split(",")),
            default_policy=policy,
            deployment_path=Path(os.environ.get("SMARTSEAL_DEPLOYMENT", ROOT / "blockchain" / "deployment.json")),
            artifacts_dir=Path(os.environ.get("SMARTSEAL_ARTIFACTS", ROOT / "blockchain" / "artifacts")),
            network_path=Path(os.environ.get("SMARTSEAL_NETWORK", ROOT / "blockchain" / "nodes" / "network.json")),
            verifier_url=os.environ.get("SMARTSEAL_VERIFIER_URL", "http://127.0.0.1:8100"),
            sync_interval=float(os.environ.get("SMARTSEAL_SYNC_INTERVAL", "5")),
            chain_enabled=os.environ.get("SMARTSEAL_CHAIN", "on").lower() != "off",
            gas_price=None if os.environ.get("SMARTSEAL_GAS_PRICE", "auto") == "auto" else int(os.environ["SMARTSEAL_GAS_PRICE"]),
            rpc_url=os.environ.get("SMARTSEAL_RPC_URL"),
        )

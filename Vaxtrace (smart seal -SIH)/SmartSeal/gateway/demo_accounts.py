from __future__ import annotations

import os

from eth_account import Account
from eth_utils import keccak

ROLES = ("ADMIN", "MANUFACTURER", "TRANSPORTER", "WAREHOUSE", "PHARMACY", "REGULATOR", "VERIFIER", "GATEWAY")


def demo_account(role: str):
    override = os.environ.get("SMARTSEAL_KEY_" + role)
    key = bytes.fromhex(override.removeprefix("0x")) if override else keccak(text=f"smartseal-demo-only::{role}")
    return Account.from_key(key)


def demo_accounts() -> dict:
    return {role: demo_account(role) for role in ROLES}

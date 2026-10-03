import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "gateway"))
from blockchain import CONTRACT_FILES, ROLE_ENUM, Deployment, load_artifact, make_w3, send_tx
from demo_accounts import demo_accounts

ARTIFACTS = HERE.parent / "artifacts"


def deploy_contract(w3, account, name, *args, gas_price=None):
    art = load_artifact(ARTIFACTS, name)
    c = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"])
    price = w3.eth.gas_price if gas_price is None else gas_price
    tx = c.constructor(*args).build_transaction({"from": account.address, "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                                                 "gas": 9_000_000, "gasPrice": price, "chainId": w3.eth.chain_id})
    receipt = w3.eth.wait_for_transaction_receipt(w3.eth.send_raw_transaction(account.sign_transaction(tx).raw_transaction), timeout=120)
    if receipt.status != 1:
        raise RuntimeError(f"deployment of {name} failed")
    return receipt.contractAddress


def deploy_all(w3, accounts=None, gas_price=None, rpc_url="") -> Deployment:
    accounts = accounts or demo_accounts()
    admin = accounts["ADMIN"]
    reg = deploy_contract(w3, admin, "SmartSealRegistry", gas_price=gas_price)
    addr = {"registry": reg,
            "anchor": deploy_contract(w3, admin, "BatchAnchor", reg, gas_price=gas_price),
            "custody": deploy_contract(w3, admin, "ShipmentCustody", reg, gas_price=gas_price),
            "verdict": deploy_contract(w3, admin, "VerdictRegistry", reg, gas_price=gas_price)}
    registry = w3.eth.contract(address=reg, abi=load_artifact(ARTIFACTS, "SmartSealRegistry")["abi"])
    for role, acct in accounts.items():
        if role != "ADMIN":
            send_tx(w3, admin, registry.functions.setRole(acct.address, ROLE_ENUM[role]), 500_000, gas_price)
    send_tx(w3, admin, registry.functions.setModule(addr["verdict"], True), 500_000, gas_price)
    return Deployment(chain_id=w3.eth.chain_id, addresses=addr, rpc_url=rpc_url,
                      participants={r: a.address for r, a in accounts.items()},
                      deployed_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--rpc", default="http://127.0.0.1:8545")
    ap.add_argument("--out", default=str(HERE.parent / "deployment.json"))
    a = ap.parse_args()
    w3 = make_w3(a.rpc)
    if not w3.is_connected():
        sys.exit(f"cannot reach {a.rpc}. Is the Besu network running? (see blockchain/README.md)")
    dep = deploy_all(w3, rpc_url=a.rpc)
    dep.save(a.out)
    print("deployed:", json.dumps(dep.addresses, indent=1), "\nwrote", a.out)

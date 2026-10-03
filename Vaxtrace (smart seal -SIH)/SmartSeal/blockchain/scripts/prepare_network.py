from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BC = HERE.parent
sys.path.insert(0, str(BC.parent / "gateway"))

NODES = [("Manufacturer", 8545), ("Transporter", 8546), ("Pharmacy", 8547), ("Regulator", 8548)]
SUBNET_PREFIX = "172.28.0."
CHAIN_ID = 2026
QBFT_MIX_HASH = "0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365"
IMAGE = os.environ.get("BESU_IMAGE", "hyperledger/besu:latest")


def build_config(chain_id: int = CHAIN_ID) -> dict:
    from demo_accounts import demo_accounts
    alloc = {a.address.removeprefix("0x").lower(): {"balance": "0xad78ebc5ac6200000"} for a in demo_accounts().values()}
    return {"genesis": {"config": {"chainId": chain_id, "berlinBlock": 0, "londonBlock": 0,
                                   "qbft": {"blockperiodseconds": 2, "epochlength": 30000, "requesttimeoutseconds": 4}},
                        "nonce": "0x0", "timestamp": "0x58ee40ba", "gasLimit": "0x1fffffffffffff", "difficulty": "0x1",
                        "mixHash": QBFT_MIX_HASH, "coinbase": "0x0000000000000000000000000000000000000000", "alloc": alloc},
            "blockchain": {"nodes": {"generate": True, "count": len(NODES)}}}


def run_generator(config_path: Path, out_dir: Path, image: str = IMAGE) -> None:
    if out_dir.exists():
        shutil.rmtree(out_dir)
    work = config_path.parent
    cmd = ["docker", "run", "--rm", "-v", f"{work}:/work", image, "operator", "generate-blockchain-config",
           f"--config-file=/work/{config_path.name}", f"--to=/work/{out_dir.name}", "--private-key-file-name=key"]
    print("running:", " ".join(cmd))
    subprocess.run(cmd, check=True)


def assemble(network_files: Path, bc_dir: Path = BC) -> dict:
    keys = sorted(p for p in (network_files / "keys").iterdir() if p.is_dir())
    if len(keys) != len(NODES):
        raise SystemExit(f"expected {len(NODES)} generated node keys, found {len(keys)}")
    (bc_dir / "genesis").mkdir(exist_ok=True)
    shutil.copyfile(network_files / "genesis.json", bc_dir / "genesis" / "genesis.json")
    nodes = []
    for i, (kdir, (name, port)) in enumerate(zip(keys, NODES), start=1):
        ndir = bc_dir / "nodes" / f"node{i}"
        if ndir.exists():
            shutil.rmtree(ndir)
        ndir.mkdir(parents=True)
        shutil.copyfile(kdir / "key", ndir / "key")
        pub = (kdir / "key.pub").read_text().strip().removeprefix("0x")
        ip = f"{SUBNET_PREFIX}{10 + i}"
        nodes.append({"name": name, "container": f"smartseal-node{i}", "address": kdir.name, "enode": f"enode://{pub}@{ip}:30303",
                      "ip": ip, "rpc": f"http://127.0.0.1:{port}"})
    (bc_dir / "nodes" / "network.json").write_text(json.dumps({"chainId": CHAIN_ID, "nodes": nodes,
                                                              "note": "DEMO ONLY keys. Node 1 is the bootnode."}, indent=1))
    (bc_dir / ".env").write_text(f"BOOTNODE_ENODE={nodes[0]['enode']}\nBESU_IMAGE={IMAGE}\n")
    return {"nodes": nodes}


if __name__ == "__main__":
    cfg = BC / "genesis" / "qbftConfigFile.json"
    cfg.parent.mkdir(exist_ok=True)
    cfg.write_text(json.dumps(build_config(), indent=1))
    out = cfg.parent / "networkFiles"
    run_generator(cfg, out)
    info = assemble(out)
    print("\nvalidators:")
    for n in info["nodes"]:
        print(f"  {n['name']:<13} {n['address']}  rpc {n['rpc']}")
    print("\nnext: docker compose up -d   (or start_network.bat)")

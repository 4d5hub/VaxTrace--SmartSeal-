import json
import shutil
import sys
from pathlib import Path

import pytest

BC = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BC / "scripts"))
import prepare_network as pn


def test_generated_config_matches_the_documented_qbft_format():
    c = pn.build_config()
    g = c["genesis"]
    assert g["config"]["chainId"] == 2026 and g["config"]["qbft"]["blockperiodseconds"] == 2 and g["config"]["londonBlock"] == 0
    assert g["mixHash"] == "0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365" and g["difficulty"] == "0x1"
    assert c["blockchain"]["nodes"] == {"generate": True, "count": 4}
    from demo_accounts import demo_accounts
    for a in demo_accounts().values():
        assert a.address.removeprefix("0x").lower() in g["alloc"]


def test_assemble_builds_node_folders_enodes_and_env(tmp_path):
    out = tmp_path / "networkFiles"
    (out / "keys").mkdir(parents=True)
    (out / "genesis.json").write_text('{"config": {}}')
    for i in range(4):
        d = out / "keys" / f"0x{i:040x}"
        d.mkdir()
        (d / "key").write_text(f"privkey{i}")
        (d / "key.pub").write_text("0x" + f"{i:x}" * 128)
    bc = tmp_path / "bc"
    bc.mkdir()
    info = pn.assemble(out, bc)
    assert [n["name"] for n in info["nodes"]] == ["Manufacturer", "Transporter", "Pharmacy", "Regulator"]
    assert (bc / "nodes" / "node3" / "key").read_text() == "privkey2" and (bc / "genesis" / "genesis.json").exists()
    env = (bc / ".env").read_text()
    assert env.splitlines()[0] == "BOOTNODE_ENODE=enode://" + "0" * 128 + "@172.28.0.11:30303"
    net = json.loads((bc / "nodes" / "network.json").read_text())
    assert net["nodes"][1]["rpc"] == "http://127.0.0.1:8546" and net["nodes"][3]["ip"] == "172.28.0.14"


def test_assemble_refuses_wrong_number_of_keys(tmp_path):
    (tmp_path / "keys" / "0xaa").mkdir(parents=True)
    with pytest.raises(SystemExit):
        pn.assemble(tmp_path, tmp_path)


def test_compose_file_is_consistent_with_the_network_plan():
    yaml = pytest.importorskip("yaml")
    c = yaml.safe_load((BC / "docker-compose.yml").read_text())
    svc = c["services"]
    assert sorted(svc) == ["node1", "node2", "node3", "node4"]
    ips = {s["networks"]["chain"]["ipv4_address"] for s in svc.values()}
    assert ips == {f"172.28.0.{n}" for n in (11, 12, 13, 14)}
    for i, (name, s) in enumerate(sorted(svc.items())):
        assert s["ports"] == [f"127.0.0.1:{8545 + i}:8545"]
        assert f"--p2p-host={s['networks']['chain']['ipv4_address']}" in s["command"]
        assert "--rpc-http-api=ETH,NET,QBFT,WEB3,TXPOOL,ADMIN" in s["command"]
        assert ("--bootnodes=${BOOTNODE_ENODE}" in s["command"]) == (name != "node1")

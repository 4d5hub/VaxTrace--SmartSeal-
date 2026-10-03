import sys
from pathlib import Path

import pytest
from web3 import EthereumTesterProvider, Web3

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "gateway"))
sys.path.insert(0, str(ROOT / "blockchain" / "scripts"))

from blockchain import ChainReader, LedgerRejected, load_artifact, send_tx
from demo_accounts import demo_accounts
from deploy import ARTIFACTS, deploy_all


class Chain:
    pass


@pytest.fixture(scope="module")
def _base():
    w3 = Web3(EthereumTesterProvider())
    accts = demo_accounts()
    for a in accts.values():
        w3.eth.send_transaction({"from": w3.eth.accounts[0], "to": a.address, "value": 10 ** 20})
    c = Chain()
    c.w3, c.accounts, c.tester = w3, accts, w3.provider.ethereum_tester
    c.dep = deploy_all(w3, accts, gas_price=None)
    return c


@pytest.fixture
def chain(_base):
    snap = _base.tester.take_snapshot()
    c = _base
    c.reader = ChainReader(c.w3, c.dep, ARTIFACTS)
    c.contract = lambda key: c.reader.c[key]

    def send(fn, role):
        return send_tx(c.w3, c.accounts[role], fn, gas=9_000_000, gas_price=None)

    def fails(fn, role):
        try:
            send(fn, role)
        except LedgerRejected as e:
            return e.code
        raise AssertionError("expected a revert")

    c.send, c.fails = send, fails
    yield c
    _base.tester.revert_to_snapshot(snap)

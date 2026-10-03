from __future__ import annotations

import importlib
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("gateway", "blockchain/scripts", "verifier"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.append(p)
if str(ROOT) not in sys.path:
    sys.path.append(str(ROOT))

from fastapi.testclient import TestClient
from web3 import EthereumTesterProvider, Web3

from app import create_app
from blockchain import BesuLedger, ChainReader, LedgerClient, LedgerUnavailable, send_tx
from config import Config, DEFAULT_POLICY
from demo_accounts import demo_accounts
from deploy import ARTIFACTS, deploy_all
from hashing import record_hash
from verification.engine import Verifier
from verification.evidence import CallableEvidence

KEY = {"X-API-Key": "stack-key"}
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Device:

    def __init__(self, seal="SEAL-A1", ship="SHP-001"):
        self.seal, self.ship, self.seq, self.prev = seal, ship, 0, "0"

    def record(self, t1=5.2, t2=5.3, shock=0.2, lid=False, light=False):
        self.seq += 1
        r = {"sealId": self.seal, "shipmentId": self.ship, "seq": self.seq,
             "timestamp": (BASE + timedelta(seconds=300 * self.seq)).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "temperature1": t1, "temperature2": t2, "shock": shock, "lid": lid, "light": light, "prevHash": self.prev}
        r["hash"] = record_hash(r)
        self.prev = r["hash"]
        return r


class SwitchLedger(LedgerClient):

    def __init__(self, inner):
        self.inner, self.down = inner, False

    def is_available(self):
        return not self.down and self.inner.is_available()

    def submit(self, kind, payload):
        if self.down:
            raise LedgerUnavailable("simulated outage")
        return self.inner.submit(kind, payload)

    def status(self):
        return {**self.inner.status(), "available": self.is_available()}


class Stack:
    def __init__(self, workdir=None, batch_size=4, rpc_url=None, provider=None, real_clock=False, verifier_url="http://127.0.0.1:8100"):
        self.tmp = Path(workdir or tempfile.mkdtemp(prefix="smartseal-"))
        self.live = rpc_url is not None
        self.w3 = Web3(Web3.HTTPProvider(rpc_url)) if self.live else Web3(provider or EthereumTesterProvider())
        self.tester = None if self.live else self.w3.provider.ethereum_tester
        self.accounts = demo_accounts()
        if not self.live:
            for a in self.accounts.values():
                self.w3.eth.send_transaction({"from": self.w3.eth.accounts[0], "to": a.address, "value": 10 ** 20})
        self.gas_price = None
        self.dep = deploy_all(self.w3, self.accounts, gas_price=self.gas_price, rpc_url=rpc_url or "in-process")
        self.real = BesuLedger(self.w3, self.dep, self.accounts, ARTIFACTS, gas_price=self.gas_price, receipt_timeout=20 if self.live else 30)
        self.ledger = SwitchLedger(self.real)
        self.reader = ChainReader(self.w3, self.dep, ARTIFACTS)
        cfg = Config(data_dir=self.tmp, db_path=self.tmp / "gateway.db", batch_size=batch_size, api_key="stack-key",
                     cors_origins=("*",), default_policy=dict(DEFAULT_POLICY), sync_interval=0.0, verifier_url=verifier_url)
        clock = None if (self.live or real_clock) else (lambda: iso(self.w3.eth.get_block("latest").timestamp))
        self.app = create_app(cfg, ledger=self.ledger, deployment=self.dep, accounts=self.accounts, reader=self.reader, clock=clock)
        self.client, self.store, self.svc = TestClient(self.app), self.app.state.store, self.app.state.svc
        self.dev, self.bundle_mutator = Device(), None
        self.verifier = Verifier(self.reader, CallableEvidence(self._evidence))
        self.seal, self.ship = "SEAL-A1", "SHP-001"

    def _evidence(self, sid):
        b = self.client.get("/api/export", params={"shipmentId": sid}).json()["bundle"]
        return self.bundle_mutator(b) if self.bundle_mutator else b

    def post(self, path, body=None, **kw):
        return self.client.post(path, json=body, headers=KEY, **kw)

    def get(self, path, **params):
        return self.client.get(path, params=params)

    def code(self, resp):
        return resp.json().get("error", {}).get("code")

    def contract_call(self, kind, payload):
        fn, role, _ = self.real._plan(kind, payload)
        return send_tx(self.w3, self.accounts[role], fn, gas=8_000_000, gas_price=self.gas_price, timeout=20)

    def advance_time(self, seconds):
        if self.tester is None:
            raise RuntimeError("time travel needs the in-process chain")
        self.tester.time_travel(self.w3.eth.get_block("latest").timestamp + seconds)
        self.tester.mine_blocks(1)

    def setup(self, policy=None):
        assert self.post("/api/seals", {"sealId": self.seal, "manufacturer": "Acme Pharma"}).status_code == 201
        body = {"shipmentId": self.ship, "sealId": self.seal}
        if policy:
            body["policy"] = policy
        assert self.post("/api/shipments", body).status_code == 201

    def send(self, n=1, **kw):
        for _ in range(n):
            r = self.post("/api/record", self.dev.record(**kw))
            assert r.status_code == 201, r.text

    def send_plan(self, plan):
        for kw in plan:
            self.send(1, **kw)

    def tamper_event(self, seq, kind="LID_OPEN"):
        r = self.post("/api/tamper-event", {"sealId": self.seal, "shipmentId": self.ship, "eventType": kind, "seq": seq,
                                            "timestamp": self.svc.now()})
        assert r.status_code == 201, r.text

    ROUTE = ("MANUFACTURER", "TRANSPORTER", "WAREHOUSE", "PHARMACY")

    def handoff(self, mode="both"):
        stage = len(self.store.list_custody(self.ship))
        return self.post("/api/custody/demo-handoff", {"shipmentId": self.ship, "fromRole": self.ROUTE[stage], "toRole": self.ROUTE[stage + 1], "mode": mode})

    def close_batch(self):
        self.post("/api/batch/close", {"shipmentId": self.ship})

    def normal(self, plan=None, finish=True):
        plan = list(plan or []) + [{}] * (8 - len(plan or []))
        self.setup()
        self.send_plan(plan[:4])
        assert self.handoff().status_code == 201
        self.send_plan(plan[4:8])
        assert self.handoff().status_code == 201 and self.handoff().status_code == 201
        if finish:
            self.close_batch()
        return self

    def sync(self):
        return self.post("/api/queue/sync").json()

    def verify(self):
        return self.verifier.run(self.ship)

    def db(self, sql, args=()):
        return self.store.unsafe_execute(sql, args)

    def rehash_from(self, seq, **changes):
        prev = "0"
        for r in self.store.list_records(self.ship):
            if r["seq"] == seq:
                r.update(changes)
            if r["seq"] >= seq:
                r["prevHash"], r["hash"] = prev, None
                r["hash"] = record_hash(r)
                self.db("UPDATE records SET temperature1=?,temperature2=?,prev_hash=?,hash=? WHERE shipment_id=? AND seq=?",
                        (r["temperature1"], r["temperature2"], r["prevHash"], r["hash"], self.ship, r["seq"]))
            prev = r["hash"]

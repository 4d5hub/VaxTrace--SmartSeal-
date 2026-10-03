import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import create_app
from blockchain import LedgerClient, LedgerRejected, LedgerUnavailable, Receipt
from config import Config, DEFAULT_POLICY
from hashing import record_hash

KEY = {"X-API-Key": "test-key"}
BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def ts(n):
    return (BASE + timedelta(seconds=300 * n)).strftime("%Y-%m-%dT%H:%M:%SZ")


class Device:

    def __init__(self, seal="SEAL-A1", ship="SHP-001"):
        self.seal, self.ship, self.seq, self.prev = seal, ship, 0, "0"

    def record(self, t1=5.2, t2=5.3, shock=0.2, lid=False, light=False):
        self.seq += 1
        r = {"sealId": self.seal, "shipmentId": self.ship, "seq": self.seq, "timestamp": ts(self.seq),
             "temperature1": t1, "temperature2": t2, "shock": shock, "lid": lid, "light": light, "prevHash": self.prev}
        r["hash"] = record_hash(r)
        self.prev = r["hash"]
        return r


class RecordingLedger(LedgerClient):
    def __init__(self):
        self.up, self.calls, self.reject_kinds = True, [], {}

    def is_available(self):
        return self.up

    def submit(self, kind, payload):
        if not self.up:
            raise LedgerUnavailable("no quorum")
        if kind in self.reject_kinds:
            raise LedgerRejected(self.reject_kinds[kind])
        self.calls.append((kind, payload))
        return Receipt(tx_hash="0x" + f"{len(self.calls):064x}", block_number=len(self.calls))


class Env:
    pass


@pytest.fixture
def env(tmp_path):
    cfg = Config(data_dir=tmp_path, db_path=tmp_path / "t.db", batch_size=4, api_key="test-key",
                 cors_origins=("*",), default_policy=dict(DEFAULT_POLICY))
    e = Env()
    e.app = create_app(cfg)
    e.client, e.store, e.svc, e.dev = TestClient(e.app), e.app.state.store, e.app.state.svc, Device()
    e.cfg = cfg

    def post(path, body, headers=KEY):
        return e.client.post(path, json=body, headers=headers)

    def setup(seal="SEAL-A1", ship="SHP-001", key=None):
        body = {"sealId": seal, "manufacturer": "Acme Pharma"}
        if key:
            body["publicKey"] = key
        assert post("/api/seals", body).status_code == 201
        assert post("/api/shipments", {"shipmentId": ship, "sealId": seal}).status_code == 201

    def send(n, **kw):
        out = []
        for _ in range(n):
            r = post("/api/record", e.dev.record(**kw))
            assert r.status_code == 201, r.text
            out.append(r.json())
        return out

    def rehash_from(seq, **changes):
        recs = e.store.list_records("SHP-001")
        prev = "0"
        for r in recs:
            if r["seq"] == seq:
                r.update(changes)
            if r["seq"] >= seq:
                r["prevHash"] = prev
                r["hash"] = record_hash(r)
                e.store.unsafe_execute(
                    "UPDATE records SET temperature1=?,temperature2=?,prev_hash=?,hash=? WHERE shipment_id=? AND seq=?",
                    (r["temperature1"], r["temperature2"], r["prevHash"], r["hash"], "SHP-001", r["seq"]))
            prev = r["hash"]

    e.post, e.setup, e.send, e.rehash_from = post, setup, send, rehash_from
    e.verify = lambda: e.client.get("/api/verify-chain", params={"shipmentId": "SHP-001"}).json()
    return e

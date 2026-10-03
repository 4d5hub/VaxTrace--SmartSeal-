import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "gateway"))
from hashing import record_hash

p = argparse.ArgumentParser()
p.add_argument("--base-url", default="http://127.0.0.1:8000")
p.add_argument("--api-key", default="demo-only-change-me")
p.add_argument("--seal", default="SEAL-A1")
p.add_argument("--shipment", default="SHP-001")
p.add_argument("--count", type=int, default=8)
p.add_argument("--temp", type=float, default=5.2)
p.add_argument("--lid", action="store_true")
a = p.parse_args()
h = {"X-API-Key": a.api_key}

with httpx.Client(base_url=a.base_url, headers=h, timeout=10) as c:
    if not any(s["sealId"] == a.seal for s in c.get("/api/seals").json()):
        print("register seal:", c.post("/api/seals", json={"sealId": a.seal, "manufacturer": "Acme Pharma"}).status_code)
    if not any(s["shipmentId"] == a.shipment for s in c.get("/api/shipments").json()):
        print("start shipment:", c.post("/api/shipments", json={"shipmentId": a.shipment, "sealId": a.seal}).status_code)
    last = c.get("/api/records/latest", params={"shipmentId": a.shipment})
    seq, prev = (last.json()["seq"], last.json()["hash"]) if last.status_code == 200 else (0, "0")
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    for _ in range(a.count):
        seq += 1
        rec = {"sealId": a.seal, "shipmentId": a.shipment, "seq": seq,
               "timestamp": (base + timedelta(minutes=5 * seq)).strftime("%Y-%m-%dT%H:%M:%SZ"),
               "temperature1": a.temp, "temperature2": round(a.temp + 0.1, 2), "shock": 0.2,
               "lid": a.lid, "light": False, "prevHash": prev}
        rec["hash"] = prev = record_hash(rec)
        r = c.post("/api/record", json=rec)
        body = r.json()
        note = f" -> batch {body['batchClosed']['batchId']} closed, root {body['batchClosed']['root'][:12]}..." if r.status_code == 201 and body["batchClosed"] else ""
        print(f"seq {seq}: HTTP {r.status_code} {json.dumps(body['error']) if r.status_code != 201 else 'ok'}{note}")
    print(json.dumps(c.get("/api/verify-chain", params={"shipmentId": a.shipment}).json()["codes"]), "<- codes from /api/verify-chain")

import argparse
import json
import sqlite3
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "gateway"))
from hashing import record_hash

ap = argparse.ArgumentParser()
ap.add_argument("cmd", choices=["seed", "verify", "attack"])
ap.add_argument("what", nargs="?", choices=["edit", "delete", "wipe"])
ap.add_argument("--base-url", default="http://127.0.0.1:8000")
ap.add_argument("--key", default="demo-only-change-me")
ap.add_argument("--shipment", default="SHP-DEMO")
ap.add_argument("--seal", default="SEAL-DEMO")
ap.add_argument("--hot", default="", help="comma list of record numbers that read 13 C")
ap.add_argument("--finalize", action="store_true")
ap.add_argument("--db", default=str(ROOT / "gateway" / "data" / "smartseal.db"))
a = ap.parse_args()
H = {"X-API-Key": a.key}


def call(method, path, **kw):
    r = httpx.request(method, a.base_url + path, headers=H, timeout=120, **kw)
    return r


if a.cmd == "seed":
    hot = {int(x) for x in a.hot.split(",") if x}
    print("seal    ", call("POST", "/api/seals", json={"sealId": a.seal, "manufacturer": "Acme Pharma"}).status_code)
    print("shipment", call("POST", "/api/shipments", json={"shipmentId": a.shipment, "sealId": a.seal}).status_code)
    start, prev = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(minutes=45), "0"

    def send(n):
        global prev
        t = 13.0 if n in hot else 5.2
        r = {"sealId": a.seal, "shipmentId": a.shipment, "seq": n, "timestamp": (start + timedelta(minutes=5 * n)).strftime("%Y-%m-%dT%H:%M:%SZ"),
             "temperature1": t, "temperature2": round(t + 0.1, 2), "shock": 0.2, "lid": False, "light": False, "prevHash": prev}
        r["hash"] = prev = record_hash(r)
        resp = call("POST", "/api/record", json=r)
        if resp.status_code != 201:
            sys.exit(f"record {n} failed: {resp.text}")

    def handoff():
        stage = len(call("GET", "/api/custody", params={"shipmentId": a.shipment}).json()["handoffs"])
        route = ["MANUFACTURER", "TRANSPORTER", "WAREHOUSE", "PHARMACY"]
        r = call("POST", "/api/custody/demo-handoff", json={"shipmentId": a.shipment, "fromRole": route[stage], "toRole": route[stage + 1], "mode": "both"})
        print(f"handoff {route[stage]} -> {route[stage + 1]}:", r.status_code, "" if r.status_code == 201 else r.text)

    for n in range(1, 5):
        send(n)
    handoff()
    for n in range(5, 9):
        send(n)
    handoff(); handoff()
    call("POST", "/api/batch/close", json={"shipmentId": a.shipment})
    print("seeded 8 records, 2 batches, 3 handoffs. Queue:", call("GET", "/api/queue").json()["pending"], "pending")

elif a.cmd == "verify":
    r = call("POST", "/api/verifier/run", params={"shipmentId": a.shipment, "finalize": str(a.finalize).lower()})
    if r.status_code != 200:
        sys.exit(f"{r.status_code} {r.text}")
    v = r.json()
    print(v["verdict"], v["codes"])
    for c in v["checks"]:
        print(f"  {c['step']:>2} {c['status']:<4} {c['name']}: {c['detail'][:100]}")
    if v.get("finalized"):
        print("finalized:", v["finalized"])

else:
    con = sqlite3.connect(a.db)
    if a.what == "edit":
        rows = con.execute("SELECT seq,temperature1,temperature2 FROM records WHERE shipment_id=? ORDER BY seq", (a.shipment,)).fetchall()
        cols = ["seal_id", "shipment_id", "seq", "timestamp", "temperature1", "temperature2", "shock", "lid", "light", "prev_hash", "hash"]
        recs = [dict(zip(cols, r)) for r in con.execute("SELECT " + ",".join(cols) + " FROM records WHERE shipment_id=? ORDER BY seq", (a.shipment,))]
        prev, first = "0", None
        for r in recs:
            if first is None and r["temperature1"] > 8:
                first = r["seq"]
            if first is not None and r["temperature1"] > 8:
                r["temperature1"], r["temperature2"] = 5.0, 5.1
        for r in recs:
            r["prev_hash"] = prev
            rec = {"sealId": r["seal_id"], "shipmentId": r["shipment_id"], "seq": r["seq"], "timestamp": r["timestamp"], "temperature1": r["temperature1"],
                   "temperature2": r["temperature2"], "shock": r["shock"], "lid": bool(r["lid"]), "light": bool(r["light"]), "prevHash": prev}
            prev = r["hash"] = record_hash(rec)
            con.execute("UPDATE records SET temperature1=?,temperature2=?,prev_hash=?,hash=? WHERE shipment_id=? AND seq=?",
                        (r["temperature1"], r["temperature2"], r["prev_hash"], r["hash"], a.shipment, r["seq"]))
        print("hot readings rewritten to 5.0 C and the whole hash chain recomputed (looks perfectly consistent to a hash-chain check).")
    elif a.what == "delete":
        con.execute("DELETE FROM records WHERE shipment_id=? AND seq=3", (a.shipment,))
        print("record 3 deleted.")
    else:
        con.execute("DELETE FROM records WHERE shipment_id=?", (a.shipment,))
        print("all records deleted.")
    con.commit()
    print("now run:  python integration\\live_demo.py verify --shipment", a.shipment)

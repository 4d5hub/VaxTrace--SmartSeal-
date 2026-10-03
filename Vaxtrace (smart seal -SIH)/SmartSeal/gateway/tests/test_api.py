import pytest

from blockchain import sync_outbox
from hashing import ZERO_ROOT, batch_payload
from merkle import merkle_root
from secure_element import MockSecureElementProvider
from tests.conftest import KEY, RecordingLedger, ts, Device


def code(resp):
    return resp.json()["error"]["code"]


def test_normal_flow_batches_close_and_chain_verifies(env):
    env.setup()
    out = env.send(8)
    assert out[3]["batchClosed"]["batchId"] == 1 and out[7]["batchClosed"]["batchId"] == 2
    b = env.client.get("/api/batches", params={"shipmentId": "SHP-001"}).json()["batches"]
    assert [x["counter"] for x in b] == [1, 2] and b[1]["prevRoot"] == b[0]["root"] and b[0]["prevRoot"] == ZERO_ROOT
    res = env.verify()
    assert res["ok"] and res["codes"] == [] and all(c["status"] in ("PASS", "WARN") for c in res["checks"])
    detail = env.client.get("/api/batches/1", params={"shipmentId": "SHP-001"}).json()
    assert detail["root"] == merkle_root(detail["merkle"]["leaves"]) == detail["merkle"]["levels"][-1][0]


def test_attack_edit_excursion_and_rehash_chain_gives_merkle_mismatch(env):
    env.setup(); env.send(8, t1=13.0, t2=13.0)
    env.rehash_from(2, temperature1=5.0, temperature2=5.0)
    res = env.verify()
    assert "MERKLE_MISMATCH" in res["codes"] and "HASH_CHAIN_BROKEN" not in res["codes"]


def test_attack_edit_without_rehash_breaks_hash_chain(env):
    env.setup(); env.send(8)
    env.store.unsafe_execute("UPDATE records SET temperature1=13.0 WHERE seq=3")
    assert "HASH_CHAIN_BROKEN" in env.verify()["codes"]


def test_attack_delete_record(env):
    env.setup(); env.send(8)
    env.store.unsafe_execute("DELETE FROM records WHERE seq=3")
    assert {"SEQ_GAP", "HASH_CHAIN_BROKEN"} <= set(env.verify()["codes"])


def test_attack_wipe_offchain_store(env):
    env.setup(); env.send(8)
    env.store.unsafe_execute("DELETE FROM records")
    assert "MISSING_DATA" in env.verify()["codes"]


def test_attack_edit_anchored_root_in_db_breaks_signature(env):
    env.setup(); env.send(4)
    env.store.unsafe_execute("UPDATE batches SET root=? WHERE batch_id=1", ("cd" * 32,))
    assert {"SIGNATURE_INVALID", "MERKLE_MISMATCH"} <= set(env.verify()["codes"])


def test_counter_gap_detected(env):
    env.setup(); env.send(8)
    env.store.unsafe_execute("UPDATE batches SET counter=counter+3 WHERE batch_id=2")
    assert "COUNTER_GAP" in env.verify()["codes"]


def test_wrong_seal_wrong_shipment_and_auth(env):
    env.setup()
    r = env.dev.record(); r["sealId"] = "SEAL-ZZ"
    assert code(env.post("/api/record", r)) == "WRONG_SEAL"
    env.post("/api/seals", {"sealId": "SEAL-B2", "manufacturer": "X"})
    r2 = Device(seal="SEAL-B2", ship="SHP-001").record()
    assert code(env.post("/api/record", r2)) == "WRONG_SHIPMENT"
    r3 = Device(ship="SHP-404").record()
    assert code(env.post("/api/record", r3)) == "WRONG_SHIPMENT"
    assert env.client.post("/api/record", json=env.dev.record()).status_code == 401


def test_record_validation_and_ordering_errors(env):
    env.setup()
    d = env.dev
    ok = d.record(); assert env.post("/api/record", ok).status_code == 201
    dup = env.post("/api/record", ok); assert dup.status_code == 201 and dup.json()["duplicate"] is True
    changed = dict(ok, temperature1=9.9); changed["hash"] = None
    assert code(env.post("/api/record", changed)) == "SEQ_DUPLICATE"
    nxt = d.record(); nxt["prevHash"] = "ab" * 32; nxt.pop("hash")
    assert code(env.post("/api/record", nxt)) == "PREV_HASH_MISMATCH"
    bad = d.record(); bad["hash"] = "cd" * 32
    assert code(env.post("/api/record", bad)) == "HASH_MISMATCH"
    skip = dict(nxt, seq=9, prevHash=ok["hash"])
    assert code(env.post("/api/record", skip)) == "SEQ_GAP"
    prec = dict(ok, seq=2, prevHash=ok["hash"], temperature1=5.123); prec.pop("hash")
    assert code(env.post("/api/record", prec)) == "SCHEMA_INVALID"
    extra = dict(ok, seq=2, prevHash=ok["hash"], evil=1); extra.pop("hash")
    assert code(env.post("/api/record", extra)) == "SCHEMA_INVALID"
    back = Device(); back.seq = 1; back.prev = ok["hash"]; r = back.record(); r["timestamp"] = "2025-01-01T00:00:00Z"; r.pop("hash")
    assert code(env.post("/api/record", r)) == "TIMESTAMP_ORDER"


def device_side_batches(env, tmp_path):
    se = MockSecureElementProvider(tmp_path / "device")
    pub = se.provision("SEAL-D1")
    env.dev = Device(seal="SEAL-D1")
    env.setup(seal="SEAL-D1", key=pub)
    out = env.send(8)
    assert out[3]["batchClosed"] is None
    recs = env.store.list_records("SHP-001")

    def make(batch_id, lo, hi, prev_root, se_=se, seal="SEAL-D1", ship="SHP-001"):
        meta = {"sealId": seal, "shipmentId": ship, "batchId": batch_id, "firstSeq": lo, "lastSeq": hi,
                "count": hi - lo + 1, "prevRoot": prev_root, "timestamp": ts(hi),
                "root": merkle_root([r["hash"] for r in recs if lo <= r["seq"] <= hi])}
        s = se_.sign_counted("SEAL-D1", lambda c: batch_payload(meta, c))
        return {**meta, "counter": s.counter, "signature": s.signature}
    return se, make


def test_device_signed_batches_replay_clone_order_and_root_checks(env, tmp_path):
    se, make = device_side_batches(env, tmp_path)
    b1 = make(1, 1, 4, ZERO_ROOT)
    assert env.post("/api/batch/submit", b1).status_code == 201
    assert code(env.post("/api/batch/submit", b1)) == "STALE_COUNTER"
    clone = MockSecureElementProvider(tmp_path / "clone"); clone.provision("SEAL-D1")
    fake = make(2, 5, 8, b1["root"], se_=clone)
    assert code(env.post("/api/batch/submit", fake)) == "SIGNATURE_INVALID"
    assert code(env.post("/api/batch/submit", make(3, 5, 8, b1["root"]))) == "BATCH_SEQUENCE_ERROR"
    assert code(env.post("/api/batch/submit", make(2, 5, 8, "ee" * 32))) == "PREV_ROOT_MISMATCH"
    assert code(env.post("/api/batch/submit", make(2, 5, 8, b1["root"], ship="SHP-404"))) == "WRONG_SHIPMENT"
    assert code(env.post("/api/batch/submit", make(2, 5, 8, b1["root"], seal="SEAL-Q9"))) == "WRONG_SEAL"
    lie = make(2, 5, 8, b1["root"]); lie["root"] = "aa" * 32
    assert code(env.post("/api/batch/submit", lie)) == "SIGNATURE_INVALID"
    assert env.post("/api/batch/submit", make(2, 5, 8, b1["root"])).status_code == 201
    res = env.verify()
    assert res["codes"] == ["COUNTER_GAP"]


def test_tamper_event_is_signed_counted_and_closes_batch(env):
    env.setup(); env.send(6)
    r = env.post("/api/tamper-event", {"sealId": "SEAL-A1", "shipmentId": "SHP-001", "eventType": "LID_OPEN", "seq": 6, "timestamp": ts(6)})
    assert r.status_code == 201 and r.json()["counter"] == 2
    batches = env.client.get("/api/batches", params={"shipmentId": "SHP-001"}).json()["batches"]
    assert [b["counter"] for b in batches] == [1, 3] and batches[1]["lastSeq"] == 6
    assert env.verify()["ok"]
    future = env.post("/api/tamper-event", {"sealId": "SEAL-A1", "shipmentId": "SHP-001", "eventType": "LID_OPEN", "seq": 99, "timestamp": ts(99)})
    assert code(future) == "EVENT_SEQ_INVALID"


def test_manual_batch_close_and_empty_close(env):
    env.setup(); env.send(2)
    assert env.post("/api/batch/close", {"shipmentId": "SHP-001"}).json()["batch"]["count"] == 2
    assert env.post("/api/batch/close", {"shipmentId": "SHP-001"}).json()["batch"] is None


def test_revocation_roles_and_effect(env):
    env.setup(); env.send(1)
    assert code(env.post("/api/seals/SEAL-A1/revoke", {"by": "TRANSPORTER"})) == "ROLE_DENIED"
    assert env.post("/api/seals/SEAL-A1/revoke", {"by": "REGULATOR"}).json()["revoked"] is True
    assert code(env.post("/api/record", env.dev.record())) == "SEAL_REVOKED"


def test_queue_is_kept_offline_and_drains_in_order(env):
    env.setup(); env.send(8)
    assert env.client.get("/api/queue").json()["pending"] == 4
    assert env.client.get("/api/status").json()["ledger"]["available"] is False
    led = RecordingLedger(); led.up = False
    res = sync_outbox(env.store, led, "2026-01-01T00:00:00Z")
    assert res["anchored"] == 0 and res["pending"] == 4
    led.up = True
    res = sync_outbox(env.store, led, "2026-01-01T00:00:00Z")
    assert res["anchored"] == 4 and res["pending"] == 0
    assert [k for k, _ in led.calls] == ["REGISTER_SEAL", "START_SHIPMENT", "BATCH", "BATCH"]
    assert all(b["anchorStatus"] == "ANCHORED" for b in env.client.get("/api/batches", params={"shipmentId": "SHP-001"}).json()["batches"])


def test_outage_mid_sync_stops_in_order_and_rejections_are_recorded(env):
    env.setup(); env.send(8)
    led = RecordingLedger(); led.reject_kinds = {"BATCH": "STALE_COUNTER"}
    res = sync_outbox(env.store, led, "2026-01-01T00:00:00Z")
    assert res["rejected"] == 2 and res["anchored"] == 2
    assert {b["anchorStatus"] for b in env.client.get("/api/batches", params={"shipmentId": "SHP-001"}).json()["batches"]} == {"REJECTED"}


def test_gateway_auto_syncs_when_ledger_becomes_available(env):
    led = RecordingLedger(); env.app.state.ledger = led
    env.setup(); env.send(4)
    assert [k for k, _ in led.calls] == ["REGISTER_SEAL", "START_SHIPMENT", "BATCH"]


def test_export_import_audit_copy(env):
    env.setup(); env.send(4)
    ex = env.client.get("/api/export", params={"shipmentId": "SHP-001"}).json()
    imp = env.post("/api/import", {"bundle": ex["bundle"]})
    assert imp.status_code == 201 and imp.json()["bundleHash"] == ex["bundleHash"] and imp.json()["selfConsistency"]["ok"]
    assert len(env.client.get("/api/audit-copies").json()["copies"]) == 1
    ex["bundle"]["records"][1]["temperature1"] = 13.0
    assert env.post("/api/import", {"bundle": ex["bundle"]}).json()["selfConsistency"]["ok"] is False


def test_status_and_health(env):
    assert env.client.get("/api/health").json()["status"] == "ok"
    s = env.client.get("/api/status").json()
    assert "NOT equivalent" in s["simulated"]["note"] and "not universal" in s["policyDisclaimer"]

import importlib.util
import secrets
from pathlib import Path

from fastapi.testclient import TestClient
from eth_utils import keccak

from integration.stack import ROOT, Stack
from custody import handoff_digest


def verifier_client(s, tmp):
    spec = importlib.util.spec_from_file_location("verifier_service_app", ROOT / "verifier" / "app.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return TestClient(mod.create_app(reader=s.reader, ledger=s.real, results_path=Path(tmp) / "results.json"))


def test_python_handoff_digest_equals_the_contract_digest():
    s = Stack()
    s.setup()
    frm, to = s.dep.participants["MANUFACTURER"], s.dep.participants["TRANSPORTER"]
    nonce = "0x" + secrets.token_hex(32)
    py = handoff_digest(s.dep.chain_id, s.dep.addresses["custody"], s.ship, frm, to, nonce, 4, "2026-01-01T00:00:00Z")
    assert "0x" + py.hex() == s.reader.handoff_digest(s.ship, frm, to, nonce, 4, "2026-01-01T00:00:00Z")


def test_gateway_and_contract_both_reject_nonce_reuse_and_bad_signers():
    s = Stack()
    s.setup(); s.send(4)
    assert s.handoff().status_code == 201
    assert s.code(s.handoff("reuse_nonce")) == "NONCE_REUSED"
    assert s.code(s.handoff("wrong_receiver_signer")) == "BAD_SIGNATURE_TO"
    assert s.code(s.handoff("sender_only")) == "NEED_BOTH_SIGNATURES"
    assert len(s.reader.handoffs(s.ship)) == 1
    st = s.get("/api/custody", shipmentId=s.ship).json()
    assert st["stage"] == 1 and st["currentCustodianRole"] == "TRANSPORTER" and not st["complete"]
    assert s.code(s.post("/api/custody/handoff", {"shipmentId": s.ship, "fromRole": "TRANSPORTER", "toRole": "WAREHOUSE", "nonce": "0x" + "00" * 32,
                                                   "atSeq": 4, "timestamp": "2026-01-01T00:00:00Z"})) == "NEED_BOTH_SIGNATURES"


def test_blockchain_endpoints_return_real_chain_data():
    s = Stack()
    s.normal()
    blocks = s.get("/api/blockchain/blocks", limit=5).json()["blocks"]
    assert blocks and blocks[0]["transactions"] is not None and blocks[0]["number"] >= blocks[-1]["number"]
    sh = s.get(f"/api/blockchain/shipments/{s.ship}").json()
    assert sh["batchCount"] == 2 and sh["handoffCount"] == 3 and sh["seal"]["revoked"] is False and sh["verdict"] is None
    assert len(s.get(f"/api/blockchain/batches/{s.ship}").json()["batches"]) == 2
    assert [h["toRole"] for h in s.get(f"/api/blockchain/custody/{s.ship}").json()["handoffs"]] == ["TRANSPORTER", "WAREHOUSE", "PHARMACY"]
    assert s.get("/api/blockchain/shipments/NOPE").status_code == 404
    st = s.get("/api/status").json()
    assert st["queuePending"] == 0 and st["ledger"]["available"] is True


def test_verifier_service_verifies_and_finalizes_on_chain(tmp_path):
    s = Stack()
    s.normal()
    vc = verifier_client(s, tmp_path)
    from verification.evidence import CallableEvidence
    from verification.engine import Verifier
    app_state_verifier = Verifier(s.reader, CallableEvidence(s._evidence))
    res = app_state_verifier.run(s.ship)
    assert res["verdict"] == "ACCEPT"
    bundle = s.get("/api/export", shipmentId=s.ship).json()["bundle"]
    r = vc.post("/verify-bundle", json={"shipmentId": s.ship, "bundle": bundle, "finalize": True}).json()
    assert r["verdict"] == "ACCEPT" and r["finalized"]["status"] == "on-chain"
    assert vc.get("/result", params={"shipmentId": s.ship}).json()["reportHash"] == r["reportHash"]
    assert s.reader.verdict(s.ship)["reportHash"] == r["reportHash"]
    assert vc.get("/result", params={"shipmentId": "NOPE"}).status_code == 404
    assert vc.get("/health").json()["chainConnected"] is True


def test_policy_swapped_by_the_gateway_is_caught_by_the_onchain_policy_hash():
    s = Stack()
    s.normal([{}] * 4 + [{"t1": 13.0, "t2": 13.0}] * 4)
    assert s.verify()["verdict"] == "REJECT"
    s.db("UPDATE shipments SET policy_json=? WHERE shipment_id=?", ('{"disclaimer":"x","tempMaxC":30.0,"tempMinC":2.0,"maxExcursionMinutes":999,"shockLimitG":2.5,"offlineGapMinutes":20,"probeDisagreementC":3.0}', s.ship))
    v = s.verify()
    assert "POLICY_MISMATCH" in v["codes"] and v["verdict"] == "REJECT"


def test_suppressed_tamper_event_and_counter_gap_are_detected():
    s = Stack()
    s.setup(); s.send(4)
    s.send(1, lid=True)
    s.send(3)
    s.handoff(); s.handoff(); s.handoff(); s.close_batch()
    v = s.verify()
    assert "TAMPER_EVENT_MISSING" in v["codes"] and v["verdict"] == "QUARANTINE"
    s2 = Stack()
    s2.normal()
    s2.svc.provider.sign_counted(s2.seal, lambda c: f"signed-but-never-anchored-{c}")
    s2.dev.seq = 8
    s2.send(4)
    s2.close_batch()
    assert "COUNTER_GAP" in s2.verify()["codes"]


def test_verifier_reports_missing_shipment():
    s = Stack()
    v = s.verifier.run("SHP-DOES-NOT-EXIST")
    assert v["verdict"] == "REJECT" and v["codes"] == ["SHIPMENT_NOT_FOUND"]

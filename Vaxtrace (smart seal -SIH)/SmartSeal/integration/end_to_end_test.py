from integration.stack import Stack


def test_normal_shipment_ends_in_accept_and_is_finalized_on_chain():
    s = Stack()
    s.setup()
    s.send(4)
    assert s.get("/api/batches", shipmentId=s.ship).json()["batches"][0]["count"] == 4
    on = s.reader.batches(s.ship)
    assert len(on) == 1 and on[0]["root"] == s.get("/api/batches", shipmentId=s.ship).json()["batches"][0]["root"]
    assert s.handoff().status_code == 201
    s.send(4)
    assert s.handoff().status_code == 201
    assert s.handoff().status_code == 201
    s.close_batch()
    v = s.verify()
    assert v["verdict"] == "ACCEPT" and v["codes"] == []
    assert [c["step"] for c in v["checks"] if c["status"] != "SKIP"][-1] == 25 and not [c for c in v["checks"] if c["status"] == "FAIL"]
    rc = s.real.submit("VERDICT", {"shipmentId": s.ship, "verdict": v["verdict"], "reasonCodes": v["codes"], "reportHash": v["reportHash"]})
    assert rc.tx_hash and s.reader.verdict(s.ship)["verdict"] == "ACCEPT"


def test_tampered_raw_data_ends_in_reject_with_merkle_mismatch():
    s = Stack()
    s.normal([{}] * 4 + [{"t1": 13.0, "t2": 13.0}] * 2)
    assert s.verify()["verdict"] == "QUARANTINE"
    for seq in (5, 6):
        s.rehash_from(seq, temperature1=5.0, temperature2=5.0)
    v = s.verify()
    assert v["verdict"] == "REJECT" and "MERKLE_MISMATCH" in v["codes"]

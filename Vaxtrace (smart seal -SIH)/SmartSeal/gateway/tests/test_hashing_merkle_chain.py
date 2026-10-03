import copy
import pytest

from hashing import canonical, fmt2, record_canonical, record_hash
from merkle import merkle_levels, merkle_proof, merkle_root, verify_proof
from verifier import verify_records
from tests.conftest import Device

VECTOR = {"sealId": "SEAL-A1", "shipmentId": "SHP-001", "seq": 1, "timestamp": "2026-01-01T00:05:00Z",
          "temperature1": 5.2, "temperature2": 5.3, "shock": 0.2, "lid": False, "light": False, "prevHash": "0"}
VECTOR_CANONICAL = ('{"lid":false,"light":false,"prevHash":"0","sealId":"SEAL-A1","seq":1,"shipmentId":"SHP-001",'
                    '"shock":0.20,"temperature1":5.20,"temperature2":5.30,"timestamp":"2026-01-01T00:05:00Z"}')
VECTOR_HASH = "a79bd1e10c2b76264645634aa4daa4431a99dfc0177e206db2a2cac3b87e22dd"


def test_canonical_test_vector_for_firmware():
    assert record_canonical(VECTOR) == VECTOR_CANONICAL
    assert record_hash(VECTOR) == VECTOR_HASH


def test_hash_ignores_key_order_and_hash_field():
    shuffled = dict(reversed(list(VECTOR.items())), hash="ff" * 32)
    assert record_hash(shuffled) == VECTOR_HASH


def test_number_formatting():
    assert fmt2(5) == "5.00" and fmt2(5.2) == "5.20" and fmt2(-0.0) == "0.00" and fmt2(-3.25) == "-3.25"
    with pytest.raises(ValueError):
        fmt2(5.123)
    with pytest.raises(TypeError):
        fmt2(True)


def test_canonical_rejects_floats_outside_fixed_fields():
    with pytest.raises(TypeError):
        canonical({"x": 1.5})


def leaves(n):
    return [record_hash({**VECTOR, "seq": i + 1}) for i in range(n)]


def test_merkle_four_leaves_matches_manual_calculation():
    import hashlib
    h = leaves(4)
    p = lambda a, b: hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()
    assert merkle_root(h) == p(p(h[0], h[1]), p(h[2], h[3]))


def test_merkle_odd_duplicates_last_and_single_is_own_root():
    import hashlib
    h = leaves(3)
    p = lambda a, b: hashlib.sha256(bytes.fromhex(a) + bytes.fromhex(b)).hexdigest()
    assert merkle_root(h) == p(p(h[0], h[1]), p(h[2], h[2]))
    assert merkle_root(h[:1]) == h[0]
    with pytest.raises(ValueError):
        merkle_root([])


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8])
def test_merkle_proofs_verify_and_detect_change(n):
    h = leaves(n)
    root = merkle_root(h)
    for i in range(n):
        assert verify_proof(h[i], merkle_proof(h, i), root)
    assert not verify_proof("00" * 32, merkle_proof(h, 0), root)


def test_merkle_mismatch_when_a_leaf_changes():
    h = leaves(4)
    changed = list(h)
    changed[2] = record_hash({**VECTOR, "seq": 3, "temperature1": 13.0})
    assert merkle_root(changed) != merkle_root(h)
    assert len(merkle_levels(h)) == 3


def chain(n=6):
    d = Device()
    return [d.record() for _ in range(n)]


def test_valid_chain_passes():
    assert verify_records(chain())["ok"]


def test_modified_value_detected():
    c = chain(); c[2]["temperature1"] = 13.0
    r = verify_records(c)
    assert "HASH_CHAIN_BROKEN" in r["codes"] and r["issues"][0]["code"] == "RECORD_HASH_MISMATCH"


def test_deleted_record_detected():
    c = chain(); del c[2]
    r = verify_records(c)
    assert "SEQ_GAP" in r["codes"] and "HASH_CHAIN_BROKEN" in r["codes"]


def test_deleted_first_record_detected():
    c = chain(); del c[0]
    assert "SEQ_GAP" in verify_records(c)["codes"]


def test_reordered_records_detected():
    c = chain(); c[2], c[3] = c[3], c[2]
    r = verify_records(c)
    assert "HASH_CHAIN_BROKEN" in r["codes"]
    assert {"SEQ_ORDER", "PREV_HASH_MISMATCH"} <= {i["code"] for i in r["issues"]}


def test_broken_prev_hash_detected():
    c = chain(); c[3]["prevHash"] = "ab" * 32; c[3]["hash"] = record_hash(c[3])
    assert any(i["code"] == "PREV_HASH_MISMATCH" for i in verify_records(c)["issues"])


def test_timestamp_reversal_detected():
    d = Device(); c = [d.record() for _ in range(4)]
    c[2]["timestamp"] = "2025-12-31T00:00:00Z"; c[2]["hash"] = record_hash(c[2])
    c[3]["prevHash"] = c[2]["hash"]; c[3]["hash"] = record_hash(c[3])
    assert "TIMESTAMP_ORDER" in verify_records(c)["codes"]

from hashing import batch_payload
from secure_element import MockSecureElementProvider, ProductionSecureElementProvider, verify_signature
import pytest

META = {"sealId": "SEAL-A1", "shipmentId": "SHP-001", "batchId": 1, "firstSeq": 1, "lastSeq": 4, "count": 4,
        "prevRoot": "0" * 64, "root": "ab" * 32, "timestamp": "2026-01-01T00:20:00Z"}


def test_sign_verify_and_counter(tmp_path):
    se = MockSecureElementProvider(tmp_path)
    pub = se.provision("SEAL-A1")
    assert se.provision("SEAL-A1") == pub and len(pub) == 130
    s1 = se.sign_counted("SEAL-A1", lambda c: batch_payload(META, c))
    s2 = se.sign_counted("SEAL-A1", lambda c: batch_payload(META, c))
    assert (s1.counter, s2.counter) == (1, 2)
    assert verify_signature(pub, s1.message, s1.signature)


def test_counter_persists_across_restart_and_never_decreases(tmp_path):
    a = MockSecureElementProvider(tmp_path); a.provision("S1")
    a.sign_counted("S1", lambda c: str(c)); a.sign_counted("S1", lambda c: str(c))
    b = MockSecureElementProvider(tmp_path)
    assert b.get_monotonic_counter("S1") == 2
    assert b.sign_counted("S1", lambda c: str(c)).counter == 3


def test_fake_and_altered_signatures_rejected(tmp_path):
    se = MockSecureElementProvider(tmp_path)
    pub, other = se.provision("A"), se.provision("B")
    s = se.sign_counted("A", lambda c: batch_payload(META, c))
    assert not verify_signature(other, s.message, s.signature)
    assert not verify_signature(pub, s.message.replace('"count":4', '"count":5'), s.signature)
    assert not verify_signature(pub, s.message, "00" * 64)
    assert not verify_signature(pub, s.message, "zz")


def test_production_provider_is_only_an_interface():
    with pytest.raises(NotImplementedError):
        ProductionSecureElementProvider().sign_counted("x", lambda c: "")

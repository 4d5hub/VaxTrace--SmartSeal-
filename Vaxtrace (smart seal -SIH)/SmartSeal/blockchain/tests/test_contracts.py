import hashlib
import secrets

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from eth_account.messages import encode_defunct
from eth_utils import keccak
from web3 import Web3

from hashing import ZERO_ROOT, batch_payload, tamper_payload
from merkle import merkle_root
from secure_element import MockSecureElementProvider
from blockchain import load_artifact
from deploy import ARTIFACTS, deploy_contract

SEAL, SHIP = "SEAL-A1", "SHP-001"
TS = "2026-01-01T00:20:00Z"


def _rs(sig_hex):
    return int(sig_hex[:64], 16), int(sig_hex[64:], 16)


def _xy(pub_hex):
    return int(pub_hex[2:66], 16), int(pub_hex[66:130], 16)


@pytest.fixture
def p256(chain):
    addr = deploy_contract(chain.w3, chain.accounts["ADMIN"], "P256Harness", gas_price=None)
    return chain.w3.eth.contract(address=addr, abi=load_artifact(ARTIFACTS, "P256Harness")["abi"])


def _sign(priv, msg: bytes):
    r, s = decode_dss_signature(priv.sign(msg, ec.ECDSA(hashes.SHA256())))
    return hashlib.sha256(msg).digest(), r, s


def _pub(priv):
    n = priv.public_key().public_numbers()
    return n.x, n.y


def test_p256_constants_match_the_curve():
    g = ec.derive_private_key(1, ec.SECP256R1()).public_key().public_numbers()
    assert (g.x, g.y) == (0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
                          0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5)


def test_p256_accepts_many_valid_signatures(p256):
    for _ in range(12):
        priv = ec.generate_private_key(ec.SECP256R1())
        d, r, s = _sign(priv, secrets.token_bytes(40))
        assert p256.functions.verify(d, r, s, *_pub(priv)).call()


def test_p256_rejects_wrong_message_key_and_garbage(p256):
    priv, other = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    d, r, s = _sign(priv, b"hello")
    q = _pub(priv)
    assert not p256.functions.verify(hashlib.sha256(b"hellO").digest(), r, s, *q).call()
    assert not p256.functions.verify(d, r, s, *_pub(other)).call()
    assert not p256.functions.verify(d, r ^ 1, s, *q).call()
    assert not p256.functions.verify(d, r, s ^ 1, *q).call()
    N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    for bad_r, bad_s in ((0, s), (r, 0), (N, s), (r, N)):
        assert not p256.functions.verify(d, bad_r, bad_s, *q).call()
    assert not p256.functions.verify(d, r, s, q[0], (q[1] + 1) % (2 ** 256)).call()
    assert not p256.functions.isOnCurve(1, 2).call()


def test_p256_edge_keys_generator_and_its_negation(p256):
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    for scalar in (1, n - 1, 2, 3):
        priv = ec.derive_private_key(scalar, ec.SECP256R1())
        d, r, s = _sign(priv, b"edge case")
        assert p256.functions.verify(d, r, s, *_pub(priv)).call(), scalar


def test_p256_gas_is_affordable(p256):
    priv = ec.generate_private_key(ec.SECP256R1())
    d, r, s = _sign(priv, b"gas")
    gas = p256.functions.verify(d, r, s, *_pub(priv)).estimate_gas()
    print("P-256 verify gas:", gas)
    assert gas < 8_000_000


def register(chain, se, seal=SEAL, ship=SHIP):
    pub = se.provision(seal)
    reg = chain.contract("registry")
    chain.send(reg.functions.registerSeal(seal, *_xy(pub)), "MANUFACTURER")
    chain.send(reg.functions.startShipment(ship, seal, bytes(32)), "MANUFACTURER")
    return pub


@pytest.fixture
def se(tmp_path):
    return MockSecureElementProvider(tmp_path)


def test_registry_roles_and_shipments(chain, se):
    reg = chain.contract("registry")
    pub = se.provision(SEAL)
    assert chain.fails(reg.functions.registerSeal(SEAL, *_xy(pub)), "TRANSPORTER") == "ROLE_DENIED"
    assert chain.fails(reg.functions.registerSeal(SEAL, 1, 2), "MANUFACTURER") == "BAD_PUBLIC_KEY"
    chain.send(reg.functions.registerSeal(SEAL, *_xy(pub)), "MANUFACTURER")
    assert chain.fails(reg.functions.registerSeal(SEAL, *_xy(pub)), "MANUFACTURER") == "SEAL_EXISTS"
    assert chain.fails(reg.functions.startShipment(SHIP, "NOPE", bytes(32)), "MANUFACTURER") == "WRONG_SEAL"
    chain.send(reg.functions.startShipment(SHIP, SEAL, bytes(32)), "MANUFACTURER")
    assert chain.fails(reg.functions.startShipment(SHIP, SEAL, bytes(32)), "MANUFACTURER") == "SHIPMENT_EXISTS"
    assert chain.reader.seal(SEAL)["publicKey"] == pub and chain.reader.shipment(SHIP)["active"]
    assert chain.fails(reg.functions.setRole(chain.accounts["GATEWAY"].address, 1), "MANUFACTURER") == "ROLE_DENIED"


def test_revocation_roles(chain, se):
    reg = chain.contract("registry")
    register(chain, se)
    assert chain.fails(reg.functions.revokeSeal(SEAL), "TRANSPORTER") == "ROLE_DENIED"
    assert chain.fails(reg.functions.revokeSeal("NOPE"), "REGULATOR") == "WRONG_SEAL"
    chain.send(reg.functions.revokeSeal(SEAL), "REGULATOR")
    assert chain.reader.seal(SEAL)["revoked"] is True
    assert chain.fails(reg.functions.revokeSeal(SEAL), "MANUFACTURER") == "ALREADY_REVOKED"


def make_batch(se, batch_id, first, last, prev_root, seal=SEAL, ship=SHIP, identity=SEAL, root=None):
    leaves = [hashlib.sha256(f"r{i}".encode()).hexdigest() for i in range(first, last + 1)]
    meta = {"sealId": seal, "shipmentId": ship, "batchId": batch_id, "firstSeq": first, "lastSeq": last,
            "count": last - first + 1, "prevRoot": prev_root, "root": root or merkle_root(leaves), "timestamp": TS}
    s = se.sign_counted(identity, lambda c: batch_payload(meta, c))
    return {**meta, "counter": s.counter, "signature": s.signature}


def tup(b):
    return (b["sealId"], b["shipmentId"], b["batchId"], b["firstSeq"], b["lastSeq"], b["count"],
            bytes.fromhex(b["prevRoot"]), bytes.fromhex(b["root"]), b["timestamp"], b["counter"])


def commit_fn(chain, b):
    r, s = _rs(b["signature"])
    return chain.contract("anchor").functions.commitBatchRoot(tup(b), r, s)


def test_batch_commit_with_real_secure_element_signature(chain, se):
    register(chain, se)
    b1 = make_batch(se, 1, 1, 4, ZERO_ROOT)
    chain.send(commit_fn(chain, b1), "GATEWAY")
    b2 = make_batch(se, 2, 5, 8, b1["root"])
    chain.send(commit_fn(chain, b2), "GATEWAY")
    on = chain.reader.batches(SHIP)
    assert [x["batchId"] for x in on] == [1, 2] and on[1]["prevRoot"] == b1["root"] and on[0]["signature"] == b1["signature"]
    assert chain.reader.last_counter(SEAL) == 2


def test_batch_reverts_replay_clone_order_root_and_roles(chain, se, tmp_path):
    register(chain, se)
    b1 = make_batch(se, 1, 1, 4, ZERO_ROOT)
    chain.send(commit_fn(chain, b1), "GATEWAY")
    assert chain.fails(commit_fn(chain, b1), "GATEWAY") == "STALE_COUNTER"
    clone = MockSecureElementProvider(tmp_path / "clone"); clone.provision(SEAL)
    assert chain.fails(commit_fn(chain, make_batch(clone, 2, 5, 8, b1["root"])), "GATEWAY") == "SIGNATURE_INVALID"
    assert chain.fails(commit_fn(chain, make_batch(se, 3, 5, 8, b1["root"])), "GATEWAY") == "BATCH_SEQUENCE_ERROR"
    assert chain.fails(commit_fn(chain, make_batch(se, 2, 5, 8, "ee" * 32)), "GATEWAY") == "PREV_ROOT_MISMATCH"
    assert chain.fails(commit_fn(chain, make_batch(se, 2, 6, 8, b1["root"])), "GATEWAY") == "BATCH_SEQUENCE_ERROR"
    assert chain.fails(commit_fn(chain, make_batch(se, 2, 5, 8, b1["root"], ship="SHP-404")), "GATEWAY") == "WRONG_SHIPMENT"
    assert chain.fails(commit_fn(chain, make_batch(se, 2, 5, 8, b1["root"], seal="SEAL-Q9")), "GATEWAY") == "WRONG_SEAL"
    lie = make_batch(se, 2, 5, 8, b1["root"]); lie["root"] = "aa" * 32
    assert chain.fails(commit_fn(chain, lie), "GATEWAY") == "SIGNATURE_INVALID"
    assert chain.fails(commit_fn(chain, make_batch(se, 2, 5, 8, b1["root"])), "TRANSPORTER") == "ROLE_DENIED"
    assert chain.fails(commit_fn(chain, make_batch(se, 2, 5, 8, b1["root"])), "MANUFACTURER") == "ROLE_DENIED"


def test_revoked_seal_cannot_commit_and_closed_shipment_is_final(chain, se):
    register(chain, se)
    chain.send(chain.contract("registry").functions.revokeSeal(SEAL), "REGULATOR")
    assert chain.fails(commit_fn(chain, make_batch(se, 1, 1, 4, ZERO_ROOT)), "GATEWAY") == "SEAL_REVOKED"


def test_tamper_event_is_signed_and_shares_the_counter(chain, se):
    register(chain, se)
    b1 = make_batch(se, 1, 1, 4, ZERO_ROOT)
    chain.send(commit_fn(chain, b1), "GATEWAY")
    ev = {"sealId": SEAL, "shipmentId": SHIP, "eventType": "LID_OPEN", "seq": 5, "timestamp": TS}
    s = se.sign_counted(SEAL, lambda c: tamper_payload(ev, c))
    r, sg = _rs(s.signature)
    fn = chain.contract("anchor").functions.recordTamperEvent((SEAL, SHIP, "LID_OPEN", 5, TS, s.counter), r, sg)
    chain.send(fn, "GATEWAY")
    t = chain.reader.tamper_events(SHIP)
    assert t[0]["eventType"] == "LID_OPEN" and t[0]["counter"] == 2
    assert chain.fails(fn, "GATEWAY") == "STALE_COUNTER"
    bad = chain.contract("anchor").functions.recordTamperEvent((SEAL, SHIP, "LID_OPEN", 6, TS, s.counter + 1), r, sg)
    assert chain.fails(bad, "GATEWAY") == "SIGNATURE_INVALID"


def handoff(chain, frm_role, to_role, nonce=None, at_seq=4, sign_from=True, sign_to=True, signer_to=None, shipment=SHIP):
    cus = chain.contract("custody")
    frm, to = chain.accounts[frm_role], chain.accounts[to_role]
    nonce = nonce or secrets.token_bytes(32)
    h = (shipment, frm.address, to.address, nonce, at_seq, TS)
    digest = cus.functions.handoffDigest(h).call()
    sig = lambda acct: bytes(acct.sign_message(encode_defunct(primitive=digest)).signature)
    sf = sig(frm) if sign_from else b""
    st = sig(signer_to or to) if sign_to else b""
    return cus.functions.transferCustody(h, sf, st), nonce


def test_full_custody_chain_with_dual_signatures(chain, se):
    register(chain, se)
    for i, (a, b) in enumerate([("MANUFACTURER", "TRANSPORTER"), ("TRANSPORTER", "WAREHOUSE"), ("WAREHOUSE", "PHARMACY")]):
        fn, _ = handoff(chain, a, b, at_seq=4 * (i + 1))
        chain.send(fn, "GATEWAY")
    hs = chain.reader.handoffs(SHIP)
    assert [(h["fromRole"], h["toRole"]) for h in hs] == [("MANUFACTURER", "TRANSPORTER"), ("TRANSPORTER", "WAREHOUSE"), ("WAREHOUSE", "PHARMACY")]
    assert chain.contract("custody").functions.currentCustodian(SHIP).call() == chain.accounts["PHARMACY"].address
    fn, _ = handoff(chain, "PHARMACY", "REGULATOR")
    assert chain.fails(fn, "GATEWAY") == "ROUTE_COMPLETE"


def test_custody_rejections(chain, se):
    register(chain, se)
    fn, nonce = handoff(chain, "MANUFACTURER", "TRANSPORTER", sign_to=False)
    assert chain.fails(fn, "GATEWAY") == "NEED_BOTH_SIGNATURES"
    fn, _ = handoff(chain, "MANUFACTURER", "TRANSPORTER", sign_from=False)
    assert chain.fails(fn, "GATEWAY") == "NEED_BOTH_SIGNATURES"
    fn, _ = handoff(chain, "MANUFACTURER", "TRANSPORTER", signer_to=chain.accounts["PHARMACY"])
    assert chain.fails(fn, "GATEWAY") == "BAD_SIGNATURE_TO"
    fn, _ = handoff(chain, "TRANSPORTER", "WAREHOUSE")
    assert chain.fails(fn, "GATEWAY") == "NOT_CURRENT_CUSTODIAN"
    fn, _ = handoff(chain, "MANUFACTURER", "PHARMACY")
    assert chain.fails(fn, "GATEWAY") == "ROUTE_VIOLATION"
    fn, _ = handoff(chain, "MANUFACTURER", "TRANSPORTER", shipment="SHP-404")
    assert chain.fails(fn, "GATEWAY") == "WRONG_SHIPMENT"
    fn, nonce = handoff(chain, "MANUFACTURER", "TRANSPORTER")
    assert chain.fails(fn, "TRANSPORTER") == "ROLE_DENIED"
    chain.send(fn, "GATEWAY")
    nxt, _ = handoff(chain, "TRANSPORTER", "WAREHOUSE", nonce=nonce)
    assert chain.fails(nxt, "GATEWAY") == "NONCE_REUSED"
    malformed = chain.contract("custody").functions.transferCustody(
        (SHIP, chain.accounts["TRANSPORTER"].address, chain.accounts["WAREHOUSE"].address, secrets.token_bytes(32), 8, TS), b"\x00" * 65, b"\x00" * 65)
    assert chain.fails(malformed, "GATEWAY") == "MALFORMED_SIGNATURE"


def test_revoked_participant_cannot_take_custody(chain, se):
    register(chain, se)
    chain.send(chain.contract("registry").functions.revokeParticipant(chain.accounts["TRANSPORTER"].address), "ADMIN")
    fn, _ = handoff(chain, "MANUFACTURER", "TRANSPORTER")
    assert chain.fails(fn, "GATEWAY") == "PARTICIPANT_REVOKED"


def test_verdict_is_final_and_closes_the_shipment(chain, se):
    register(chain, se)
    ver = chain.contract("verdict")
    fn = ver.functions.finalizeVerdict(SHIP, 3, ["MERKLE_MISMATCH", "EXCURSION_EXCEEDED"], keccak(text="report"))
    assert chain.fails(fn, "TRANSPORTER") == "ROLE_DENIED"
    chain.send(fn, "VERIFIER")
    v = chain.reader.verdict(SHIP)
    assert v["verdict"] == "REJECT" and v["reasonCodes"] == ["MERKLE_MISMATCH", "EXCURSION_EXCEEDED"] and v["verifierRole"] == "VERIFIER"
    assert chain.fails(fn, "VERIFIER") == "VERDICT_EXISTS"
    assert chain.reader.shipment(SHIP)["active"] is False
    assert chain.fails(commit_fn(chain, make_batch(se, 1, 1, 4, ZERO_ROOT)), "GATEWAY") == "SHIPMENT_INACTIVE"
    assert chain.fails(ver.functions.finalizeVerdict("SHP-404", 1, [], bytes(32)), "VERIFIER") == "WRONG_SHIPMENT"

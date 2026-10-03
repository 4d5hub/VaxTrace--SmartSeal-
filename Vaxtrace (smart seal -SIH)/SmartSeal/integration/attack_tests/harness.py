from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from integration.stack import Stack
from blockchain import LedgerRejected, LedgerUnavailable
from custody import recover_signer, handoff_digest
from hashing import batch_payload
from secure_element import MockSecureElementProvider
from verification.engine import Verifier
from verification.evidence import BundleEvidence

HOT = {"t1": 13.0, "t2": 13.0}


def obs(v, **kw):
    return {"verdict": v["verdict"], "codes": v["codes"], **kw}


def revert_of(fn):
    try:
        fn()
    except LedgerRejected as e:
        return e.code
    except LedgerUnavailable as e:
        return "UNAVAILABLE: " + str(e)
    return None


def next_batch_payload(s, provider, root="ab" * 32, seal=None):
    last = s.reader.batches(s.ship)[-1]
    meta = {"sealId": s.seal, "shipmentId": s.ship, "batchId": last["batchId"] + 1, "firstSeq": last["lastSeq"] + 1, "lastSeq": last["lastSeq"] + 4,
            "count": 4, "prevRoot": last["root"], "root": root, "timestamp": s.svc.now()}
    sg = provider.sign_counted(seal or s.seal, lambda c: batch_payload(meta, c))
    return {**meta, "counter": sg.counter, "signature": sg.signature}


def sc_normal(s):
    v = s.normal().verify()
    return obs(v, passed=v["verdict"] == "ACCEPT")


def sc_edit(s):
    s.normal([{}] * 4 + [HOT] * 2)
    before = s.verify()
    for seq in (5, 6):
        s.rehash_from(seq, temperature1=5.0, temperature2=5.0)
    v = s.verify()
    return obs(v, before_attack=before["verdict"], passed=before["verdict"] == "QUARANTINE" and v["verdict"] == "REJECT" and "MERKLE_MISMATCH" in v["codes"]
               and "HASH_CHAIN_BROKEN" not in v["codes"])


def sc_delete(s):
    s.normal()
    s.db("DELETE FROM records WHERE seq=3")
    v = s.verify()
    return obs(v, passed=v["verdict"] == "REJECT" and "SEQ_GAP" in v["codes"])


def sc_reorder(s):
    s.normal()

    def swap(b):
        r = b["records"]
        r[2], r[3] = r[3], r[2]
        return b
    s.bundle_mutator = swap
    v = s.verify()
    return obs(v, passed=v["verdict"] == "REJECT" and "HASH_CHAIN_BROKEN" in v["codes"])


def sc_fabricated(s):
    s.normal()
    attacker = MockSecureElementProvider(s.tmp / "attacker")
    attacker.provision(s.seal)
    code = revert_of(lambda: s.contract_call("BATCH", next_batch_payload(s, attacker)))
    v = s.verify()
    return obs(v, revert=code, passed=code == "SIGNATURE_INVALID" and v["verdict"] == "ACCEPT")


def sc_replay(s):
    s.normal()
    b = s.reader.batches(s.ship)[0]
    payload = {"sealId": s.seal, "shipmentId": s.ship, **{k: b[k] for k in ("batchId", "firstSeq", "lastSeq", "count", "prevRoot", "root", "timestamp", "counter", "signature")}}
    code = revert_of(lambda: s.contract_call("BATCH", payload))
    return {"verdict": s.verify()["verdict"], "codes": [], "revert": code, "passed": code == "STALE_COUNTER"}


def sc_clone(s):
    s.normal()
    clone = MockSecureElementProvider(s.tmp / "clone")
    clone_key = clone.provision(s.seal)
    code = revert_of(lambda: s.contract_call("BATCH", next_batch_payload(s, clone, root="cd" * 32)))
    return {"verdict": s.verify()["verdict"], "codes": [], "revert": code, "registeredKey": s.reader.seal(s.seal)["publicKey"][:24] + "...",
            "cloneKey": clone_key[:24] + "...", "passed": code == "SIGNATURE_INVALID"}


def sc_spoof(s):
    s.normal([{}] * 2 + [{"t1": 5.2, "t2": 12.0}] * 5)
    v = s.verify()
    s2 = Stack()
    s2.normal()
    v2 = s2.verify()
    return obs(v, both_probes_fooled=obs(v2), passed=v["verdict"] == "QUARANTINE" and "SENSOR_DISAGREE" in v["codes"] and v2["verdict"] == "ACCEPT")


def sc_lid(s):
    s.setup()
    s.send(4)
    assert s.handoff().status_code == 201
    s.send(1)
    s.send(1, lid=True)
    s.tamper_event(6)
    s.send(2)
    assert s.handoff().status_code == 201 and s.handoff().status_code == 201
    s.close_batch()
    v = s.verify()
    return obs(v, tamper_events_on_chain=len(s.reader.tamper_events(s.ship)), passed=v["verdict"] == "QUARANTINE" and "LID_OPEN_UNAUTHORIZED" in v["codes"])


def sc_single_party(s):
    s.setup()
    s.send(4)
    a, b = s.handoff("sender_only"), s.handoff("receiver_only")
    dep = s.dep.participants
    forged = {"shipmentId": s.ship, "fromAddress": dep["MANUFACTURER"], "toAddress": dep["TRANSPORTER"], "nonce": "0x" + "42" * 32,
              "atSeq": 4, "timestamp": s.svc.now(), "sigFrom": "0x" + "11" * 65, "sigTo": "0x"}
    on_chain = revert_of(lambda: s.contract_call("HANDOFF", forged))
    ok = s.handoff()
    hs = s.reader.handoffs(s.ship)
    d = handoff_digest(s.dep.chain_id, s.dep.addresses["custody"], s.ship, hs[0]["from"], hs[0]["to"], hs[0]["nonce"], hs[0]["atSeq"], hs[0]["timestamp"])
    receiver_cannot_deny = (recover_signer(d, hs[0]["sigTo"]) or "").lower() == dep["TRANSPORTER"].lower()
    return {"verdict": "n/a", "codes": [], "gateway_rejections": [s.code(a), s.code(b)], "contract_revert": on_chain, "later_dual_signed_handoff": ok.status_code,
            "receiver_signature_recovers_to_receiver": receiver_cannot_deny,
            "passed": s.code(a) == s.code(b) == on_chain == "NEED_BOTH_SIGNATURES" and ok.status_code == 201 and receiver_cannot_deny}


def sc_offline(s):
    s.setup()
    s.ledger.down = True
    s.send(4)
    s.handoff()
    s.send(4)
    s.handoff(); s.handoff()
    s.close_batch()
    queued = s.get("/api/queue").json()["pending"]
    s.advance_time(30 * 60)
    s.ledger.down = False
    res = s.sync()
    v = s.verify()
    return obs(v, queued_while_offline=queued, pending_after_sync=res["pending"], passed=queued >= 5 and res["pending"] == 0 and v["verdict"] == "QUARANTINE" and "OFFLINE_GAP" in v["codes"])


def sc_wipe(s):
    s.normal()
    copy = s.get("/api/export", shipmentId=s.ship).json()["bundle"]
    s.db("DELETE FROM records")
    v = s.verify()
    recovered = Verifier(s.reader, BundleEvidence(copy)).run(s.ship)
    return obs(v, recovered_from_audit_copy=recovered["verdict"], passed=v["verdict"] == "REJECT" and "MISSING_DATA" in v["codes"] and recovered["verdict"] == "ACCEPT")


def sc_validators(s):
    if not s.live:
        return {"skipped": True, "passed": None, "reason": "needs a live Besu network (--rpc URL --docker). The in-process test chain has no validators and this suite refuses to fake quorum."}
    docker = lambda *a: subprocess.run(["docker", *a], capture_output=True, text=True, timeout=60)
    s.setup(); s.send(4)
    docker("stop", "smartseal-node4")
    time.sleep(3)
    three = s.sync()["pending"]
    s.send(4)
    docker("stop", "smartseal-node3")
    time.sleep(3)
    s.send(4)
    two = s.sync()
    docker("start", "smartseal-node3"); docker("start", "smartseal-node4")
    time.sleep(15)
    after = s.sync()
    return {"verdict": "n/a", "codes": [], "pending_with_3_of_4": three, "pending_with_2_of_4": two["pending"], "pending_after_restart": after["pending"],
            "passed": three == 0 and two["pending"] > 0 and after["pending"] == 0}


def sc_revoked(s):
    s.normal()
    denied = s.post("/api/seals/SEAL-A1/revoke", {"by": "TRANSPORTER"})
    assert s.post("/api/seals/SEAL-A1/revoke", {"by": "REGULATOR"}).status_code == 200
    gw = s.post("/api/record", s.dev.record())
    provider = s.svc.provider
    chain = revert_of(lambda: s.contract_call("BATCH", next_batch_payload(s, provider)))
    v = s.verify()
    return obs(v, revoke_by_transporter=s.code(denied), gateway_rejects_records=s.code(gw), contract_revert=chain,
               passed=s.code(denied) == "ROLE_DENIED" and s.code(gw) == "SEAL_REVOKED" and chain == "SEAL_REVOKED" and v["verdict"] == "REJECT" and "SEAL_REVOKED" in v["codes"])


def sc_short(s):
    v = s.normal([{}] * 4 + [HOT] * 2).verify()
    return obs(v, passed=v["verdict"] == "QUARANTINE" and "EXCURSION_SHORT" in v["codes"])


def sc_long(s):
    v = s.normal([{}] * 4 + [HOT] * 4).verify()
    return obs(v, passed=v["verdict"] == "REJECT" and "EXCURSION_EXCEEDED" in v["codes"])


SCENARIOS = [
    (1, "Edit an excursion out of the log", sc_edit, "",
     "Transporter lowers hot readings and recomputes the whole hash chain so it looks self-consistent.",
     "REJECT with MERKLE_MISMATCH", "Merkle root anchored on-chain when the batch closed (the transporter cannot rewrite the ledger)",
     "Detection needs an honest majority of validators and an honest copy of the anchored root.", "DETECTED"),
    (2, "Delete a record", sc_delete, "", "Transporter deletes one stored record.", "REJECT with SEQ_GAP (also HASH_CHAIN_BROKEN)",
     "Sequence numbers plus the record count anchored in the batch", "The deleted reading cannot be restored from this store alone.", "DETECTED"),
    (3, "Reorder records", sc_reorder, "", "A malicious store serves two records swapped.", "REJECT with HASH_CHAIN_BROKEN",
     "prevHash links and sequence order", "None specific.", "DETECTED"),
    (4, "Fabricated batch", sc_fabricated, "", "Compromised gateway submits a batch signed with the attacker's own key.", "Contract reverts SIGNATURE_INVALID; shipment verdict unchanged",
     "BatchAnchor.sol verifies the ECDSA P-256 signature against the seal key registered on-chain", "A stolen or extracted real seal key would defeat this.", "PREVENTED"),
    (5, "Replay an old signed batch", sc_replay, "", "Attacker resubmits batch 1 with its valid signature.", "Contract reverts STALE_COUNTER",
     "Monotonic counter check in BatchAnchor.sol", "Relies on the counter being non-resettable in hardware (a mock in this prototype).", "PREVENTED"),
    (6, "Cloned seal", sc_clone, "", "Firmware and config are copied to another device that cannot copy the key.", "Contract reverts SIGNATURE_INVALID",
     "Private key lives only in the secure element; the ledger knows the registered public key", "Physical key extraction from a real chip is out of scope.", "PREVENTED"),
    (7, "Sensor spoofing (oracle problem)", sc_spoof, "", "Attacker holds probe 1 at 5.2 C while the real temperature is 12 C.", "QUARANTINE with SENSOR_DISAGREE; if BOTH probes are fooled the result is ACCEPT",
     "Second, independent probe compared against the first", "A signature proves which device produced a reading, not that the reading is true. Fooling both probes is undetectable.", "PARTIALLY_MITIGATED"),
    (8, "Lid opened mid-transit", sc_lid, "", "Enclosure opened between handoffs.", "QUARANTINE with LID_OPEN_UNAUTHORIZED",
     "Reed switch to signed tamper event anchored on-chain, compared with dual-signed handoff positions", "A switch bypassed before deployment is not detected.", "DETECTED"),
    (9, "Single-party handoff / false denial", sc_single_party, "", "Sender pushes custody without the receiver, or a receiver later denies receipt.",
     "NEED_BOTH_SIGNATURES from gateway and contract; completed handoffs are non-repudiable", "Dual secp256k1 signatures recovered on-chain (ShipmentCustody.sol)",
     "Two colluding parties can agree on a false story; the design proves agreement, not honesty.", "PREVENTED"),
    (10, "Long offline period", sc_offline, "", "Jamming or outage: the seal cannot reach the chain for a long time.", "Everything queues locally, syncs later, verdict QUARANTINE with OFFLINE_GAP",
     "Offline-first outbox plus anchor time vs signed batch time", "Backdating inside the gap is bounded only by counters and anchor times; jamming itself is not prevented.", "PARTIALLY_MITIGATED"),
    (11, "Off-chain store wiped", sc_wipe, "", "Transporter deletes every stored record.", "REJECT with MISSING_DATA; an audit copy restores an ACCEPT",
     "Roots and counters stay on-chain; audit copies (export/import) hold the data", "Without another copy the data is gone: the chain proves the loss but cannot restore it.", "PARTIALLY_MITIGATED"),
    (12, "Validator compromised or offline", sc_validators, "", "Validators are stopped one by one.", "3 of 4 keep committing; 2 of 4 cannot reach QBFT quorum and the queue holds",
     "QBFT quorum (2f+1 of 4)", "Three colluding validators break the guarantee.", "PARTIALLY_MITIGATED"),
    (13, "Revoked seal keeps committing", sc_revoked, "", "Regulator revokes the seal; the seal or gateway keeps trying.", "Gateway SEAL_REVOKED; contract reverts SEAL_REVOKED; verdict REJECT",
     "Revocation state in SmartSealRegistry plus role checks", "Revocation power sits with one admin/regulator key: insider misuse needs governance.", "PREVENTED"),
    (14, "Short temperature excursion", sc_short, "", "Two hot readings (10 min).", "QUARANTINE with EXCURSION_SHORT", "Verifier policy against the on-chain policy hash",
     "Demo policy values, not a medical judgement.", "DETECTED"),
    (15, "Long temperature excursion", sc_long, "", "Four hot readings (20 min).", "REJECT with EXCURSION_EXCEEDED", "Verifier policy against the on-chain policy hash",
     "Demo policy values, not a medical judgement.", "DETECTED"),
    (16, "Normal shipment", sc_normal, "", "No attack: three dual-signed handoffs, readings in range.", "ACCEPT", "All 24 checks pass", "A clean result shows the record is intact, not that the probe was honest.", "BASELINE"),
]

LIMITATIONS = [
    ("Sensor spoofing / oracle problem", "NOT_SOLVED", "A signature proves origin, not truth. One fooled probe is caught by probe comparison."),
    ("Physical sensor manipulation", "NOT_SOLVED", "Heating, cooling or shielding a probe is outside what cryptography can see."),
    ("Both redundant sensors fooled", "NOT_SOLVED", "Scenario 7 shows the result is ACCEPT."),
    ("Laboratory-grade secure-element key extraction", "NOT_SOLVED", "A hardware property; the mock provider used here keeps its key in a file."),
    ("Physical removal and re-binding of the seal", "PARTIALLY_MITIGATED", "Binding is recorded at startShipment; a tamper-evident strap and NFC tie-in are future work."),
    ("Collusion between parties", "NOT_SOLVED", "Dual signatures show agreement, not honesty."),
    ("Majority validator compromise", "NOT_SOLVED", "3 of 4 validators colluding can rewrite state."),
    ("Off-chain data loss", "PARTIALLY_MITIGATED", "The chain proves what existed; audit copies can restore it if they exist."),
    ("Jamming / network outage", "PARTIALLY_MITIGATED", "Offline-first queue and OFFLINE_GAP flag; jamming itself is not prevented."),
    ("Gateway compromise", "PARTIALLY_MITIGATED", "It cannot forge seal or party signatures and tampered evidence is caught, but it can withhold, delay or censor."),
    ("Malicious firmware", "NOT_SOLVED", "Secure boot and multi-party firmware approval are not built in this prototype."),
    ("Insider misuse of admin powers", "NOT_SOLVED", "The registry admin can assign roles and revoke participants; production needs multi-party governance."),
]


def run_all(only=None, rpc_url=None, docker=False):
    results = []
    for sid, name, fn, _x, action, expected, detection, limitation, cls in SCENARIOS:
        if only and sid not in only:
            continue
        t0 = time.time()
        stack = Stack(rpc_url=rpc_url) if (rpc_url and (docker or sid != 12)) else Stack()
        try:
            out = fn(stack)
        except Exception as e:
            out = {"passed": False, "error": f"{type(e).__name__}: {e}"}
        results.append({"id": sid, "name": name, "attackerAction": action, "expected": expected, "detection": detection, "limitation": limitation,
                        "classification": cls, "seconds": round(time.time() - t0, 1), "observed": out,
                        "status": "SKIPPED" if out.get("skipped") else ("PASS" if out.get("passed") else "FAIL")})
    return {"generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "mode": f"live Besu at {rpc_url}" if rpc_url else "in-process EVM (real compiled contracts, no validator network)",
            "summary": {"pass": sum(r["status"] == "PASS" for r in results), "fail": sum(r["status"] == "FAIL" for r in results),
                        "skipped": sum(r["status"] == "SKIPPED" for r in results), "total": len(results)},
            "results": results, "limitations": [{"item": a, "classification": b, "note": c} for a, b, c in LIMITATIONS],
            "disclaimer": "Demo policy values. Nothing here is a claim of tamper-proof or unhackable."}


def save_report(report, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text(json.dumps(report, indent=1))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", help="comma-separated scenario ids")
    ap.add_argument("--rpc", help="run against a live Besu JSON-RPC URL")
    ap.add_argument("--docker", action="store_true", help="allow scenario 12 to stop/start smartseal-node3/4 containers")
    ap.add_argument("--json", default=str(Path(__file__).resolve().parents[2] / "gateway" / "data" / "attack_report.json"))
    a = ap.parse_args()
    rep = run_all({int(x) for x in a.only.split(",")} if a.only else None, a.rpc, a.docker)
    save_report(rep, a.json)
    for r in rep["results"]:
        o = r["observed"]
        print(f"{r['id']:>2} {r['status']:<7} {r['classification']:<20} {r['name']:<38} {o.get('verdict', '')} {','.join(o.get('codes', []))} {o.get('revert') or o.get('error') or ''}")
    print(rep["summary"], "->", a.json)
    sys.exit(1 if rep["summary"]["fail"] else 0)

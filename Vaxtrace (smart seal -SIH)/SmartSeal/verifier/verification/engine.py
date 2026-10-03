from __future__ import annotations

import json
import time

import verification
import verifier as gw_chain
from batching import policy_hash
from custody import ROUTE, handoff_digest, recover_signer
from hashing import ZERO_ROOT, batch_payload, parse_ts, sha256_hex, tamper_payload
from merkle import merkle_root
from policies import policy as pol
from secure_element import verify_signature

REJECT_CODES = {"SHIPMENT_NOT_FOUND", "POLICY_MISMATCH", "NO_ANCHORS", "MISSING_DATA", "SEQ_GAP", "TIMESTAMP_ORDER", "HASH_CHAIN_BROKEN",
                "MERKLE_MISMATCH", "SIGNATURE_INVALID", "COUNTER_GAP", "BATCH_SEQUENCE_ERROR", "PREV_ROOT_MISMATCH", "UNREGISTERED_SEAL",
                "SEAL_REVOKED", "CUSTODY_BROKEN", "EXCURSION_EXCEEDED"}
MESSAGES = {
    "SHIPMENT_NOT_FOUND": "The shipment is not registered on the ledger.",
    "POLICY_MISMATCH": "The policy supplied with the evidence does not match the policy hash anchored on-chain.",
    "NO_ANCHORS": "No batch commitments are anchored on-chain for this shipment.",
    "MISSING_DATA": "Off-chain evidence is missing for batches that were anchored on-chain.",
    "SEQ_GAP": "Records are missing inside the recorded sequence or inside an anchored batch.",
    "TIMESTAMP_ORDER": "Record timestamps go backwards.",
    "HASH_CHAIN_BROKEN": "A record hash or previous-hash link does not verify.",
    "MERKLE_MISMATCH": "Recomputed Merkle root differs from the root anchored on-chain.",
    "SIGNATURE_INVALID": "A batch or tamper-event signature does not verify against the registered secure-element key.",
    "COUNTER_GAP": "Secure-element counter values are not contiguous: something was signed but never anchored.",
    "BATCH_SEQUENCE_ERROR": "Batch ids or sequence ranges are not consecutive.",
    "PREV_ROOT_MISMATCH": "A batch does not chain to the previous batch root.",
    "UNREGISTERED_SEAL": "The seal is not registered on-chain.",
    "SEAL_REVOKED": "The seal was revoked on-chain.",
    "CUSTODY_BROKEN": "Custody is incomplete or is not a valid dual-signed chain Manufacturer to Pharmacy.",
    "EXCURSION_EXCEEDED": "A temperature excursion lasted longer than the policy allows.",
    "EXCURSION_SHORT": "A short temperature excursion within the policy tolerance: inspect the goods.",
    "SENSOR_DISAGREE": "The two temperature probes disagree by more than the policy allows (possible sensor tampering).",
    "SHOCK_EXCEEDED": "A shock reading exceeded the policy limit.",
    "LID_OPEN_UNAUTHORIZED": "The lid was opened with no matching authorized handoff.",
    "TAMPER_EVENT_MISSING": "Anchored records show the lid open but no signed tamper event exists on-chain.",
    "OFFLINE_GAP": "A prolonged offline gap (late anchoring or a logging gap) exceeded the policy limit.",
    "INCOMPLETE_EVIDENCE": "Some records are not yet covered by an anchored batch (evidence incomplete but possibly recoverable).",
}


def _pub_meta(sh, b):
    return {"sealId": sh["sealId"], "shipmentId": sh["shipmentId"], "batchId": b["batchId"], "firstSeq": b["firstSeq"], "lastSeq": b["lastSeq"],
            "count": b["count"], "prevRoot": b["prevRoot"], "root": b["root"], "timestamp": b["timestamp"]}


class Verifier:
    def __init__(self, reader, evidence):
        self.reader, self.evidence = reader, evidence

    def run(self, shipment_id: str, policy_override: dict | None = None) -> dict:
        t0 = time.perf_counter()
        checks, codes = [], set()

        def add(step, name, status, detail="", code=None):
            checks.append({"step": step, "name": name, "status": status, "detail": detail, "code": code if status in ("FAIL", "WARN") else None})
            if status in ("FAIL", "WARN") and code:
                codes.add(code)

        reject = set(REJECT_CODES)
        R, skip = self.reader, lambda s, n: add(s, n, "SKIP", "not evaluated: an earlier check made it impossible")
        NAMES = {1: "Fetch on-chain shipment state", 2: "Fetch on-chain batch anchors", 3: "Fetch on-chain custody chain", 4: "Fetch raw off-chain records",
                 5: "Sequence continuity", 6: "Timestamps ordered", 7: "Recompute every record hash", 8: "Previous-hash links",
                 9: "Batch record counts and coverage", 10: "Recompute each Merkle root", 11: "Compare Merkle roots with on-chain roots",
                 12: "Verify batch signatures", 13: "Monotonic counters", 14: "Batch order", 15: "Previous-root chaining",
                 16: "Seal registration", 17: "Seal revocation status", 18: "Custody chain", 19: "Dual custody signatures",
                 20: "Temperature policy", 21: "Tamper events", 22: "Shock policy", 23: "Sensor disagreement", 24: "Offline and logging gaps"}

        sh = R.shipment(shipment_id)
        if not sh:
            add(1, NAMES[1], "FAIL", "shipment not found on-chain", "SHIPMENT_NOT_FOUND")
            for s in range(2, 25):
                skip(s, NAMES[s])
            return self._finish(shipment_id, checks, codes, t0, {}, reject)
        add(1, NAMES[1], "PASS", f"seal {sh['sealId']}, {'active' if sh['active'] else 'closed'}")
        batches = R.batches(shipment_id)
        add(2, NAMES[2], "PASS" if batches else "FAIL", f"{len(batches)} anchored batches", "NO_ANCHORS")
        handoffs = R.handoffs(shipment_id)
        add(3, NAMES[3], "PASS", f"{len(handoffs)} handoffs on-chain")
        tamper = R.tamper_events(shipment_id)
        seal = R.seal(sh["sealId"])

        bundle, err = None, None
        try:
            bundle = self.evidence.fetch(shipment_id)
        except Exception as e:
            err = f"{type(e).__name__}: {e}"
        records = (bundle or {}).get("records") or []
        add(4, NAMES[4], "PASS" if records else "FAIL", f"{len(records)} records" if records else (err or "evidence source returned no records"), "MISSING_DATA")

        policy = dict((bundle or {}).get("shipment", {}).get("policy") or {})
        if policy_override:
            policy.update(policy_override)
        if bundle and policy_hash({k: policy[k] for k in ("tempMinC", "tempMaxC", "maxExcursionMinutes", "shockLimitG", "offlineGapMinutes", "probeDisagreementC") if k in policy}) != sh["policyHash"] and not policy_override:
            add(1, "Policy hash matches on-chain policy", "FAIL", "supplied policy differs from the anchored policy hash", "POLICY_MISMATCH")
        opts = pol.options(policy)

        chain = gw_chain.verify_records(records) if records else {"issues": []}
        pick = lambda *cs: [f"seq {i['seq']}: {i['detail']}" for i in chain["issues"] if i["code"] in cs]
        for step, cs, code in ((5, ("SEQ_GAP",), "SEQ_GAP"), (6, ("TIMESTAMP_ORDER",), "TIMESTAMP_ORDER"),
                               (7, ("RECORD_HASH_MISMATCH",), "HASH_CHAIN_BROKEN"), (8, ("PREV_HASH_MISMATCH", "SEQ_ORDER"), "HASH_CHAIN_BROKEN")):
            if not records:
                skip(step, NAMES[step])
            else:
                f = pick(*cs)
                add(step, NAMES[step], "FAIL" if f else "PASS", "; ".join(f[:3]) if f else "ok", code)

        by_seq = {r["seq"]: r for r in records}
        missing, partial, roots, mism = [], [], [], []
        for b in batches:
            span = range(b["firstSeq"], b["lastSeq"] + 1)
            present = [by_seq[s] for s in span if s in by_seq]
            if b["count"] != len(span):
                partial.append(f"batch {b['batchId']}: count {b['count']} != range {len(span)}")
            if not present:
                missing.append(f"batch {b['batchId']}: no records for seq {b['firstSeq']}-{b['lastSeq']}")
            elif len(present) < len(span):
                partial.append(f"batch {b['batchId']}: {len(present)} of {len(span)} records present")
            else:
                try:
                    root = merkle_root([r["hash"] for r in present])
                except ValueError:
                    root = None
                roots.append((b["batchId"], root))
                if root != b["root"]:
                    mism.append(f"batch {b['batchId']}: recomputed {str(root)[:12]}... vs on-chain {b['root'][:12]}...")
        if not batches:
            for s in (9, 10, 11):
                skip(s, NAMES[s])
        else:
            add(9, NAMES[9], "FAIL" if (missing or partial) else "PASS", "; ".join((missing + partial)[:3]) or "every anchored batch is fully present",
                "MISSING_DATA" if missing else "SEQ_GAP")
            if missing and partial:
                codes.update({"MISSING_DATA", "SEQ_GAP"})
            add(10, NAMES[10], "PASS", f"{len(roots)} roots recomputed" if roots else "nothing to recompute")
            add(11, NAMES[11], "FAIL" if mism else "PASS", "; ".join(mism[:3]) or "all roots match", "MERKLE_MISMATCH")
        last_batch_seq = batches[-1]["lastSeq"] if batches else 0
        tail = [r for r in records if r["seq"] > last_batch_seq]
        if tail and batches:
            add(9, "Records not yet covered by an anchored batch", "WARN", f"{len(tail)} records after seq {last_batch_seq}", "INCOMPLETE_EVIDENCE")

        if not seal:
            for s in (12,):
                skip(s, NAMES[s])
        else:
            bad = [f"batch {b['batchId']}" for b in batches if not verify_signature(seal["publicKey"], batch_payload(_pub_meta(sh, b), b["counter"]), b["signature"])]
            bad += [f"tamper counter {t['counter']}" for t in tamper if not verify_signature(
                seal["publicKey"], tamper_payload({"sealId": sh["sealId"], "shipmentId": shipment_id, "eventType": t["eventType"], "seq": t["seq"], "timestamp": t["timestamp"]}, t["counter"]), t["signature"])]
            add(12, NAMES[12], "FAIL" if bad else "PASS", ", ".join(bad) + " invalid" if bad else f"{len(batches) + len(tamper)} signatures verified", "SIGNATURE_INVALID")
        ctr = sorted([b["counter"] for b in batches] + [t["counter"] for t in tamper])
        problems = []
        if ctr and (len(set(ctr)) != len(ctr) or ctr != list(range(ctr[0], ctr[0] + len(ctr)))):
            problems.append(f"counters {ctr} are not contiguous")
        if [b["counter"] for b in batches] != sorted(b["counter"] for b in batches):
            problems.append("batch counters do not increase with batch id")
        add(13, NAMES[13], "FAIL" if problems else "PASS", "; ".join(problems) or f"counters {ctr}", "COUNTER_GAP")
        order, chainp, prev = [], [], None
        for i, b in enumerate(batches):
            if b["batchId"] != i + 1 or b["firstSeq"] != (1 if prev is None else prev["lastSeq"] + 1):
                order.append(f"batch {b['batchId']} out of sequence")
            if b["prevRoot"] != (ZERO_ROOT if prev is None else prev["root"]):
                chainp.append(f"batch {b['batchId']} prevRoot does not chain")
            prev = b
        add(14, NAMES[14], "FAIL" if order else "PASS", "; ".join(order) or "consecutive", "BATCH_SEQUENCE_ERROR")
        add(15, NAMES[15], "FAIL" if chainp else "PASS", "; ".join(chainp) or "every prevRoot links to the previous root", "PREV_ROOT_MISMATCH")

        add(16, NAMES[16], "PASS" if seal else "FAIL", f"registered by {seal['manufacturer']}" if seal else "seal not registered on-chain", "UNREGISTERED_SEAL")
        add(17, NAMES[17], "FAIL" if (seal and seal["revoked"]) else "PASS", "revoked" if (seal and seal["revoked"]) else "not revoked", "SEAL_REVOKED")

        cprob = []
        if len(handoffs) != 3:
            cprob.append(f"{len(handoffs)} of 3 handoffs completed")
        prev_to = sh["initialCustodian"]
        for i, h in enumerate(handoffs):
            if h["fromRole"] != ROUTE[i] or h["toRole"] != ROUTE[i + 1]:
                cprob.append(f"handoff {i + 1} is {h['fromRole']}->{h['toRole']}, expected {ROUTE[i]}->{ROUTE[i + 1]}")
            if h["from"].lower() != prev_to.lower():
                cprob.append(f"handoff {i + 1} sender is not the current holder")
            prev_to = h["to"]
        if len({h["nonce"] for h in handoffs}) != len(handoffs):
            cprob.append("a nonce was reused")
        add(18, NAMES[18], "FAIL" if cprob else "PASS", "; ".join(cprob) or "Manufacturer > Transporter > Warehouse > Pharmacy complete", "CUSTODY_BROKEN")
        sigbad = []
        chain_id, custody_addr = R.custody_domain()
        for i, h in enumerate(handoffs):
            d = handoff_digest(chain_id, custody_addr, shipment_id, h["from"], h["to"], h["nonce"], h["atSeq"], h["timestamp"])
            for lab, sig, who in (("sender", h["sigFrom"], h["from"]), ("receiver", h["sigTo"], h["to"])):
                got = recover_signer(d, sig)
                if not got or got.lower() != who.lower():
                    sigbad.append(f"handoff {i + 1} {lab} signature invalid")
        add(19, NAMES[19], "FAIL" if sigbad else "PASS", "; ".join(sigbad) or f"{len(handoffs) * 2} signatures recovered to the expected parties", "CUSTODY_BROKEN")

        if not records:
            for s in range(20, 25):
                skip(s, NAMES[s])
        else:
            lo, hi, limit = policy.get("tempMinC", 2.0), policy.get("tempMaxC", 8.0), policy.get("maxExcursionMinutes", 15)
            runs = pol.excursion_runs(records, lo, hi, opts["excursionProbeRule"], opts["defaultSamplingSeconds"])
            longest = max((r["minutes"] for r in runs), default=0)
            st = "PASS" if not runs else ("FAIL" if longest > limit else "WARN")
            add(20, NAMES[20], st, f"{lo}-{hi} C, limit {limit} min; longest excursion {longest} min ({len(runs)} runs; probe rule '{opts['excursionProbeRule']}')" if runs
                else f"all readings within {lo}-{hi} C", "EXCURSION_EXCEEDED" if longest > limit else "EXCURSION_SHORT")
            tol, opens = opts["handoffToleranceRecords"], pol.lid_open_runs(records)
            unauth = [t["seq"] for t in tamper if t["eventType"] == "LID_OPEN" and not any(abs(h["atSeq"] - t["seq"]) <= tol for h in handoffs)]
            unseen = [s for s in opens if not any(t["eventType"] == "LID_OPEN" and abs(t["seq"] - s) <= tol for t in tamper)]
            if unauth:
                code = "LID_OPEN_UNAUTHORIZED"
                if opts["unauthorizedLidOpenVerdict"] == "REJECT":
                    reject.add(code)
                add(21, NAMES[21], "WARN", f"lid opened at seq {unauth} with no matching handoff", code)
            elif unseen:
                add(21, NAMES[21], "WARN", f"records show lid open at seq {unseen} but no signed tamper event is anchored", "TAMPER_EVENT_MISSING")
            else:
                add(21, NAMES[21], "PASS", f"{len(tamper)} signed tamper events, all explained")
            shocks = [r["seq"] for r in records if r["shock"] > policy.get("shockLimitG", 2.5)]
            add(22, NAMES[22], "WARN" if shocks else "PASS", f"shock above {policy.get('shockLimitG', 2.5)} g at seq {shocks[:5]}" if shocks else "within limit", "SHOCK_EXCEEDED")
            dis = [r["seq"] for r in records if abs(r["temperature1"] - r["temperature2"]) > policy.get("probeDisagreementC", 3.0)]
            add(23, NAMES[23], "WARN" if dis else "PASS", f"probes differ by more than {policy.get('probeDisagreementC', 3.0)} C at seq {dis[:5]}" if dis else "probes agree", "SENSOR_DISAGREE")
            gl = policy.get("offlineGapMinutes", 20)
            late = [f"batch {b['batchId']} anchored {round((b['anchoredAt'] - parse_ts(b['timestamp']).timestamp()) / 60, 1)} min after signing"
                    for b in batches if b["anchoredAt"] - parse_ts(b["timestamp"]).timestamp() > gl * 60]
            gaps = [f"no records for {g['minutes']} min after seq {g['afterSeq']}" for g in pol.record_gaps(records, gl)]
            add(24, NAMES[24], "WARN" if (late or gaps) else "PASS", "; ".join((late + gaps)[:3]) or f"no gap longer than {gl} min", "OFFLINE_GAP")
        return self._finish(shipment_id, checks, codes, t0, {"policy": policy, "options": opts}, reject)

    def _finish(self, shipment_id, checks, codes, t0, extra, reject):
        verdict = "REJECT" if codes & reject else ("QUARANTINE" if codes else "ACCEPT")
        checks.sort(key=lambda c: (c["step"], c["name"]))
        checks.append({"step": 25, "name": "Produce verdict", "status": "PASS", "detail": verdict, "code": None})
        result = {"shipmentId": shipment_id, "verdict": verdict, "codes": sorted(codes),
                  "reasons": [MESSAGES.get(c, c) for c in sorted(codes)], "checks": checks, "elapsedMs": round((time.perf_counter() - t0) * 1000, 1),
                  "policyNote": "Demo policy values, not medical or regulatory certification.", **extra}
        result["reportHash"] = "0x" + sha256_hex(json.dumps({k: result[k] for k in ("shipmentId", "verdict", "codes", "checks")}, sort_keys=True, separators=(",", ":")))
        return result

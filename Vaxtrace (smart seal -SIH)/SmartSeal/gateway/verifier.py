from __future__ import annotations

from hashing import ZERO_HASH, ZERO_ROOT, batch_payload, parse_ts, record_hash, tamper_payload
from merkle import merkle_root
from secure_element import verify_signature

AGGREGATE = {"RECORD_HASH_MISMATCH": "HASH_CHAIN_BROKEN", "PREV_HASH_MISMATCH": "HASH_CHAIN_BROKEN",
             "SEQ_ORDER": "HASH_CHAIN_BROKEN", "SEQ_GAP": "SEQ_GAP", "TIMESTAMP_ORDER": "TIMESTAMP_ORDER"}


def verify_records(records: list, expect_first_seq: int = 1, first_prev_hash=ZERO_HASH) -> dict:
    issues, prev = [], None
    for r in records:
        try:
            if record_hash(r) != r["hash"]:
                issues.append({"code": "RECORD_HASH_MISMATCH", "seq": r["seq"], "detail": "stored hash does not match record contents"})
        except (ValueError, TypeError, KeyError) as e:
            issues.append({"code": "RECORD_HASH_MISMATCH", "seq": r.get("seq"), "detail": f"record cannot be canonicalized: {e}"})
        expected = expect_first_seq if prev is None else prev["seq"] + 1
        if r["seq"] > expected:
            issues.append({"code": "SEQ_GAP", "seq": r["seq"], "detail": f"expected seq {expected}, got {r['seq']}"})
        elif r["seq"] < expected:
            issues.append({"code": "SEQ_ORDER", "seq": r["seq"], "detail": f"seq {r['seq']} out of order (expected {expected})"})
        want_prev = first_prev_hash if prev is None else prev["hash"]
        if want_prev is not None and r["prevHash"] != want_prev:
            issues.append({"code": "PREV_HASH_MISMATCH", "seq": r["seq"], "detail": "prevHash does not point at the previous record"})
        if prev is not None:
            try:
                if parse_ts(r["timestamp"]) < parse_ts(prev["timestamp"]):
                    issues.append({"code": "TIMESTAMP_ORDER", "seq": r["seq"], "detail": "timestamp earlier than previous record"})
            except ValueError:
                issues.append({"code": "TIMESTAMP_ORDER", "seq": r["seq"], "detail": "unparseable timestamp"})
        prev = r
    return {"ok": not issues, "issues": issues, "codes": sorted({AGGREGATE[i["code"]] for i in issues})}


def verify_integrity(records: list, batches: list, tamper_events: list, public_key: str) -> dict:
    checks, codes = [], set()

    def add(name, failures, code, ok_detail="ok"):
        checks.append({"name": name, "status": "FAIL" if failures else "PASS", "code": code if failures else None,
                       "detail": "; ".join(failures[:5]) + (f" (+{len(failures) - 5} more)" if len(failures) > 5 else "") if failures else ok_detail})
        if failures:
            codes.add(code)

    chain = verify_records(records)
    by = lambda *cs: [f"seq {i['seq']}: {i['detail']}" for i in chain["issues"] if i["code"] in cs]
    add("Sequence continuity", by("SEQ_GAP"), "SEQ_GAP", f"{len(records)} records contiguous")
    add("Timestamp ordering", by("TIMESTAMP_ORDER"), "TIMESTAMP_ORDER")
    add("Record hashes recomputed", by("RECORD_HASH_MISMATCH"), "HASH_CHAIN_BROKEN")
    add("Previous-hash links", by("PREV_HASH_MISMATCH", "SEQ_ORDER"), "HASH_CHAIN_BROKEN")

    by_seq = {r["seq"]: r for r in records}
    missing, counts, roots = [], [], []
    for b in batches:
        span = range(b["firstSeq"], b["lastSeq"] + 1)
        present = [by_seq[s] for s in span if s in by_seq]
        if b["count"] != len(span):
            counts.append(f"batch {b['batchId']}: count {b['count']} != span {len(span)}")
        if not present:
            missing.append(f"batch {b['batchId']}: no records for seq {b['firstSeq']}-{b['lastSeq']}")
        elif len(present) < len(span):
            counts.append(f"batch {b['batchId']}: only {len(present)} of {len(span)} records present")
        else:
            try:
                if merkle_root([r["hash"] for r in present]) != b["root"]:
                    roots.append(f"batch {b['batchId']}: recomputed root differs from anchored root")
            except ValueError as e:
                roots.append(f"batch {b['batchId']}: {e}")
    add("Anchored batches have data", missing, "MISSING_DATA", f"{len(batches)} batches covered")
    add("Batch record counts", counts, "SEQ_GAP")
    add("Merkle roots match anchored roots", roots, "MERKLE_MISMATCH")

    sigs = []
    for b in batches:
        if not verify_signature(public_key, batch_payload(b, b["counter"]), b["signature"]):
            sigs.append(f"batch {b['batchId']}: signature invalid for registered key")
    for e in tamper_events:
        if not verify_signature(public_key, tamper_payload(e, e["counter"]), e["signature"]):
            sigs.append(f"tamper event counter {e['counter']}: signature invalid")
    add("Signatures verify against registered public key", sigs, "SIGNATURE_INVALID")

    order, prev = [], None
    for i, b in enumerate(batches):
        if b["batchId"] != i + 1:
            order.append(f"batch id {b['batchId']} at position {i + 1}")
        want_root = ZERO_ROOT if prev is None else prev["root"]
        if b["prevRoot"] != want_root:
            order.append(f"batch {b['batchId']}: prevRoot does not chain")
        want_first = 1 if prev is None else prev["lastSeq"] + 1
        if b["firstSeq"] != want_first:
            order.append(f"batch {b['batchId']}: firstSeq {b['firstSeq']} != {want_first}")
        prev = b
    add("Batch order and prevRoot chain", order, "BATCH_SEQUENCE_ERROR")

    ctr, bad = sorted([b["counter"] for b in batches] + [e["counter"] for e in tamper_events]), []
    if ctr:
        if len(set(ctr)) != len(ctr):
            bad.append("duplicate counter values")
        elif ctr != list(range(ctr[0], ctr[0] + len(ctr))):
            bad.append(f"counter values not contiguous: {ctr}")
    chrono = [b["counter"] for b in batches]
    if chrono != sorted(chrono):
        bad.append("batch counters do not increase with batch id")
    add("Monotonic counters contiguous", bad, "COUNTER_GAP", f"counters {ctr}")

    tail = [r for r in records if batches and r["seq"] > batches[-1]["lastSeq"]] if batches else list(records)
    checks.append({"name": "Anchoring coverage", "status": "WARN" if tail or any(b.get("anchorStatus") == "PENDING" for b in batches) else "PASS", "code": None,
                   "detail": f"{len(tail)} records not yet covered by a signed batch; {sum(b.get('anchorStatus') != 'ANCHORED' for b in batches)} batches not yet on the ledger"})
    return {"ok": not codes, "codes": sorted(codes), "checks": checks, "issues": chain["issues"]}

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from decimal import Decimal, ROUND_HALF_EVEN

ZERO_HASH = "0"
ZERO_ROOT = "0" * 64
HEX64 = re.compile(r"^[0-9a-f]{64}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
FIXED2 = frozenset({"shock", "temperature1", "temperature2"})
RECORD_FIELDS = ("lid", "light", "prevHash", "sealId", "seq", "shipmentId",
                 "shock", "temperature1", "temperature2", "timestamp")

DOMAIN_BATCH = "SMARTSEAL/BATCH/v1"
DOMAIN_TAMPER = "SMARTSEAL/TAMPER/v1"
DOMAIN_HANDOFF = "SMARTSEAL/HANDOFF/v1"


def sha256_hex(data) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def fmt2(value) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float, Decimal)):
        raise TypeError("measured value must be a number")
    d = Decimal(str(value))
    q = d.quantize(Decimal("0.01"), rounding=ROUND_HALF_EVEN)
    if q != d:
        raise ValueError(f"{value} has more than 2 decimal places")
    text = format(q, "f")
    return "0.00" if text == "-0.00" else text


def _scalar(key, value, fixed2):
    if key in fixed2:
        return fmt2(value)
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=True)
    raise TypeError(f"unsupported value for {key!r}: {type(value).__name__}")


def canonical(obj: dict, fixed2=frozenset()) -> str:
    return "{" + ",".join(f"{json.dumps(k)}:{_scalar(k, obj[k], fixed2)}" for k in sorted(obj)) + "}"


def parse_ts(ts: str) -> datetime:
    if not isinstance(ts, str) or not TS_RE.match(ts):
        raise ValueError("timestamp must look like 2026-01-01T00:00:00Z")
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def record_canonical(rec: dict) -> str:
    missing = [k for k in RECORD_FIELDS if k not in rec]
    if missing:
        raise ValueError(f"record is missing fields: {missing}")
    return canonical({k: rec[k] for k in RECORD_FIELDS}, FIXED2)


def record_hash(rec: dict) -> str:
    return sha256_hex(record_canonical(rec))


def batch_payload(meta: dict, counter: int) -> str:
    return canonical({
        "domain": DOMAIN_BATCH, "sealId": meta["sealId"], "shipmentId": meta["shipmentId"],
        "batchId": meta["batchId"], "firstSeq": meta["firstSeq"], "lastSeq": meta["lastSeq"],
        "count": meta["count"], "prevRoot": meta["prevRoot"], "root": meta["root"],
        "timestamp": meta["timestamp"], "counter": counter})


def tamper_payload(ev: dict, counter: int) -> str:
    return canonical({
        "domain": DOMAIN_TAMPER, "sealId": ev["sealId"], "shipmentId": ev["shipmentId"],
        "eventType": ev["eventType"], "seq": ev["seq"], "timestamp": ev["timestamp"],
        "counter": counter})

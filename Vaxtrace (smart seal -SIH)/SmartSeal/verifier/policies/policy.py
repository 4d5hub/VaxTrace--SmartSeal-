from __future__ import annotations

import json
from pathlib import Path
from statistics import median

import verification
from hashing import parse_ts

DEFAULTS = json.loads((Path(__file__).parent / "demo_policy.json").read_text())["verifierOptions"]


def options(policy: dict) -> dict:
    return {**DEFAULTS, **{k: v for k, v in policy.items() if k in DEFAULTS}}


def excursion_runs(records: list, lo: float, hi: float, rule: str, default_interval: int) -> list:
    if not records:
        return []
    t = [parse_ts(r["timestamp"]).timestamp() for r in records]
    diffs = [b - a for a, b in zip(t, t[1:]) if b > a]
    interval = median(diffs) if diffs else default_interval
    def out(r):
        vals = [r["temperature1"]] if rule == "primary" else [r["temperature1"], r["temperature2"]]
        return any(v < lo or v > hi for v in vals)
    runs, i = [], 0
    while i < len(records):
        if out(records[i]):
            j = i
            while j + 1 < len(records) and out(records[j + 1]):
                j += 1
            end = t[j + 1] if j + 1 < len(records) else t[j] + interval
            runs.append({"firstSeq": records[i]["seq"], "lastSeq": records[j]["seq"], "minutes": round((end - t[i]) / 60, 2)})
            i = j + 1
        else:
            i += 1
    return runs


def record_gaps(records: list, limit_minutes: float) -> list:
    out = []
    for a, b in zip(records, records[1:]):
        gap = (parse_ts(b["timestamp"]) - parse_ts(a["timestamp"])).total_seconds() / 60
        if gap > limit_minutes:
            out.append({"afterSeq": a["seq"], "minutes": round(gap, 2)})
    return out


def lid_open_runs(records: list) -> list:
    return [r["seq"] for i, r in enumerate(records) if r["lid"] and (i == 0 or not records[i - 1]["lid"])]

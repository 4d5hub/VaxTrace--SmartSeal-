# Verifier service (port 8100)

Independent reconstruction of a shipment's history. It reads the **chain** (contracts) and the **raw evidence** (the gateway's `/api/export`, or an imported audit copy) and never opens the gateway's database.
It reuses the gateway's primitive modules (hashing, Merkle, signature check, custody digest); a production verifier should vendor an independently audited copy of those.

Run: `run_verifier.bat` (needs `blockchain\deployment.json`). API: `POST /verify {shipmentId, gatewayUrl, finalize}`, `POST /verify-bundle {shipmentId, bundle, finalize}`, `GET /result?shipmentId=`, `GET /health`.
`finalize: true` writes the verdict to `VerdictRegistry` (and closes the shipment).

## The 25 checks, in order
1 on-chain shipment state (and policy hash) · 2 batch anchors · 3 custody chain · 4 raw records · 5 sequence continuity · 6 timestamps ordered · 7 record hashes recomputed · 8 previous-hash links ·
9 batch record counts and coverage · 10 Merkle roots recomputed · 11 compared with on-chain roots · 12 batch signatures · 13 monotonic counters · 14 batch order · 15 previous-root chaining ·
16 seal registration · 17 revocation · 18 custody chain complete · 19 dual custody signatures recovered · 20 temperature policy · 21 tamper events · 22 shock · 23 sensor disagreement · 24 offline gaps · 25 verdict.

## Verdict rules (project policy, not medical or regulatory certification)
* **REJECT**: bad signature, Merkle mismatch, broken hash chain, missing anchored data, sequence or counter gap, broken custody, revoked or unregistered seal, no anchors, policy hash mismatch, excursion longer than allowed.
* **QUARANTINE**: short excursion, probe disagreement, shock over limit, lid opened without a matching handoff, tamper event missing for an open lid, prolonged offline gap, records not yet anchored.
* **ACCEPT**: every check passes.
Defaults (editable per shipment; hash anchored on-chain): 2 to 8 °C, longest excursion 15 min, shock 2.5 g, offline gap 20 min, probe disagreement 3 °C.
Behaviour options are in `policies/demo_policy.json`: which probe controls excursions (`primary` or `any`), handoff tolerance in records, and whether an unauthorized lid opening quarantines or rejects.
Excursion length = first out-of-range reading to the first in-range reading after it (or last reading plus the sampling interval).
